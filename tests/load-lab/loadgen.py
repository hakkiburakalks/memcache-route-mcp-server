#!/usr/bin/env python3
"""Traffic generator for the local test lab. Standard library only.

Every request is one memcached text-protocol operation, chosen like this:

    GET            with probability get_ratio
    DELETE         with probability (1 - get_ratio) * delete_share
    SET            otherwise

so the printed GET/SET/DELETE counts add up to the requests sent. A GET miss does NOT trigger a
refill unless --fill-on-miss is given (cache-aside), in which case the extra SETs are counted
separately as "fill_sets".

Examples:
    loadgen.py --target mc1:11211 --profile read-heavy --duration 30 --concurrency 32
    loadgen.py --target mcrouter:5000 --profile eviction-heavy --rps 5000 --duration 60
    loadgen.py --list-profiles
"""
import argparse
import asyncio
import bisect
import json
import random
import sys
import time

# name -> settings. dist: zipf:<s> | uniform | hot:<keys>:<share of traffic>
PROFILES = {
    "read-heavy":      dict(get=0.90, dist="zipf:1.0", sizes=[100, 300, 1000, 3000], ttls=[0, 300, 3600], keyspace=50_000),
    "balanced":        dict(get=0.70, dist="zipf:1.0", sizes=[100, 300, 1000, 3000], ttls=[0, 300, 3600], keyspace=50_000),
    "write-heavy":     dict(get=0.30, dist="zipf:0.8", sizes=[100, 300, 1000, 3000], ttls=[60, 300, 3600], keyspace=50_000),
    "hot-key":         dict(get=0.90, dist="hot:10:0.90", sizes=[200, 1000], ttls=[300], keyspace=50_000),
    # Working set well above a 64 MB node: forces constant eviction pressure with reads.
    "memory-pressure": dict(get=0.70, dist="uniform", sizes=[2000, 4000, 8000], ttls=[0, 3600], keyspace=400_000),
    # Mostly writes of large values into a huge keyspace: evictions dominate.
    "eviction-heavy":  dict(get=0.30, dist="uniform", sizes=[8000, 16000, 32000, 64000], ttls=[0], keyspace=600_000),
}


class Keys:
    def __init__(self, spec, n, rnd):
        self.n, self.rnd = n, rnd
        kind, *arg = spec.split(":")
        self.kind = kind
        if kind == "zipf":
            s = float(arg[0])
            acc, self.cum = 0.0, []
            for i in range(n):
                acc += 1.0 / ((i + 1) ** s)
                self.cum.append(acc)
            self.total = acc
        elif kind == "hot":
            self.hot, self.share = int(arg[0]), float(arg[1])

    def pick(self):
        r = self.rnd
        if self.kind == "zipf":
            return min(bisect.bisect_left(self.cum, r.random() * self.total), self.n - 1)
        if self.kind == "hot":
            return r.randrange(self.hot) if r.random() < self.share else r.randrange(self.n)
        return r.randrange(self.n)


class Conn:
    def __init__(self, host, port, timeout):
        self.host, self.port, self.timeout = host, port, timeout
        self.r = self.w = None

    async def open(self):
        self.r, self.w = await asyncio.wait_for(asyncio.open_connection(self.host, self.port), self.timeout)

    def close(self):
        if self.w:
            self.w.close()
        self.r = self.w = None

    async def _line(self):
        return await asyncio.wait_for(self.r.readline(), self.timeout)

    async def get(self, key):
        self.w.write(f"get {key}\r\n".encode())
        hit = False
        while True:
            line = await self._line()
            if not line:
                raise ConnectionError("closed")
            if line.startswith(b"VALUE"):
                n = int(line.split()[3])
                await asyncio.wait_for(self.r.readexactly(n + 2), self.timeout)
                hit = True
            elif line.startswith(b"END"):
                return hit
            else:
                raise ConnectionError(f"unexpected reply {line[:40]!r}")

    async def set(self, key, size, ttl):
        self.w.write(f"set {key} 0 {ttl} {size}\r\n".encode() + b"x" * size + b"\r\n")
        line = await self._line()
        if not line.startswith(b"STORED"):
            raise ConnectionError(f"set refused {line[:40]!r}")

    async def delete(self, key):
        self.w.write(f"delete {key}\r\n".encode())
        line = await self._line()
        if not (line.startswith(b"DELETED") or line.startswith(b"NOT_FOUND")):
            raise ConnectionError(f"delete refused {line[:40]!r}")


def pct(sorted_ms, q):
    if not sorted_ms:
        return None
    return round(sorted_ms[min(len(sorted_ms) - 1, int(q * len(sorted_ms)))], 3)


async def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", action="append", help="host:port; repeat to shard keys client-side")
    ap.add_argument("--profile", default="read-heavy", choices=sorted(PROFILES))
    ap.add_argument("--duration", type=float, default=30, help="seconds")
    ap.add_argument("--concurrency", type=int, default=32)
    ap.add_argument("--rps", type=float, default=0, help="total requests/s; 0 = as fast as possible")
    ap.add_argument("--keyspace", type=int, help="number of distinct keys (default per profile)")
    ap.add_argument("--value-size", type=int, help="fixed value size in bytes (default per profile)")
    ap.add_argument("--get-ratio", type=float, help="override the profile's GET share (0-1)")
    ap.add_argument("--delete-share", type=float, default=0.10, help="share of non-GET requests that are DELETE")
    ap.add_argument("--warm", type=float, default=0.5, help="fraction of the keyspace written before the run")
    ap.add_argument("--fill-on-miss", action="store_true", help="SET after a GET miss (cache-aside)")
    ap.add_argument("--timeout", type=float, default=2.0, help="per-operation timeout, seconds")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--list-profiles", action="store_true")
    a = ap.parse_args()
    if a.list_profiles:
        print(json.dumps(PROFILES, indent=2))
        return
    if not a.target:
        ap.error("--target is required")
    p = PROFILES[a.profile]
    get_ratio = p["get"] if a.get_ratio is None else a.get_ratio
    keyspace = a.keyspace or p["keyspace"]
    sizes = [a.value_size] if a.value_size else p["sizes"]
    targets = [(t.rsplit(":", 1)[0], int(t.rsplit(":", 1)[1])) for t in a.target]

    stats = dict(get=0, get_hit=0, get_miss=0, set=0, delete=0, fill_sets=0, errors=0, timeouts=0, reconnects=0)
    lat = {"get": [], "set": [], "delete": []}

    def target_for(idx):
        return targets[idx % len(targets)]

    async def warm():
        n = int(keyspace * a.warm)
        rnd = random.Random(a.seed)
        conns = {}
        for i in range(n):
            h, pt = target_for(i)
            c = conns.get((h, pt))
            if c is None:
                c = conns[(h, pt)] = Conn(h, pt, a.timeout)
                await c.open()
            try:
                await c.set(f"k:{i}", sizes[rnd.randrange(len(sizes))], p["ttls"][rnd.randrange(len(p["ttls"]))])
            except Exception:
                pass
        for c in conns.values():
            c.close()

    deadline = 0.0
    per_worker_interval = (a.concurrency / a.rps) if a.rps > 0 else 0.0

    async def worker(wid):
        rnd = random.Random(a.seed * 1000 + wid)
        keys = Keys(p["dist"], keyspace, rnd)
        conns = {}
        next_at = time.perf_counter() + rnd.random() * per_worker_interval
        while time.perf_counter() < deadline:
            if per_worker_interval:
                delay = next_at - time.perf_counter()
                if delay > 0:
                    await asyncio.sleep(delay)
                next_at += per_worker_interval
            idx = keys.pick()
            host, port = target_for(idx)
            c = conns.get((host, port))
            r = rnd.random()
            op = "get" if r < get_ratio else ("delete" if rnd.random() < a.delete_share else "set")
            t0 = time.perf_counter()
            try:
                if c is None or c.w is None:
                    c = conns[(host, port)] = Conn(host, port, a.timeout)
                    await c.open()
                key = f"k:{idx}"
                if op == "get":
                    hit = await c.get(key)
                    stats["get_hit" if hit else "get_miss"] += 1
                    if not hit and a.fill_on_miss:
                        await c.set(key, sizes[rnd.randrange(len(sizes))], p["ttls"][rnd.randrange(len(p["ttls"]))])
                        stats["fill_sets"] += 1
                elif op == "set":
                    await c.set(key, sizes[rnd.randrange(len(sizes))], p["ttls"][rnd.randrange(len(p["ttls"]))])
                else:
                    await c.delete(key)
                stats[op] += 1
                lat[op].append((time.perf_counter() - t0) * 1000)
            except asyncio.TimeoutError:
                stats["timeouts"] += 1
                if c:
                    c.close()          # never reuse a connection after a half-read reply
                stats["reconnects"] += 1
            except (ConnectionError, OSError, asyncio.IncompleteReadError):
                stats["errors"] += 1
                if c:
                    c.close()
                stats["reconnects"] += 1
                await asyncio.sleep(0.05)
        for c in conns.values():
            c.close()

    if a.warm > 0:
        await warm()
    started = time.perf_counter()
    deadline = started + a.duration
    await asyncio.gather(*(worker(i) for i in range(a.concurrency)))
    elapsed = time.perf_counter() - started
    total = stats["get"] + stats["set"] + stats["delete"]
    out = {
        "profile": a.profile, "targets": a.target, "duration_s": round(elapsed, 2),
        "concurrency": a.concurrency, "requested_rps": a.rps or "max", "keyspace": keyspace,
        "value_sizes": sizes, "get_ratio": get_ratio, "delete_share": a.delete_share,
        "requests": total, "achieved_rps": round(total / elapsed, 1),
        "ops": {k: stats[k] for k in ("get", "set", "delete", "fill_sets")},
        "observed_mix": {k: round(stats[k] / total, 3) if total else 0 for k in ("get", "set", "delete")},
        "cache": {"hits": stats["get_hit"], "misses": stats["get_miss"],
                  "hit_ratio": round(stats["get_hit"] / stats["get"], 4) if stats["get"] else None},
        "errors": stats["errors"], "timeouts": stats["timeouts"], "reconnects": stats["reconnects"],
        "latency_ms": {op: {"p50": pct(sorted(v), .50), "p95": pct(sorted(v), .95), "p99": pct(sorted(v), .99)}
                       for op, v in lat.items() if v},
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(130)
