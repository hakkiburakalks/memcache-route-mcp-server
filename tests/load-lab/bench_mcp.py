#!/usr/bin/env python3
"""Throughput / latency benchmark of the MCP server itself, at several cluster sizes.

For each node count N it starts N small memcached containers, an mcrouter fronting them and a
dedicated MCP server container (all on the lab network, removed afterwards), then drives a
closed loop of C client threads per operation:

    healthz           plain HTTP, no MCP         -> transport floor
    tools_list        MCP request, no backend    -> MCP/JSON-RPC overhead
    get_stats         MCP + one memcached node   -> adds one backend round trip
    compare_nodes     MCP + N nodes in parallel
    mcrouter_compare  MCP + mcrouter config + N destinations
    metrics           GET /metrics with N scrape targets

The Python client is a measurement tool with its own limits (GIL, one process); numbers show
relative behaviour on this machine, not a guarantee. Results go to --out as JSON.

    python bench_mcp.py --nodes 1 3 16 --duration 8 --concurrency 1 8
"""
import argparse
import http.client
import json
import os
import platform
import re
import subprocess
import tempfile
import threading
import time

NET = "memcached-mcp-lab"
IMAGE = "memcached-mcp:lab"
TOKEN = "bench-token-bench-token-bench-token-0123456789"
PORT = 18090


def sh(*cmd, check=True):
    return subprocess.run(cmd, check=check, capture_output=True, text=True, encoding="utf8", errors="replace")


def env_info():
    ver = sh("docker", "version", "--format", "{{.Server.Version}}", check=False).stdout.strip()
    mem = sh("docker", "info", "--format", "{{.MemTotal}}", check=False).stdout.strip()
    return {"platform": platform.platform(), "python": platform.python_version(), "cpus": os.cpu_count(),
            "docker_server": ver, "docker_vm_memory_bytes": int(mem) if mem.isdigit() else None,
            "note": "Docker Desktop VM; loopback-grade latency, not a real network"}


def start_cluster(n):
    names = [f"bn{i}" for i in range(1, n + 1)]
    if sh("docker", "network", "inspect", NET, check=False).returncode:
        sh("docker", "network", "create", NET)
    procs = [subprocess.Popen(["docker", "run", "-d", "--rm", "--name", f"bench-{x}", "--network", NET,
                               "--network-alias", x, "memcached:1.6", "-m", "16"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for x in names]
    for p in procs:
        p.wait()
    cfg = {"pools": {"main": {"servers": [f"{x}:11211" for x in names]}}, "route": "PoolRoute|main"}
    path = os.path.join(tempfile.gettempdir(), "bench-mcrouter.json")
    json.dump(cfg, open(path, "w"))
    sh("docker", "rm", "-f", "bench-mcrouter", "bench-mcp", check=False)
    sh("docker", "create", "--name", "bench-mcrouter", "--network", NET, "--network-alias", "bench-mcrouter",
       "mcrouter/mcrouter", "mcrouter", "--config-file=/etc/mcrouter.json", "-p", "5000")
    sh("docker", "cp", path, "bench-mcrouter:/etc/mcrouter.json")
    sh("docker", "start", "bench-mcrouter")
    nodes = ",".join(f"{x}:11211" for x in names)
    dest_map = ",".join(f"{x}:11211={x}:11211" for x in names)
    sh("docker", "run", "-d", "--name", "bench-mcp", "--network", NET, "-p", f"127.0.0.1:{PORT}:8080",
       "-e", f"MEMCACHED_MCP_HTTP_TOKEN={TOKEN}", "-e", "MEMCACHED_MCP_HTTP_ALLOW_PLAINTEXT=1",
       "-e", f"MEMCACHED_MCP_ALLOWLIST={nodes},bench-mcrouter:5000",
       "-e", f"MEMCACHED_MCP_METRICS_TARGETS={nodes}", "-e", f"MEMCACHED_MCP_DEST_MAP={dest_map}",
       "-e", "MEMCACHED_MCP_HTTP_MAX_CONCURRENT=64", "-e", "MEMCACHED_MCP_HTTP_MAX_SESSIONS_PER_USER=128",
       IMAGE, "--http", "0.0.0.0:8080")
    time.sleep(3)
    return names


def stop_cluster(names):
    sh("docker", "rm", "-f", "bench-mcp", "bench-mcrouter", *[f"bench-{x}" for x in names], check=False)


class Client:
    def __init__(self):
        self.c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=60)
        self.sid = None
        self.n = 10

    def post(self, body):
        h = {"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json",
             "Accept": "application/json, text/event-stream"}
        if self.sid:
            h["Mcp-Session-Id"] = self.sid
        self.c.request("POST", "/mcp", json.dumps(body), h)
        r = self.c.getresponse()
        return r, r.read().decode()

    def init(self):
        r, _ = self.post({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "bench", "version": "0"}}})
        self.sid = r.getheader("Mcp-Session-Id")
        if r.status != 200 or not self.sid:
            raise RuntimeError(f"initialize failed: HTTP {r.status}")
        self.post({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def close(self):
        """Ends the session so runs do not pile up against the per-user session cap."""
        try:
            if self.sid:
                h = {"Authorization": "Bearer " + TOKEN, "Mcp-Session-Id": self.sid}
                self.c.request("DELETE", "/mcp", headers=h)
                self.c.getresponse().read()
        except Exception:
            pass
        self.c.close()

    def tool(self, name, args):
        self.n += 1
        r, data = self.post({"jsonrpc": "2.0", "id": self.n, "method": "tools/call",
                             "params": {"name": name, "arguments": args}})
        return r.status == 200 and '"isError":true' not in data and '"error"' not in data[:200]

    def tools_list(self):
        self.n += 1
        r, _ = self.post({"jsonrpc": "2.0", "id": self.n, "method": "tools/list"})
        return r.status == 200

    def get(self, path, auth=True):
        h = {"Authorization": "Bearer " + TOKEN} if auth else {}
        self.c.request("GET", path, headers=h)
        r = self.c.getresponse()
        r.read()
        return r.status == 200


def pct(v, q):
    return round(v[min(len(v) - 1, int(q * len(v)))] * 1000, 2) if v else None


def sample_resources(stop, out):
    while not stop.is_set():
        r = sh("docker", "stats", "--no-stream", "--format", "{{.CPUPerc}}|{{.MemUsage}}", "bench-mcp", check=False)
        m = re.match(r"([\d.]+)%\|([\d.]+)(\w+)", r.stdout.strip())
        if m:
            mem = float(m.group(2)) * {"B": 1, "KiB": 1024, "MiB": 1 << 20, "GiB": 1 << 30}.get(m.group(3), 1)
            out.append((float(m.group(1)), mem))
        stop.wait(0.3)


def run_op(label, make_fn, conc, secs, needs_session=True):
    clients = []
    for _ in range(conc):
        c = Client()
        if needs_session:
            c.init()
        clients.append(c)
    lat, errs, lock = [], [0], threading.Lock()
    stop_at = time.time() + secs
    res, stop = [], threading.Event()
    rt = threading.Thread(target=sample_resources, args=(stop, res))
    rt.start()

    def worker(c):
        fn = make_fn(c)
        mine, e = [], 0
        while time.time() < stop_at:
            t0 = time.perf_counter()
            try:
                ok = fn()
            except Exception:
                ok = False
            dt = time.perf_counter() - t0
            if ok:
                mine.append(dt)
            else:
                e += 1
        with lock:
            lat.extend(mine)
            errs[0] += e

    ts = [threading.Thread(target=worker, args=(c,)) for c in clients]
    t0 = time.time()
    [t.start() for t in ts]
    [t.join() for t in ts]
    el = time.time() - t0
    stop.set()
    rt.join()
    for c in clients:
        c.close()
    lat.sort()
    total = len(lat) + errs[0]
    return {"op": label, "concurrency": conc, "requests": total, "rps": round(total / el, 1),
            "p50_ms": pct(lat, .5), "p95_ms": pct(lat, .95), "p99_ms": pct(lat, .99),
            "error_rate": round(errs[0] / total, 4) if total else None,
            "cpu_pct_avg": round(sum(r[0] for r in res) / len(res), 1) if res else None,
            "cpu_pct_max": max((r[0] for r in res), default=None),
            "mem_mib_max": round(max((r[1] for r in res), default=0) / (1 << 20), 1)}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--nodes", type=int, nargs="+", default=[1, 3, 16])
    ap.add_argument("--concurrency", type=int, nargs="+", default=[1, 8])
    ap.add_argument("--duration", type=float, default=8)
    ap.add_argument("--out", default="bench-results.json")
    a = ap.parse_args()
    report = {"environment": env_info(), "duration_s": a.duration, "runs": []}
    for n in a.nodes:
        print(f"== {n} node(s)", flush=True)
        names = start_cluster(n)
        try:
            addrs = [f"{x}:11211" for x in names]
            ops = {
                "healthz": lambda c: (lambda: c.get("/healthz", auth=False)),
                "tools_list": lambda c: c.tools_list,
                "get_stats": lambda c: (lambda: c.tool("get_stats", {"addr": addrs[0]})),
                "compare_nodes": lambda c: (lambda: c.tool("compare_nodes", {"addrs": addrs})),
                "mcrouter_compare": lambda c: (lambda: c.tool("mcrouter_compare_destinations", {"addr": "bench-mcrouter:5000"})),
                "metrics": lambda c: (lambda: c.get("/metrics")),
            }
            for conc in a.concurrency:
                for label, mk in ops.items():
                    r = run_op(label, mk, conc, a.duration, needs_session=label not in ("healthz", "metrics"))
                    r["nodes"] = n
                    report["runs"].append(r)
                    print(f"  {label:17} c={conc:<3} {r['rps']:>8} rps  p50={r['p50_ms']}ms p95={r['p95_ms']}ms "
                          f"p99={r['p99_ms']}ms err={r['error_rate']} cpu={r['cpu_pct_avg']}% mem={r['mem_mib_max']}MiB",
                          flush=True)
        finally:
            stop_cluster(names)
        json.dump(report, open(a.out, "w"), indent=2)
    print("written", a.out)


if __name__ == "__main__":
    main()
