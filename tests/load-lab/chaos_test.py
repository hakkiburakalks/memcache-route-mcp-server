#!/usr/bin/env python3
"""Network chaos scenarios against the lab, driven through the MCP server's HTTP API.

Needs the lab running (docker compose up -d --build). Chaos is applied to one lab container at
a time by chaos.sh, never to the host. Prints one line per check (PASS / FAIL) and a JSON
summary; exits non-zero if anything failed.

    python chaos_test.py            # all scenarios
    python chaos_test.py latency    # only scenarios whose name contains the word
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

PORT = os.environ.get("MCP_PORT", "18080")
TOKEN = os.environ.get("LAB_TOKEN", "lab-token-lab-token-lab-token-0123456789")
HERE = os.path.dirname(os.path.abspath(__file__))
NODES = ["mc1:11211", "mc2:11211", "mc3:11211"]
results = []
# On Windows a bare "bash" can resolve to the WSL launcher; use the one found on PATH.
BASH = shutil.which("bash") or "bash"


def http(body, sid=None, timeout=60):
    h = {"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json",
         "Accept": "application/json, text/event-stream"}
    if sid:
        h["Mcp-Session-Id"] = sid
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}/mcp", json.dumps(body).encode(), h)
    r = urllib.request.urlopen(req, timeout=timeout)
    return r.headers.get("Mcp-Session-Id"), r.read().decode()


def session():
    sid, _ = http({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "chaos", "version": "0"}}})
    http({"jsonrpc": "2.0", "method": "notifications/initialized"}, sid)
    return sid


def call(sid, tool, args, timeout=60):
    """Returns (is_error, text, seconds)."""
    t0 = time.time()
    _, out = http({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                   "params": {"name": tool, "arguments": args}}, sid, timeout)
    dt = time.time() - t0
    d = [json.loads(x) for x in re.findall(r"data: (\{.*\})", out)][-1]
    if "error" in d:
        return True, json.dumps(d["error"]), dt
    r = d["result"]
    return bool(r.get("isError")), r["content"][0]["text"], dt


def chaos(*a):
    subprocess.run([BASH, "chaos.sh", *a], check=True, capture_output=True, cwd=HERE)


def check(name, ok, detail=""):
    results.append({"check": name, "result": "PASS" if ok else "FAIL", "detail": detail})
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}")


def conns(sid, node="mc3:11211"):
    err, text, _ = call(sid, "get_stats", {"addr": node})
    return int(json.loads(text)["curr_connections"]) if not err else -1


def healthy(sid):
    err, text, _ = call(sid, "compare_nodes", {"addrs": NODES})
    return (not err) and json.loads(text)["unreachable"] == []


def heal_all():
    for s in ("mc1", "mc2", "mc3", "mcrouter"):
        try:
            chaos("heal", s)
        except Exception:
            pass


def scenario_latency(sid):
    for ms in (10, 50, 100):
        chaos("latency", "mc1", str(ms))
        err, text, dt = call(sid, "get_stats", {"addr": "mc1:11211"})
        check(f"latency {ms}ms: get_stats still works", not err, f"{dt:.2f}s")
        # Connect + stats + (no extra round trips): expect a small multiple of the delay.
        check(f"latency {ms}ms: call time bounded", dt < 3.0, f"{dt:.2f}s")
        chaos("heal", "mc1")


def scenario_loss(sid):
    for pct in (1, 5):
        chaos("loss", "mc2", str(pct))
        ok = errs = 0
        slowest = 0.0
        for _ in range(60):
            err, text, dt = call(sid, "get_stats", {"addr": "mc2:11211"})
            ok += not err
            errs += bool(err)
            slowest = max(slowest, dt)
        # Loss can cost retransmits (up to the 3 s op timeout) but must never hang a call.
        check(f"packet loss {pct}%: every call returns within the op timeout", slowest < 8.0,
              f"ok={ok} err={errs} slowest={slowest:.2f}s")
        chaos("heal", "mc2")
    check("recovered after packet loss", healthy(sid))


def scenario_slow_node(sid):
    chaos("slow", "mc3")     # 500 ms +- 100 ms
    err, text, dt = call(sid, "compare_nodes", {"addrs": NODES})
    check("slow node: compare_nodes completes", not err and dt < 10, f"{dt:.2f}s")
    chaos("heal", "mc3")
    check("slow node: recovered", healthy(sid))


def scenario_partition(sid):
    before = conns(sid)
    chaos("partition", "mc2")
    err, text, dt = call(sid, "compare_nodes", {"addrs": NODES})
    unreachable = json.loads(text)["unreachable"] if not err else []
    check("partition: node reported unreachable, others compared",
          not err and len(unreachable) == 1 and "mc2" in unreachable[0], f"{dt:.2f}s {unreachable}")
    check("partition: bounded by the op timeout", dt < 8.0, f"{dt:.2f}s")
    err, text, dt = call(sid, "get_stats", {"addr": "mc2:11211"})
    check("partition: single-node call returns an error, not a hang", err and dt < 8.0, f"{dt:.2f}s {text[:60]}")
    chaos("heal", "mc2")
    time.sleep(1)
    check("partition: recovered after heal", healthy(sid))
    check("partition: no connection leak on a healthy node", conns(sid) <= before + 2, f"{before} -> {conns(sid)}")


def scenario_reset(sid):
    chaos("reset", "mc1")
    err, text, dt = call(sid, "get_stats", {"addr": "mc1:11211"})
    check("connection reset: clean error", err and dt < 5.0, f"{dt:.2f}s {text[:70]}")
    chaos("heal", "mc1")
    check("connection reset: recovered", healthy(sid))


def scenario_restarts(sid):
    chaos("restart", "mc1")
    time.sleep(1.5)
    err, text, dt = call(sid, "get_stats", {"addr": "mc1:11211"})
    check("node restart: reachable again", not err, f"{dt:.2f}s")
    if not err:
        up = int(json.loads(text)["uptime"])
        check("node restart: uptime reset (counters restarted)", up < 30, f"uptime={up}s")
    err, text, dt = call(sid, "diagnose_node", {"addr": "mc1:11211"})
    check("node restart: diagnosis on a fresh node does not raise alarms",
          not err and all(f["severity"] != "critical" for f in json.loads(text)), text[:100])
    chaos("restart", "mcrouter")
    time.sleep(2.5)
    err, text, dt = call(sid, "mcrouter_get_stats", {"addr": "mcrouter:5000"})
    check("mcrouter restart: reachable again", not err, f"{dt:.2f}s {text[:60]}")


def scenario_cancel(sid):
    """Clients that give up mid-request must not leave connections behind on the server side."""
    before = conns(sid)
    chaos("slow", "mc3")
    for _ in range(10):
        try:
            http({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                  "params": {"name": "get_stats", "arguments": {"addr": "mc3:11211"}}}, sid, timeout=0.15)
        except Exception:
            pass          # the client hung up on purpose
    chaos("heal", "mc3")
    time.sleep(8)         # let in-flight work finish or time out
    after = conns(sid)
    check("cancelled requests: connections to memcached are released", after <= before + 2, f"{before} -> {after}")
    check("cancelled requests: server still healthy", healthy(sid))


SCENARIOS = [("latency", scenario_latency), ("loss", scenario_loss), ("slow", scenario_slow_node),
             ("partition", scenario_partition), ("reset", scenario_reset), ("restarts", scenario_restarts),
             ("cancel", scenario_cancel)]

if __name__ == "__main__":
    only = sys.argv[1] if len(sys.argv) > 1 else ""
    heal_all()
    sid = session()
    check("baseline: all nodes reachable", healthy(sid))
    for name, fn in SCENARIOS:
        if only and only not in name:
            continue
        print(f"--- {name}")
        try:
            fn(sid)
        except Exception as e:      # a crashed scenario is a failure, not a skip
            check(f"{name}: scenario ran to completion", False, repr(e)[:150])
        finally:
            heal_all()
    failed = [r for r in results if r["result"] == "FAIL"]
    print(json.dumps({"passed": len(results) - len(failed), "failed": len(failed)}))
    sys.exit(1 if failed else 0)
