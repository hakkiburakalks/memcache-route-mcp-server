# Operations

This guide combines the production runbook and the local load/chaos laboratory. It does not
start Docker, publish images or connect to production Memcached. Commands are templates:
review values and secret names for your environment first.

This runbook is for operators deploying the Helm chart. It does not start Docker, publish images,
or connect to production Memcached. Commands are templates: review the values and secret names for
your cluster first.

## 1. Preflight

- [ ] Image is a reviewed **digest** (`image.digest: sha256:...`), not a mutable tag.
- [ ] `imagePullSecrets` exists if the registry is private; the chart does not create it.
- [ ] `auth.existingSecret` exists with the selected key (`tokens.json` for file mode, `token` for
      shared-token mode). The Secret is in the release namespace.
- [ ] `allowlist` contains every `host:port` the tools may reach, and nothing else.
- [ ] `allowedHosts` contains the public ingress hostname; otherwise `Host` checks reject it.
- [ ] TLS terminates at an ingress/service mesh. The binary itself speaks plain HTTP; the chart
      sets `MEMCACHED_MCP_HTTP_ALLOW_PLAINTEXT=1` only inside the pod network.
- [ ] `resources.requests/limits` are sized for your workload. **256Mi is not a measured
      guarantee**; see [CONTAINER-SECURITY.md](CONTAINER-SECURITY.md) and the memory-budget
      limitations in [CONFIGURATION.md](CONFIGURATION.md#process-wide-memory-budget).
- [ ] `networkPolicy.enabled=true` with explicit ingress peers, and egress rules for the
      memcached/mcrouter destination labels and ports, if the CNI enforces NetworkPolicy.
- [ ] `replicaCount` and `autoscaling` are deliberate. Each replica has its own in-memory sessions,
      token store and rate limits. HPA scale-down loses sessions.
- [ ] A log pipeline collects stderr (audit and server logs); the image has no shell and no local
      log rotation.

## 2. Install

Create the Secret out of band. Do not put tokens in `values.yaml` or Helm CLI arguments.

```sh
# One-off: issue a token, then store only the hashed entry in the Secret.
memcached-mcp new-token alice read,metrics 30
kubectl -n mcp create secret generic mcp-tokens --from-file=tokens.json
```

Install:

```sh
helm upgrade --install mcp deploy/helm/memcached-mcp -n mcp --create-namespace \
  --values production-values.yaml \
  --set image.repository=registry.example.com/memcached-mcp \
  --set image.tag=0.1.0-alpha.9 \
  --set image.digest=sha256:<64-hex> \
  --atomic --wait --timeout 5m
```

Check:

```sh
kubectl -n mcp rollout status deployment/mcp-memcached-mcp
kubectl -n mcp get pods -l app.kubernetes.io/name=memcached-mcp
kubectl -n mcp port-forward svc/mcp-memcached-mcp 8080:8080
curl -fsS http://127.0.0.1:8080/healthz
# /metrics needs a token with the `metrics` permission:
curl -fsS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/metrics | head
```

Expected logs: `listening on http://0.0.0.0:8080/mcp`, `auth: N user(s) loaded`, and no token
values. A bad token returns 401; rate/concurrency refusals return 429 with `Retry-After`; a
scrubbed `/metrics` failure returns 503.

## 3. Upgrade

```sh
helm diff upgrade mcp deploy/helm/memcached-mcp -n mcp -f production-values.yaml  # optional plugin
helm upgrade mcp deploy/helm/memcached-mcp -n mcp -f production-values.yaml \
  --atomic --wait --timeout 5m
kubectl -n mcp rollout status deployment/mcp-memcached-mcp
```

The chart uses `maxUnavailable: 0`, `maxSurge: 1`, a 30 s termination grace period and a 10 s
in-process drain. With one replica, the new pod becomes ready before the old pod is removed; MCP
sessions on the old pod are still lost when it terminates. Clients must re-initialise or use a
sticky ingress that keeps the old endpoint until the session ends.

## 4. Rollback

```sh
helm history mcp -n mcp
helm rollback mcp <revision> -n mcp --wait --timeout 5m
kubectl -n mcp rollout status deployment/mcp-memcached-mcp
kubectl -n mcp get pdb
```

Rollback changes the image/config but not Secrets. If the previous release expected a different
Secret key (`tokens.json` vs `token`), restore it first and expect a brief 401/503 window.

## 5. Token rotation and revocation

File mode (`auth.mode=file`, preferred):

1. Add the new hashed entry, or remove the old entry, in `tokens.json`.
2. Update the Secret:
   `kubectl -n mcp create secret generic mcp-tokens --from-file=tokens.json --dry-run=client -o yaml | kubectl apply -f -`
3. Wait for the projected Secret to update (measured on kind: about 93 s including kubelet sync)
   and for the server's 5-second reload tick.
4. Verify: old token gets 401; new token initialises and can call `tools/list`.
5. Removing a user closes that user's open sessions on the next reload. Do not leave an empty or
   invalid file: an empty `users` list revokes everyone; an invalid file keeps the previous users
   and is reported in the audit log.

Shared-token mode (`auth.mode=token`): the token is in an environment variable, so updating the
Secret does **not** change the running process. Restart the Deployment and accept a short
unavailability window, or migrate to file mode.

## 6. Graceful shutdown and rollout restart

```sh
kubectl -n mcp rollout restart deployment/mcp-memcached-mcp
kubectl -n mcp rollout status deployment/mcp-memcached-mcp
kubectl -n mcp logs deployment/mcp-memcached-mcp --tail=100
```

Look for `shutdown: signal received, draining`. The process waits up to 10 s for in-flight
requests; the pod is allowed 30 s. The scratch image has no shell for a `preStop sleep`, so do not
rely on a fixed delay to drain long-lived SSE streams. Use client reconnect/retry at the ingress.

## 7. Scaling

- **Manual replicas:** safe for stateless request/response calls only with sticky routing; sessions
  are per pod. Per-user request/session caps and token reload state are per pod, so N replicas mean
  up to N times the per-pod allowance.
- **HPA:** off by default. If enabled, set `minReplicas >= 2`, require working session affinity and
  client re-initialise behavior, and remember that scale-down terminates sessions and ignores the
  PodDisruptionBudget. The default CPU request is 50m, so a CPU-utilization target is noisy; tune
  `resources.requests.cpu` and `autoscaling.targetCPUUtilizationPercentage` together.
- **PDB:** rendered only with more than one replica (or HPA). `minAvailable: 1` protects voluntary
  disruptions, not HPA scale-down and not node failure.
- **Session affinity:** the chart uses `ClientIP` with a 3-hour timeout. Behind an ingress/LB, make
  routing sticky with a cookie or equivalent; client IPs can change through NAT/proxies.

## 8. Incident checks

| Symptom | Check |
|---|---|
| Pod not ready | `kubectl describe pod`, startup/readiness events, `/healthz` via port-forward |
| 401 everywhere | Secret key/name, token hash, `auth.mode`, projected file content (never print the raw token in tickets) |
| 429 | Per-user `MEMCACHED_MCP_HTTP_MAX_CONCURRENT` or `/metrics` cap; inspect client concurrency |
| `/metrics` 503 | Overall scrape deadline or cache-body reservation; check target latency and memory budget gauges |
| Target rows `up 0` | DNS/egress NetworkPolicy, allowlist mismatch, target down; `/healthz` will still be 200 by design |
| OOMKilled | Compare `memcached_mcp_memory_budget_available_bytes`, tool workload and actual RSS; 256Mi is not a proven limit |
| Sessions vanish | Pod restarted/scaled down or request routed to another pod; inspect affinity and `helm history` |
| Audit stopped | stderr/log collector, disk pressure; if `MEMCACHED_MCP_AUDIT_LOG` is set, its writable volume |

## 9. Capacity and guarantees

- The 96 MiB reservation budget is **not** a process RSS limit. JSON-RPC/HTTP copies, allocator
  overhead and runtime memory are outside it.
- The 256 MiB container limit in the chart is a starting point, not a measured production
  guarantee. No Linux/container peak-RSS or OOM validation was performed in this work package.
- The in-memory session architecture limits horizontal scaling. Do not promise shared sessions,
  cross-pod rate limits or seamless HPA scale-down.
- NetworkPolicy behavior depends on the CNI; the chart only emits policy objects. It was not
  tested against a live CNI here.

## 10. Related documents

- [DEPLOYMENT.md](DEPLOYMENT.md)
- [CONTAINER-SECURITY.md](CONTAINER-SECURITY.md)
- [CONFIGURATION.md](CONFIGURATION.md)
- [SECURITY.md](../SECURITY.md)

## Load and chaos laboratory

`tests/load-lab/` is a local Docker Compose lab for exercising the HTTP transport, the tool
fan-out and the mcrouter destination comparison under load. It is development tooling, not part
of the release artifact, and it is not run in CI.

### What is there

| Path | Purpose |
| --- | --- |
| `docker-compose.yml` | memcached nodes, an mcrouter, the server image, Prometheus and Grafana |
| `loadgen.py` | traffic generator for `healthz`, `tools/list`, `get_stats`, `compare_nodes`, `mcrouter_compare_destinations` and `/metrics` |
| `bench_mcp.py` | MCP benchmark driver; writes JSON/log output to the path you choose |
| `chaos.sh`, `chaos_test.py` | kill/restart/partition style checks against the running lab |
| `run-load.sh` | convenience wrapper |
| `prometheus/`, `grafana/` | scrape configuration and a dashboard |
| `results/` | local output directory (generated; ignored by git) |

### Running it

Docker must be running locally. From the repository root:

```sh
docker compose -f tests/load-lab/docker-compose.yml up -d --build
tests/load-lab/run-load.sh
docker compose -f tests/load-lab/docker-compose.yml down
```

The compose file publishes host ports for the memcached nodes and mcrouter. It builds the server
image as `memcached-mcp:lab`. The lab is loopback-grade: Docker Desktop on Windows/macOS adds VM
latency, so absolute numbers are useful for comparisons within one machine, not as production
capacity claims.

### Reading the results

A run writes `results/bench-*.log` and `results/bench-*.json` (ignored by git); keep the recorded
environment with the numbers: CPU count, Docker VM memory and loopback latency are part of the
result. Historical local runs covered 1, 3, 16, 64, 128 and 256-node stages.

The 256-node stage is deliberately a stress case. It shows where connection fan-out and response
buffering become visible (for example `compare_nodes` and `/metrics` latency), not a supported
cluster size guarantee.
