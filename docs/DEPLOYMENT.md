# Deployment

The server speaks MCP over **stdio** (default, one client, the process owner is trusted) and
**Streamable HTTP** (`--http ADDR:PORT`, bearer tokens, several clients). There is no TLS in the
binary: terminate it at a proxy, ingress or service mesh.

## Binary

Download the archive for your platform from the GitHub release, or build:

```
cargo build --release --locked -p memcache-route-mcp-server      # target/release/memcached-mcp
```

stdio, for a local assistant:

```
MEMCACHED_MCP_ALLOWLIST=127.0.0.1:11211 ./memcached-mcp
```

HTTP on loopback:

```
memcached-mcp new-token alice read,metrics 30          # prints the token once, plus a file entry
echo '{"users":[ <entry from above> ]}' > tokens.json
MEMCACHED_MCP_ALLOWLIST=127.0.0.1:11211 MEMCACHED_MCP_HTTP_TOKEN_FILE=tokens.json \
  ./memcached-mcp --http 127.0.0.1:8080
curl -s http://127.0.0.1:8080/healthz          # ok
```

## Docker

The image is a static musl binary in an empty (`scratch`) image running as UID 65532. It is not
published by the project yet; build it:

```
docker build -t memcached-mcp:local .
docker run --rm -p 127.0.0.1:8080:8080 \
  -e MEMCACHED_MCP_ALLOWLIST=host.docker.internal:11211 \
  -e MEMCACHED_MCP_HTTP_TOKEN="$(head -c 32 /dev/urandom | base64 | tr -d '=+/')" \
  -e MEMCACHED_MCP_HTTP_ALLOW_PLAINTEXT=1 \
  memcached-mcp:local --http 0.0.0.0:8080
```

Publish the port on loopback or behind a TLS proxy; `ALLOW_PLAINTEXT=1` acknowledges that the
container listens on a non-loopback address inside its network. The image has no shell, so a
`HEALTHCHECK` cannot run a command; use an HTTP check against `/healthz` from the orchestrator.

The image carries OCI labels (title, source, licence, revision, version, created) set from build
arguments. The Rust builder is pinned by version and multi-arch digest; see
[CONTAINER-SECURITY.md](CONTAINER-SECURITY.md) for the pin, SBOM, provenance and vulnerability
scanning gates. The final image is `scratch` with no shell, so use an HTTP health check from the
orchestrator. The current branding image `memcached-mcp:0.1.0-alpha.9` was built and run locally (non-root,
read-only rootfs, healthy `/healthz`). Syft, Trivy and Cosign were used from verified official
releases for local SBOM generation, **0 vulnerability / 0 secret** scans and a transparency-logged
Cosign blob signature; no image signature, provenance or publication exists yet.

## Kubernetes (Helm)

The chart targets Kubernetes **1.23+** (uses `autoscaling/v2` and `policy/v1`).

```
kubectl create secret generic mcp-tokens --from-file=tokens.json
helm install mcp deploy/helm/memcached-mcp \
  --set image.repository=<your registry>/memcached-mcp --set image.tag=<tag> \
  --set image.digest=sha256:<64-hex> \
  --set auth.existingSecret=mcp-tokens \
  --set "allowlist={memcached-0.memcached:11211,mcrouter:5000}" \
  --set "metrics.memcachedTargets={memcached-0.memcached:11211}"
```

Defaults: non-root, read-only root filesystem, no privilege escalation, all capabilities dropped,
`seccompProfile: RuntimeDefault`, no service-account token, requests (50m CPU, 32Mi) and a 256Mi
memory limit, startup/readiness/liveness probes against `/healthz`, a rolling update with
`maxUnavailable: 0`/`maxSurge: 1`, a 30 s termination grace period and a PDB when more than one
replica is in use. The chart also sets the process-wide upstream budget (64), the reservation
memory budget (96 MiB, `memoryBudgetMb`) and `/metrics` limits (4 concurrent, fan-out 16, 8 s
deadline, 5 s cache); see
[CONFIGURATION.md](CONFIGURATION.md#metrics-resource-and-freshness-semantics). The 256Mi container
limit is a starting point, not a measured guarantee: the reservation budget excludes JSON/HTTP
copies and allocator overhead, so verify peak RSS with your own targets and load before relying on
it.

Production settings to set explicitly:

- `image.digest` (or a registry with immutable tags) instead of a mutable tag.
- `imagePullSecrets` for a private registry.
- `auth.mode=file` with a projected `tokens.json` Secret; the chart mounts only that key,
  read-only, `defaultMode: 0440` with `fsGroup: 65532`. Shared-token mode puts the secret in the
  process environment and requires a pod restart to rotate.
- `networkPolicy.enabled=true` with explicit ingress peers. Egress isolation is opt-in:
  `networkPolicy.egress.enabled=true`, `networkPolicy.egress.rules` with the memcached/mcrouter
  destination selectors and ports, and the DNS selector for your cluster.
- `probes`, `resources`, `replicaCount`/`autoscaling` and `podDisruptionBudget` for the workload.
  HPA is off by default because in-memory MCP sessions are not shared; scale-down loses sessions.

See [OPERATIONS.md](OPERATIONS.md) for install, upgrade, rollback, token rotation, rollout restart and
incident checks.

### Rotating and revoking tokens

The token file is a mounted Secret and is re-read every 5 seconds. Update the Secret; Kubernetes
propagates it to the pod within about a minute (measured: 93 s on kind including the kubelet
sync), after which the old token returns 401. An empty `{"users":[]}` revokes everyone. A file that
does not parse is ignored and reported in the audit log, so a typo cannot lock everyone out (and
cannot silently keep a revoked user alive either: fix the file).

### Several replicas

Sessions, the per-user request limit, the per-user session cap and the token store are **per pod**:

- A client's session lives on the pod that created it. The chart sets `sessionAffinity: ClientIP`
  on the Service; without affinity a client that lands on another pod is told its session is
  unknown and must re-initialise.
- With N replicas a user can hold up to N times the per-pod limits.
- Token reload happens per pod, so a revocation takes effect on each pod when its mounted Secret
  updates.

One replica is enough for most uses; the server is light (see the benchmark in
[OPERATIONS.md](OPERATIONS.md#load-and-chaos-laboratory)).

## Monitoring

`GET /metrics` (same bearer token, `metrics` permission) exposes counters and gauges for the
configured memcached and mcrouter targets, `memcached_up`, mcrouter destination reachability and
the server's own cache/refresh/memory-budget counters and gauges. `tests/load-lab/prometheus/prometheus.yml`
and `tests/load-lab/grafana/` hold a working scrape configuration and a dashboard. Scrape with a
token from the Secret; never put the token in the Prometheus config in clear text—use a secret
reference or a file managed by your secret system.
