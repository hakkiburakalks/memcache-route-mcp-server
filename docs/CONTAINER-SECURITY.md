# Container security

This document covers the image, not the Helm chart. For installation, upgrade and rollback, see
[OPERATIONS.md](OPERATIONS.md).

## Image model

- Static musl binary in a **scratch** runtime image. There is no shell, package manager, libc
  loader, `curl` or `wget` in the final image.
- Runs as **UID:GID 65532:65532**. The Dockerfile sets `USER`; the chart repeats
  `runAsNonRoot`, `runAsUser`, `runAsGroup`, `fsGroup` and `seccompProfile: RuntimeDefault`.
- The chart sets `readOnlyRootFilesystem: true`, drops all capabilities and disables privilege
  escalation. The process does not need a writable root filesystem; audit lines go to stderr
  unless an explicit audit file is configured.
- No service-account token is mounted (`automountServiceAccountToken: false`).
- The final image contains `/memcached-mcp`, `/LICENSE` and OCI labels. Build arguments never
  include tokens or token files.

## Base image pinning

The builder is pinned by version **and** multi-arch manifest digest:

```
rust:1.95-alpine@sha256:606fd313a0f49743ee2a7bd49a0914bab7deedb12791f3a846a34a4711db7ed2
```

`Dockerfile` exposes this as `ARG RUST_IMAGE` so a reviewed upgrade can override it. Update the
version and digest together. To find the current multi-arch digest without starting a Docker
daemon:

```
curl -fsSL https://hub.docker.com/v2/repositories/library/rust/tags/1.95-alpine \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["digest"])'
```

or, with a working BuildKit client:

```
docker buildx imagetools inspect rust:1.95-alpine
```

The base digest narrows the build inputs, but `apk add musl-dev` resolves package versions from
the Alpine repositories at build time. This image is therefore **not guaranteed to be bit-for-bit
reproducible** across time. For stronger reproducibility, mirror the Alpine repository and pin
the `musl-dev` package version in the same change. The `# syntax=docker/dockerfile:1` frontend
directive is also a floating tag; pin it to a reviewed digest for an air-gapped or
high-assurance build.

## Build and inspect

```sh
# Local build: no push, no registry credentials needed.
docker build --pull \
  --build-arg VERSION=0.1.0-alpha.9 \
  --build-arg REVISION=$(git rev-parse HEAD) \
  --build-arg CREATED=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t memcached-mcp:local .

docker image inspect memcached-mcp:local \
  --format 'user={{.Config.User}} entrypoint={{.Config.Entrypoint}}'
```

The image intentionally has no `HEALTHCHECK`: scratch has no command to run one. Use the
orchestrator's HTTP probe against `GET /healthz` (the Helm chart does this).

## Secrets

- **Preferred:** `auth.mode=file`, a Kubernetes Secret holding `tokens.json` with hashed tokens.
  The chart projects only the selected key, mounts it read-only with `defaultMode: 0440`, and
  uses `fsGroup: 65532` so the non-root process can read it. The file is re-read every 5 seconds.
- **Shared token mode:** `auth.mode=token` puts `MEMCACHED_MCP_HTTP_TOKEN` in the container
  environment. It is not in the image or command line, but environment variables are visible to
  processes with access to the container/runtime. Prefer file mode for production.
- The server does not print tokens. It logs the user count, never token values; denied requests
  are audited with the peer address, not the `Authorization` header.
- Avoid `--build-arg` for secrets. Nothing in the Dockerfile accepts one.
- The audit log records key names and outcomes, never values. If `MEMCACHED_MCP_AUDIT_LOG` is set
  to a file, that file must be on an explicitly mounted writable volume; the chart leaves it unset
  so audit lines go to stderr for the platform log collector.

## Health and shutdown behavior

- `GET /healthz` is unauthenticated and exempt from the `Host` check. It returns `ok` once the
  process is serving. It is **process liveness/readiness, not upstream readiness**: a memcached
  target being down does not make `/healthz` fail. Per-target state is reported by
  `memcached_up{...}` on `/metrics`.
- Startup, readiness and liveness probes all use `/healthz`; the startup probe tolerates a slow
  image pull/start before liveness begins. Probe timing is configurable under `probes`.
- On SIGTERM/SIGINT the HTTP server stops accepting new connections and waits up to **10 seconds**
  for in-flight requests. The chart sets `terminationGracePeriodSeconds: 30`, leaving time for
  endpoint propagation and process exit.
- The scratch image has no shell, so a `preStop` command such as `sleep` is not available. During
  a rollout, clients with long-lived SSE streams can still lose the stream when the pod is
  removed; use a service mesh/ingress with retries or reconnect clients.
- Container `docker stop`/Kubernetes rollout sends SIGTERM to PID 1; the server handles it. Without
  that handler the runtime would eventually SIGKILL the process.

## Provenance, SBOM and scanning

These steps are deliberately **release-independent**: run them on a locally built image before
publishing anything. They do not push or deploy.

```sh
# BuildKit provenance + SBOM attestations (requires BuildKit/buildx).
docker buildx build --pull \
  --sbom=true --provenance=mode=max \
  --load -t memcached-mcp:scan .

# SPDX or CycloneDX SBOM (syft).
syft memcached-mcp:scan -o spdx-json=memcached-mcp.spdx.json

# Vulnerability scan (trivy): fail the gate on fixable HIGH/CRITICAL findings.
trivy image --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed \
  --exit-code 1 memcached-mcp:scan

# Signed provenance verification (cosign), once the image is signed by the release pipeline.
cosign verify-attestation --type slsaprovenance <registry>/memcached-mcp@sha256:<digest>
```

Minimum release gate, once the image is published:

1. Immutable digest recorded and referenced by the chart (`image.digest`).
2. SBOM attached to the image/release.
3. No unwaived fixable CRITICAL/HIGH vulnerabilities; document exceptions with owner and expiry.
4. Provenance verifies against the release workflow identity.
5. Image runs as non-root with read-only root FS and passes `/healthz` in a real cluster.

Local status on 2026-11-03: the current branding image `memcached-mcp:0.1.0-alpha.9`
(`sha256:c95473f8…`) was built from the pinned `rust:1.95-alpine` builder and verified as UID
65532 with a read-only root filesystem and healthy `/healthz`. Syft 1.56.0, Trivy 0.76.1 and
Cosign 3.1.4 were verified from official releases and used locally: **0 vulnerabilities**, **0
secrets**, and a Cosign blob signature verified with public transparency-log entries. No CI-backed
image signature, provenance attestation or publication exists yet; `syft`, `trivy` and `cosign`
were not installed system-wide.

`scripts/verify-image.sh <local-image>` performs the local portion when the tooling exists: it
checks that Docker is reachable **without starting it**, verifies UID/GID 65532, writes
`container-security/sbom.spdx.json` with syft and fails on fixable HIGH/CRITICAL findings with
trivy. It exits 2 (BLOCKED) rather than reporting a false pass when Docker, syft or trivy is
missing.

## Related files

- `Dockerfile`
- `.dockerignore`
- `deploy/helm/memcached-mcp/templates/deployment.yaml`
- `docs/OPERATIONS.md`
