# Release readiness

**Date:** 2026-11-03

**Status:** **NO-GO for release**. Local build, test, live protocol, failover, branding image
runtime and supply-chain verification evidence is present; CI/tag, published image provenance,
Helm runtime and release-publication gates are not.

**Production readiness:** **NOT VERIFIED**.

This is the consolidated record of the final QA, P1 live-integration, stabilization and
work-package reports. The project is safe for local and controlled staging validation; it is not
claimed to be production-ready.

## Branding

The project is now **MemCacheRoute MCP Server** — *“Understand your cache. Trace your routes.
Diagnose with confidence.”* — with the description “AI-powered diagnostics and troubleshooting for
Memcached and mcrouter.”

Branding was applied to the README and tagline, the MCP server identity
(`memcache-route-mcp-server`), Cargo package metadata, Docker/OCI labels, Helm chart description and
values schema title, workflow display names, release archive names, the Grafana dashboard title, and
security/contribution documentation.

The following identifiers were intentionally retained to avoid breaking existing integrations:
executable `memcached-mcp`, Rust package names and internal crates, `MEMCACHED_MCP_*` environment
variables, all MCP tool names, Helm chart name `memcached-mcp`, Helm directory, image repository and
binary filesystem path. Version remains `0.1.0-alpha.9`.

The GitHub repository was renamed to `hakkiburakalks/memcache-route-mcp-server`; the old slug
redirects, and the local `origin` plus clone/source-label documentation now use the new HTTPS URL.
The internal compatibility identifiers listed above are unchanged.

### Branding files changed

- `README.md` — title, tagline, description, compatibility note.
- `crates/mcp-server/Cargo.toml` — package description.
- `crates/mcp-server/src/main.rs` — MCP server identity.
- `scripts/smoke.sh` — identity assertion.
- `Dockerfile` — OCI title/description/build label and `/LICENSE` copy.
- `deploy/helm/memcached-mcp/Chart.yaml` and `values.schema.json` — descriptions/title.
- `.github/workflows/ci.yml` and `release.yml` — workflow display names and archive prefix.
- `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md` — brand text.
- `tests/load-lab/grafana/dashboards/memcached-mcp.json` — dashboard title.
- `docs/RELEASE-READINESS.md` — this record.
- Release archives also include `LICENSE` (cleanup follow-up).

## Verification summary

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS |
| `cargo test --workspace --no-fail-fast` | **287 passed, 0 failed, 0 ignored** |
| `cargo audit` | PASS — 1402 advisories, 127 dependencies |
| `python -I scripts/check-licenses.py` | PASS — 122 dependency licences accepted |
| `cargo build --release --locked -p mcp-server` | PASS |
| Release binary smoke test | PASS — `smoke ok` with the new MCP identity |
| Helm `lint --strict` / valid render | PASS |
| Helm PDB/HPA/NetworkPolicy render | PASS (static) |
| `docker compose -f tests/compat/docker-compose.yml config --quiet` | PASS |
| Markdown links/anchors | PASS — all Markdown links and anchors resolve |
| Version consistency | PASS — `0.1.0-alpha.9` in workspace, `Cargo.lock`, Chart version/appVersion and changelog |
| Local history consolidation | PASS — private `main` contains the five planned commits plus one CI correction; no tag |
| `git diff --check` (worktree and `origin/main..HEAD`) | PASS |
| Current branding image build/runtime | PASS — `memcached-mcp:0.1.0-alpha.9`, read-only rootfs, healthy `/healthz` |
| Source/dependency SBOM | PASS — 137 SPDX packages / 139 CycloneDX components |
| Image SBOM | PASS — scratch image (1 filesystem package; dependencies covered by source SBOM) |
| Trivy image/source vulnerability scan | PASS — 0 vulnerabilities |
| Trivy secret scans | PASS — 0 secrets in image/source |
| Cosign evidence signature | PASS — ephemeral-key blob signature verified; public Rekor entries disclosed below |

The 287-test harness includes 15 live tests that self-skip without lab variables; about **272
tests execute assertions locally**. The live matrix was executed separately.

The current branding image was rebuilt from the pinned
`rust:1.95-alpine@sha256:606fd313…` builder on 2026-11-03 (build exit 0). See
[Container and Helm validation](#container-and-helm-validation) and
[Security and supply-chain evidence](#security-and-supply-chain-evidence) for digests, SBOMs,
scans and signing evidence.

## Live compatibility and failover evidence

Isolated Docker lab, project-specific network, exact pinned images:

| Area | Evidence | Result |
|---|---|---|
| memcached 1.4.39 | core live 3/3; MCP e2e 47/47; `meta: false` | PASS |
| memcached 1.5.22 | core live 3/3; MCP e2e 47/47; `meta: false` | PASS |
| memcached 1.6.45 | core live 3/3; MCP e2e 47/47; `meta: true` | PASS |
| Eviction (4 MB server) | 1/1; critical eviction finding observed | PASS |
| mcrouter 34.0.0 live | 1/1 | PASS |
| mcrouter-enabled MCP e2e | 47/47, 0 env-skips | PASS |
| Failover integration test | **5/5 consecutive runs** with `mc-a` stopped | PASS |
| Hard failure | plain pool fails loudly; failover stores on `mc-b` | PASS |
| MCP diagnosis | `down_without_failover` / `failover_active` | PASS |

The failover test was fixed without weakening the client: `Client::store` still retires a
connection after a `SERVER_ERROR`; the test now reconnects before follow-up reads.

## Live MCP and image evidence

- 14 of the 18 pre-existing read tools were invoked against real services; all returned
  `isError: false` and the declared `schema_version: "1.0"` where applicable. The expanded alpha
  tools were exercised in the live campaign below, including real mcrouter/failover/proxy states;
  the proxy adapter was retested after its blocker fix.
- New diagnostics were exercised against 1.4.39, 1.5.22 and 1.6.45 with correct meta detection.
- Auth: missing/wrong token → 401; read-only tokens see no write tools; expiry, per-user limits and
  token reload pass.
- Live deadline: a paused node returned `timed out` in 6086 ms; recovery after unpause worked.
- Session, request, body and concurrency limits pass; memory-budget harness passes.
- Live MCP tool evidence was collected on the pre-branding image; branding changed only the
  `serverInfo.name` and metadata. Tool names, arguments, schemas, auth and transport behavior were
  not changed.
- Rebuilt branding image `memcached-mcp:0.1.0-alpha.9` (image ID `sha256:c95473f8…`, 2,781,780
  bytes, amd64) runs as UID/GID 65532, has no shell, contains `/memcached-mcp` and `/LICENSE`,
  runs with a read-only root filesystem and returns `ok` from `/healthz`.

## Hardening and features already implemented

- **WP-01 / WP-02 / R1:** per-command and process-wide memory budgets, connection retirement,
  token revocation/session cleanup, DNS fallback and connect budgets, bounded `/metrics` fan-out,
  overall scrape deadline, singleflight TTL cache and internal budget/freshness metrics.
- **WP-03:** scratch/non-root image, digest-pinned builder, OCI metadata, Helm schema, digest
  rendering, Secret projection, probes, PDB/HPA, NetworkPolicy ingress/egress and runbook.
- **WP-04 / stabilization:** whole-call tool deadlines, POST slow-drip deadline, strict protocol
  parsing, mcrouter config/route/JSON bounds, non-blocking bounded audit writer, per-identity audit
  throttling, DNS/connect budget sharing and sampling limits.
- **WP-06A–F:** deterministic RCA, incident snapshots and diffs, cluster topology/health, cache
  efficiency advice, safe remediation advice and historical anomaly detection. All are read-only,
  schema-versioned (`1.0`), bounded and free of automatic remediation.
- Prometheus remains optional; no external AI service, database, background collector or automatic
  remediation is required.

## Alpha.9 expanded intelligence

Added in this pass, reusing existing collectors and snapshot/RCA engines:

- `plan_cache_capacity` — capacity/workload facts, connection saturation and observed snapshot
  deltas; no forecast or time-to-exhaustion.
- `analyze_slab_fragmentation` — per-class chunk/page efficiency, eviction/OOM, segmented-LRU
  settings and extstore fields with explicit uncertainty.
- `analyze_incident_timeline` — chronological intervals composed from snapshot diff and history.
- `analyze_mcrouter_routing` — known route-handle inventory, structural risks, config impact and
  explicit unsupported/UNKNOWN coverage; no offline routing simulation.
- `analyze_mcrouter_tko` — soft/hard TKO evidence, destination health, failover/queue counters and
  missing telemetry.
- `compare_cache_clusters` — read-only comparison of supplied Memcached/mcrouter cluster snapshots.
- `advise_cache_migration` — routing/capacity/version/warmup/rollback advice; no data movement or
  exact key simulation.
- `analyze_memcached_proxy` — read-only proxy stats adapter for Memcached 1.6.23+; no Lua/config
  execution.
- Meta `X` stale flag exposed by `get_key_metadata`.

The maintained coverage matrix is in
[COMPATIBILITY.md](../COMPATIBILITY.md#feature-and-version-coverage-matrix). The live campaign
below covers capacity, slabs, timeline, routing, cluster comparison, migration, TKO and the corrected
proxy adapter; exact routing simulation remains unsupported and is not claimed as complete.

## MCP integration (resources, prompts, structured output)

Added on top of the existing stdio/Streamable HTTP transport and session handling; tool names,
arguments, authorization, allowlists, deadlines, budgets, audit behavior and existing text results
are unchanged.

- **Resources:** four bounded, read-only, stable URIs — `memcache-route://capabilities`,
  `memcache-route://tools`, `memcache-route://operator-guide` and `memcache-route://targets`.
  URIs over 2048 bytes and content over 64 KiB are rejected. `targets` lists at most 256 allowlisted
  addresses, requires the `read` permission and audits denials; it never exposes tokens, key values
  or credentials. No discovery or background collection is added.
- **Prompts:** six static investigation prompts (`investigate-memory-pressure`,
  `diagnose-mcrouter-routing`, `investigate-hit-ratio`, `compare-cache-clusters`,
  `review-cache-migration`, `investigate-failover-tko`). Retrieving one executes no tool and makes
  no upstream connection. Client-supplied prompt arguments are ignored and never interpolated into
  the instructions.
- **Structured output:** `server_info` advertises an `outputSchema` (`version` string,
  `meta_commands` boolean) and returns matching `structuredContent` while preserving its legacy
  `version:`/`meta_commands:` text. Other tools keep their existing text/JSON output and advertise
  no unvalidated output schema. Uncertainty and partial-evidence fields are unchanged.
- **Protocol:** `initialize` advertises `tools`, `prompts` and `resources`; resources/list,
  resources/read, prompts/list, prompts/get, tools/list and tools/call are exercised through the
  real binary over stdio and HTTP. Sessions, bearer authentication, per-user permissions and
  `/metrics` behavior are unchanged.
- **Focused tests:** capability negotiation, resources list/read, prompts list/get, structured
  content versus its advertised schema, unauthorized `targets` access with audit evidence,
  malformed/wrong-scheme/oversized URIs, ignored injection-like prompt arguments, legacy
  2024-11-05 initialization and retained text output.
- **Not implemented/claimed:** sampling, elicitation, tasks, resource subscriptions or
  `list_changed` notifications, pagination, 2026-07-28 extensions, third-party-client
  interoperability testing and live external client validation.

## Expanded alpha live campaign (2026-11-03)

Reused the isolated compose lab: memcached 1.4.39 (11214), 1.5.22 (11215), 1.6.45 (11216),
4 MB 1.6.45 (11217), mcrouter 34.0.0 plain pool (11218) and failover route (11222). The proxy
phase used a separate official `memcached:1.6.45` container (11223) built with proxy support and
started with the built-in route library plus a minimal server-owned Lua file; no client-supplied Lua
was executed. The full MCP e2e suite ran **47/47 on each Memcached version with no skips**.

| Test | Exact result | Status |
| --- | --- | --- |
| Capacity healthy / pressure / insufficient / deltas | 1.4.39 `healthy`; 1.6.45 at 82.0% `actionable` (memory, target and low hit ratio); 1.5.22 83 gets `watch`; 3-snapshot history +5.1 pp | **PASS** |
| Capacity malformed / unavailable | target 2.0 rejected; closed allowlisted 11224 connection error | **PASS** |
| Slab fragmentation | 1.6.45 class 2 internal waste; 4 MB node class 29 evicted 61 items plus free-chunk opportunities; malformed/unavailable rejected | **PASS** |
| Incident timeline/history | 2 intervals, 22 events, 4 anomalies (eviction 1.422/s vs 0 baseline); one snapshot `insufficient_evidence`; malformed rejected | **PASS** |
| Cluster comparison | Two explicit clusters: 5 findings, +37.0 pp memory, +0.442 evictions/s, −1 destination, 4 history anomalies; one/empty cluster rejected | **PASS** |
| Migration advisor | Live plain router → proposed failover: 6 structural changes, 2 capacity findings, cold-cache expected; malformed/missing/unavailable rejected | **PASS** |
| Routing analysis | PoolRoute 3 destinations; FailoverRoute depth 2; proposed impact pools +2/−1, destinations −1; malformed/unavailable rejected | **PASS** |
| TKO healthy/down/recovery | Healthy 0 down/0 suspect; with mc-a stopped: down=1 suspect=1, critical no-failover finding, failover inferred, 35/40 failover probes completed (5 timed out/errored); after restart both routers healthy (3/3 and 2/2 up) | **PASS (state evidence only)** |
| MCP resources/prompts/structured | 4 resources, 6 prompts, `server_info` structured + legacy text; independent SDK and e2e | **PASS** |
| Independent MCP client | Python MCP SDK 2.3.0 over Streamable HTTP and stdio: legacy negotiated 2025-11-25, auto negotiated 2026-07-28, 27 tools, unknown tool/resource rejected, bad token 401 | **PASS** |
| Client session close | DELETE returns 202; SDK logs `Session termination failed: 202` but session ends | **PARTIAL** |
| Reverse proxy | Reference nginx: MCP works; 4 KiB body 413, 4 KiB header 400, idle close 2.0 s, held connection 503, rapid requests 429 | **PASS (lab)** |
| Peak memory | Current-tree image, 256 MiB limit, 8 sessions/30 s: 47,388 calls, 0 errors, sampled peak 9.04 MiB, median 8.22 MiB, no OOM, `/healthz` 200 | **PASS (sampled, not cgroup peak)** |
| Helm runtime | kind v1.37.0, chart installed with in-cluster memcached 1.6.45: Ready, non-root 65532, read-only rootfs, fsGroup 65532, token auth and tools/resources work | **PASS (local kind)** |
| Proxy-enabled server detection | Official 1.6.45 proxy build: `observed`, `enabled: true`, `statistics_available: true` | **PASS** |
| Proxy stats parsing | Raw `stats proxy` = 25 `STAT` fields (26 lines including `END`), `stats proxyfuncs` = 4 fields (5 lines); tool returned the same populated 25/4 fields | **PASS** |
| Proxy-disabled 1.6.45 | `proxy_enabled=no`: `status: disabled`, `enabled: false`, `detected: false`, empty stats | **PASS** |
| Proxy older versions / safety / deadline | 1.5.22 and 1.4.39 `not_applicable`; extra Lua-like arguments ignored; 500 ms deadline returned in 0.52 s; closed upstream and malformed target rejected | **PASS** |

### Proxy blocker correction (2026-11-03)

- Added fixed `Client::stats_proxy` and `Client::stats_proxyfuncs` commands. `get_stats` and
  `encode_stats` still reject `proxy`, `proxyfuncs` and every other unlisted group before the wire.
- `proxy_enabled` now follows documented `yes`/`no` semantics. Missing or malformed values produce
  `insufficient_evidence`, not inferred enablement.
- Added explicit `disabled` and `statistics_unavailable` statuses plus `enabled`,
  `statistics_available` and bounded `statistics_error` fields; command failures are retained.
- Live retest on the official 1.6.45 proxy build: `observed`, 25 `stats proxy` fields and 4
  `stats proxyfuncs` fields, matching the raw replies. Disabled 1.6.45: `disabled`. 1.5.22/1.4.39:
  `not_applicable`. Closed upstream and malformed target: rejected.
- New coverage: 10 proxy analyzer tests; fixed-command/error/oversize tests; deadline and
  cancelled-memory-budget tests; enabled/disabled/unavailable/missing/malformed/hostile e2e cases;
  allowlist and HTTP authorization checks. Full suite: **287 passed, 0 failed, 0 ignored**.

Risks from this campaign: the TKO test observed a down/suspect state and recovery but did not measure
transition durations; capacity/slab/cluster/migration/timeline results use a synthetic lab workload,
not production traffic; peak RSS was sampled with `docker stats`, not read from a cgroup high-water
counter; the nginx result is a reference configuration, not the production ingress; the kind result
does not cover production ingress, NetworkPolicy enforcement, HA/PDB behavior or token rotation; and
the proxy correction was verified in the same synthetic lab, while dynamic proxy routing behavior
remains UNKNOWN and unexecuted.

## Security and supply-chain evidence

### Tool provenance and versions

Downloaded the official Windows amd64 assets from GitHub releases and verified both the release
attestations and published SHA-256 checksums before execution. No system-wide installation or
PATH/credential change was made.

| Tool | Version | Verified source | Asset SHA-256 | Release attestation |
|---|---|---|---|---|
| Syft | 1.56.0 | `anchore/syft` v1.56.0 | `c4cd2846…98661d` | `gh release verify` PASS |
| Trivy | 0.76.1 | `aquasecurity/trivy` v0.76.1 | `1051f49c…2dc9bf` | `gh release verify` PASS |
| Cosign | 3.1.4 | `sigstore/cosign` v3.1.4 | `cbe95378…c1f2a` | `gh release verify` PASS |

The pinned builder `rust:1.95-alpine@sha256:606fd313…db7ed2` was pulled and its digest/architecture
(`amd64`, `linux`) matched the Dockerfile.

### Image build and SBOMs

- Built `memcached-mcp:0.1.0-alpha.9` from the current tree with
  `VERSION=0.1.0-alpha.9`, revision `6441054…`, and `CREATED=2026-11-03T03:06:57Z`; build exit 0.
- Image ID `sha256:c95473f897d515635d1a0bf2e1566ff3f445016775122e65aa91c9bb9583bf48`, size
  2,781,780 bytes, `amd64`/`linux`, user `65532:65532`.
- Labels verified: title `MemCacheRoute MCP Server`, description, version `0.1.0-alpha.9`, revision,
  licence `Apache-2.0`, source URL and pinned builder digest.
- Root filesystem contains only `/memcached-mcp`, `/LICENSE` and runtime pseudo-files; no shell or
  package manager. `/LICENSE` matches the repository license byte-for-byte.
- Source/dependency SBOM (Syft): **137 SPDX packages**, **139 CycloneDX components**, including the
  application crates and third-party dependencies.
- Image SBOM (Syft): **1 filesystem package** because the runtime is `scratch` and the binary is
  stripped; dependency coverage is provided by the source/dependency SBOM.
- Evidence directory: `C:\Users\burak\AppData\Local\Temp\memcache-route-supplychain\sbom`.
  `SHA256SUMS` covers the SBOMs, scan results, metadata and tool versions.

### Vulnerability, secret and config scans

All scans ran without `--ignore-unfixed`, severity suppression or automatic remediation.

| Scan | Result |
|---|---|
| `trivy image` (vulnerabilities) | **0 vulnerabilities** |
| `trivy fs` (source/Cargo.lock vulnerabilities) | **0 vulnerabilities** |
| `trivy fs --scanners secret` | **0 secrets** |
| `trivy image --scanners secret` | **0 secrets** |
| `cargo audit` | 0 vulnerabilities; 127 dependencies |
| `trivy config` | 1 LOW in `Dockerfile` (no HEALTHCHECK; intentional for scratch), 1 HIGH + 1 LOW in `tests/load-lab/chaos/Dockerfile` (root user and no HEALTHCHECK; test-only fixture) |

`trivy config` skipped the Helm chart because required values were not supplied; Helm was validated
separately with explicit values. The chaos Dockerfile is a throwaway test helper that shares one lab
container's network namespace; it is not part of the release image.

### Local signing evidence

- Generated an ephemeral local key pair in the temporary evidence directory; no existing key or
  credential was overwritten.
- Signed `SHA256SUMS` with Cosign and verified the bundle:
  `cosign verify-blob --key … --bundle …` → **Verified OK**.
- Final public-key SHA-256 fingerprint:
  `8593D81CA953F16B661BA7383CE43CE0FF31097F13BDDA057BB6A84ABE891EEB`.
- Private keys were removed after verification; public keys and `.sigstore.json` bundles remain in
  the temporary evidence directory.
- This is **not an image signature and not CI provenance**; the image was not signed or published.

**Public transparency-log deviation:** Cosign's default transparency logging created three
`hashedrekord` Rekor entries for the local blob-signature attempts (log indexes **3657074412**,
**3657085188**, **3657100932**). They sign only local evidence files (`source.spdx.json`,
`SHA256SUMS`), not the container image, and contain no credentials or private key material. Rekor
entries are immutable. If the release policy requires that no signature material be publicly
logged before publication, this is an unresolved process deviation that must be reviewed.

### Rekor metadata review (read-only)

Read-only inspection of `https://rekor.sigstore.dev/api/v1/log/entries?logIndex=<index>` confirmed:

| Log index | Kind | Artifact hash | Public key SHA-256 | Identity/cert | Inclusion proof |
|---|---|---|---|---|---|
| 3657074412 | `hashedrekord@0.0.1` | `109d1d4d…e47b9` — `source.spdx.json` | `95C17FE7…A9F446B` | none | present |
| 3657085188 | `hashedrekord@0.0.1` | `e7b15f94…b737e3` — earlier `SHA256SUMS` (superseded) | `B9549BF3…6C794F` | none | present |
| 3657100932 | `hashedrekord@0.0.1` | `03fc56f3…c5472` — current `SHA256SUMS` | `6450A6B9…DBB7800` | none | present |

The bodies contain only `apiVersion`, `kind`, `spec.data.hash`, `spec.signature.content` and
`spec.signature.publicKey.content`. There is **no certificate, email, OIDC issuer, subject, filename,
path, signature content beyond the public signature, or embedded artifact content**. Each entry has
a `signedEntryTimestamp` and inclusion proof. The public keys and signatures are public by design;
no private key or credential is present.

**Preventive control for future pre-release local signing:** use an offline/transparency-disabled
signing configuration (or a Cosign version/flag that does not upload to Rekor), and assert the
produced bundle has zero `verificationMaterial.tlogEntries` before treating it as local-only.
Require explicit approval before signing any pre-release evidence on a network-connected machine.
For release artifacts, use the approved CI keyless identity and sign only after the publication
decision. This control must be part of the release checklist.

### Reproducible build/scan commands

```sh
docker pull rust:1.95-alpine@sha256:606fd313a0f49743ee2a7bd49a0914bab7deedb12791f3a846a34a4711db7ed2
docker build --build-arg VERSION=0.1.0-alpha.9 \
  --build-arg REVISION=$(git rev-parse HEAD) \
  --build-arg CREATED=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  -t memcached-mcp:0.1.0-alpha.9 .

syft dir:. --exclude './target/**' --exclude './.git/**' \
  -o spdx-json=source.spdx.json -o cyclonedx-json=source.cdx.json
syft memcached-mcp:0.1.0-alpha.9 -o spdx-json=image.spdx.json

trivy image --scanners vuln --timeout 15m memcached-mcp:0.1.0-alpha.9
trivy fs --scanners vuln --skip-dirs target --skip-dirs .git .
trivy fs --scanners secret --skip-dirs target --skip-dirs .git .
trivy image --scanners secret memcached-mcp:0.1.0-alpha.9
trivy config .

cosign sign-blob --key local.key --bundle evidence.sigstore.json --yes SHA256SUMS
cosign verify-blob --key local.pub --bundle evidence.sigstore.json SHA256SUMS
```

## Container and Helm validation

- Dockerfile remains `scratch`, non-root (`65532:65532`), no shell/package manager, with OCI
  title/description/version/revision/licence labels updated. `/LICENSE` was added for attribution.
- The rebuilt image ran with `--read-only`, `--cap-drop ALL` and `no-new-privileges`; it stayed
  running, reported user `65532:65532`, and returned `ok` from `/healthz`.
- Helm `lint --strict` passes; valid render shows `runAsNonRoot`, `fsGroup: 65532`,
  `readOnlyRootFilesystem`, `drop: ["ALL"]`, probes and the alpha.9 version label.
- With two replicas plus HPA, a PDB (`minAvailable: 1`) and HPA (`minReplicas: 2`, `maxReplicas: 5`)
  render. NetworkPolicy renders with an explicit peer and fails closed with an empty peer list.
- Default render fails closed without allowlist/credentials.
- Live CNI/NetworkPolicy enforcement, Secret projection timing, PDB/HPA behavior, rollout/rollback
  and token rotation remain **NOT VERIFIED** without an isolated cluster.
- Reverse-proxy header-read, idle-timeout and connection controls remain delegated and unverified.

## Git history and backup coverage

**Previous backup:** `C:\Users\burak\AppData\Local\Temp\memcached-mcp-backup-20261103-054321.tgz`
(259,994 bytes, 126 entries / 91 files, SHA-256 `6C84A0B7…752BD`) covers the working-tree files at
that time, but it **excludes `.git`, `target`, `.claude-flow` and `.swarm`**. It predates the branding
and supply-chain changes, so it does **not** cover the current tree or any Git commits/history.

**Current consolidated baseline backup (covers `9b05ad0`):**

- `history-consolidated-20261103-063006.bundle`, SHA-256
  `CE85A1852E0EEB4B34B570FC217F445C8DE7E7DF4919456F4B08D76487615E12`;
  `git bundle verify` reports complete history for `9b05ad0` (`main`/`HEAD`), `origin/main`
  (`ef65d55`) and tags `v0.1.0-alpha.1` through `v0.1.0-alpha.8`.
- `tree-consolidated-20261103-063006.tgz`, SHA-256
  `52AB7D8421CA8837C31C6DAF76B1740F24B9155AD78C4A8CECF948FECD869B61`.
- This baseline does **not** cover the five new local alpha.9 commits.

**Fresh pre-commit backup (2026-11-03 08:39:49, before the local commits):**

- Tree: `C:\Users\burak\AppData\Local\Temp\memcache-route-supplychain\precommit-20261103-083949\tree.tgz`,
  SHA-256 `5628920C69F06A33D16B4D088C577102D4F136AFCE627D8EEA596DD02C148506`.
  Verified **98 files**, with every included worktree file byte-identical to disk, including the
  eight untracked analyzer modules. Excludes `.git` contents, `target`, `.claude-flow`, `.claude`
  and `.swarm`.
- History: `C:\Users\burak\AppData\Local\Temp\memcache-route-supplychain\precommit-20261103-083949\history.bundle`,
  SHA-256 `30813B2C38711F89753F7483BAA94D9A9FEF9B527BABDEF541A67C4B2A2B408A`;
  `git bundle verify` reports complete history for `9b05ad0` (`main`/`HEAD`), `origin/main` and all
  tags.
- The older `tree-20261103-062017.tgz` / `history-20261103-062017.bundle` pair predates `9b05ad0`
  and is retained only as historical evidence.
- A fresh tree/history pair must still be created after the final commit because this pre-commit
  backup captures the worktree, not the resulting commit IDs.

### Consolidation result

Local history consolidation completed on `main`; published history was not rewritten.

| Commit | Subject | Scope |
|---|---|---|
| `0f9ffbf` | Harden runtime security, reliability and diagnostics | Rust crates, Cargo metadata/lock, tests |
| `2d78eb1` | MemCacheRoute branding and consolidated documentation | README, changelog, security/contribution docs, `docs/` |
| `HEAD` | Release hygiene, packaging and verification | Dockerfile, Helm, workflows, scripts, fixtures, ignore rules, cleanup record, `.serena` removal |

- `origin/main` advanced from `ef65d55` through the private fast-forward pushes described below.
- The tree was clean immediately after consolidation. The alpha.9 feature pass was committed in
  five planned commits plus one CI correction and pushed to the private `main` branch; no tag was created.
- No generated `.pyc`, benchmark output, `.serena` state, SBOM, signing key or temporary evidence is
  present in the commit tree.
- Tags remain `v0.1.0-alpha.1`–`v0.1.0-alpha.8`; no alpha.9 tag was created.

### Tree comparison and recovery

- Pre-consolidation tree archive: 91 files, 126 entries, SHA-256
  `8D045B81229BA6012A7CE7F86612B038822CEADB51656A097364EB45BC4427F1`.
- Final tree after consolidation: 91 files. All source and test files were byte-identical to the
  archive; only `LICENSE`, `REPOSITORY-CLEANUP-REPORT.md` and this document differed due final
  whitespace/metadata updates. The subsequent alpha.9 feature pass adds eight pure analyzer modules
  and documentation updates on top of that consolidated tree.
- Full pre-consolidation history: `history-final-20261103-062507.bundle`, SHA-256
  `DF4C78CD4D44C2CFDB75F7B16699FC70D57AF1FD3FED918CF84674D46F295082`; `git bundle verify`
  reports a complete history containing `6441054`, `origin/main` (`ef65d55`) and all tags.
- Recovery path: clone the verified bundle into a fresh directory or use the live `git reflog` to
  return to the pre-consolidation state. No hard reset or destructive recovery is required.

The GitHub repository rename to `memcache-route-mcp-server` is complete; the clone URL, OCI source
label, remote and documentation references use the new name.

### Release content review

- Current tree contains **40 Rust source/test files** (including 10 integration-test files), **16
  Markdown documents**, Helm chart/templates, workflows, scripts and fixtures.
- Compared with `origin/main`: 87 tracked paths differ plus 8 untracked analyzer modules (including
  the 3 local commits); the only tracked deletions are `.serena/` (agent state); Python cache and
  benchmark output are removed from the tree.
- Intended source is present: protocol/client/memory, diagnostics/RCA/snapshots/efficiency/
  remediation/history/capacity/slabs/timeline/cluster comparison, mcrouter cluster/failover/routing/
  TKO/migration, MCP auth/audit/HTTP/tools/resources/prompts/metrics and the corrected proxy adapter.
- Intended tests are present: unit, hostile, e2e, security, metrics, deadlines, memory budget,
  eviction, live, failover and proxy stats views.
- Intended documentation, Helm hardening, release workflows/scripts, LICENSE and SECURITY are present.
- Version is consistently `0.1.0-alpha.9`; no source/test files were removed.

### Chaos Dockerfile HIGH finding

Trivy reports `DS-0002` (HIGH, image runs as root) and `DS-0026` (LOW, no HEALTHCHECK) for
`tests/load-lab/chaos/Dockerfile`.

This image is a throwaway helper built on demand by `tests/load-lab/chaos.sh`. It is run with
`--rm`, `--cap-add NET_ADMIN` and `--network container:<one lab container>` solely to apply
`tc`/`iptables` inside that container's network namespace; it never touches the host network, is not
part of the release image, is not built by CI and is not deployed. Root is required for the
`tc`/`iptables` operations in this helper, so the HIGH finding is **appropriately isolated** and
does not require a release-image correction. It remains visible and unsuppressed; if the test lab is
ever promoted beyond disposable local tooling, run it with a dedicated non-root capability set
(`NET_ADMIN` plus file capabilities) and add a process health check.

## Final publication preparation (2026-11-03)

### Working-tree audit since `9b05ad0`

- **Five planned commits plus one CI correction** contain the 16 previously modified tracked files
  and 8 new analyzer modules. The working tree is clean. No tracked file is deleted
  by the expanded-alpha pass; the only historical deletions versus `origin/main` are `.serena/`
  agent state. `Cargo.toml` and `Cargo.lock` are unchanged since `9b05ad0`, so no new dependency was
  introduced.
- Included: capacity, slab, timeline and cluster comparison; mcrouter routing, TKO and migration;
  MCP resources, prompts and `server_info` structured output; the fixed proxy adapter; and their
  tests and documentation.
- No generated logs, benchmark output, SBOM, signing key, token file, `.env`, certificate or
  temporary artifact is tracked or untracked in the worktree. Ignored entries are only `target/`,
  `.claude-flow/`, `.claude/` and `.swarm/`.
- Current tree: **40 Rust source/test files** (32 tracked + 8 new) and **16 Markdown documents**.
- Version is consistently `0.1.0-alpha.9` in workspace/crates, `Cargo.lock`, chart version/appVersion,
  changelog and README. The newest tag remains `v0.1.0-alpha.8`; no alpha.9 tag exists.
- The compatibility matrix was reviewed: the proxy row is now `SUPPORTED (live)`; no `FAIL` status
  remains. Partial/unsupported entries (extstore, exact routing simulation, dynamic proxy/Lua
  behavior and non-live production coverage) still match their evidence and are not claimed complete.
- Full local suite: **287 passed, 0 failed, 0 ignored**; live e2e **47/47** on 1.4.39, 1.5.22 and
  1.6.45. Proxy live retest: 25 `stats proxy` fields and 4 `stats proxyfuncs` fields, disabled and
  older-server states correct.
- The pre-consolidation bundle `history-20261103-062017.bundle` predates `9b05ad0`; it does not cover
  the three local commits or this worktree. A fresh tree archive and history bundle are required
  after the final commit.

### Public Rekor metadata confirmation

Read-only `https://rekor.sigstore.dev/api/v1/log/entries?logIndex=<index>` checks of **3657074412**,
**3657085188** and **3657100932** confirm each body contains only `apiVersion`, `kind`,
`spec.data.hash`, `spec.signature.content` and `spec.signature.publicKey.content`. No certificate,
email, OIDC issuer, subject, filename, path or artifact content is present. The three immutable
`hashedrekord` entries and the documented public transparency-log deviation remain intact. Policy
acceptance is still required before publication.

### Executed commits and private CI

The five planned commits plus one CI correction are on private `main`; the worktree is clean:

1. `57a860d` `feat(diagnostics): add expanded analyzers and proxy stats support` — capacity, slab,
   timeline and cluster analyzers, the fixed proxy adapter and client stats views, and regression
   tests. This combines the planned diagnostics and proxy groups because `diagnostics/src/lib.rs`
   is shared by both.
2. `9b815bf` `feat(mcrouter): add routing, TKO and migration intelligence` — routing/config impact,
   TKO evidence and migration advice.
3. `9c1cbf1` `feat(mcp): expose expanded diagnostics, resources and prompts` — tool wiring, bounded
   resources, static prompts, structured output and e2e coverage.
4. `7133bbc` `docs: update expanded-alpha compatibility and operator guidance` — compatibility,
   tools, diagnostics, architecture, README and changelog.
5. `7d9620e` `docs: finalize alpha.9 release readiness and publication plan` — audit, backups,
   Rekor confirmation, rename/CI checklist, staging gates and release sequence.
6. `34beb5c` `fix(diagnostics): satisfy stable clippy some_filter lint` — CI correction using
   `bool::then_some`; behavior unchanged.

The proxy correction is in commit 1 rather than a standalone commit so that no partial staging of
the shared diagnostics module or `main.rs`/`e2e.rs` is required.

Private fast-forward pushes:

- `ef65d55..7d9620e` (`main`)
- `7d9620e..34beb5c` (`main`), correction only
- `34beb5c..9a9427b` (`main`), release-readiness evidence

No force push, tag, release or image/Helm publication was performed. The GitHub repository rename
was completed afterwards; the old URL redirects and local `origin` now uses
`https://github.com/hakkiburakalks/memcache-route-mcp-server.git` (SSH is not configured locally).

CI evidence:

- Run **41586262241** on `7d9620e`
  <https://github.com/hakkiburakalks/memcache-route-mcp-server/actions/runs/41586262241>
  **failed** in `build (ubuntu-latest)` and `build (macos-latest)` at
  `cargo clippy --all-targets -- -D warnings`: `clippy::some_filter` in
  `crates/diagnostics/src/snapshot.rs:962`. All other eight jobs passed.
- Correction `34beb5c` was pushed normally. Run **41587022980**
  <https://github.com/hakkiburakalks/memcache-route-mcp-server/actions/runs/41587022980>
  **passed all 10 jobs**: build (Linux/macOS), mcrouter, Helm, memcached 1.4.39/1.5.22/1.6.45,
  image build/smoke, audit and licences.
- Run **41587731807** on the docs-only evidence commit `9a9427b`
  <https://github.com/hakkiburakalks/memcache-route-mcp-server/actions/runs/41587731807>
  **passed all 10 jobs** as well.
- The final rename/documentation update is a docs-only follow-up after `9a9427b` and is validated
  separately.

### Completed repository rename

Completed on 2026-11-03:

- GitHub repository is now **`hakkiburakalks/memcache-route-mcp-server`**, private, default branch
  `main`; the old slug redirects.
- Local `origin` was updated to
  `https://github.com/hakkiburakalks/memcache-route-mcp-server.git`. SSH is not configured locally
  (`Permission denied (publickey)`), so HTTPS with the existing GitHub credential is retained.
- `CONTRIBUTING.md` clone URL/`cd` path and the `Dockerfile` OCI source label were updated, along
  with this record. README and Cargo metadata contain no hardcoded clone URL.
- Workflows use `${{ github.repository }}`/`${{ github.ref_name }}` dynamically; the archive prefix
  is already `memcache-route-mcp-*`.
- Internal compatibility identifiers remain unchanged: executable `memcached-mcp`, crate names,
  `MEMCACHED_MCP_*`, MCP tool names, Helm chart name `memcached-mcp` and image repository.
- Tag, release, image publication and post-commit backup remain pending.

### CI and release prerequisites

- CI currently runs fmt/clippy/tests/build/smoke, the three Memcached versions, mcrouter/failover,
  image build smoke, Helm render, audit and licence checks. It does **not** start a proxy-enabled
  Memcached or run the live proxy stats check; add that job before publication if live CI evidence
  is required by the release policy.
- Add/confirm a Windows test job; the release workflow builds Windows but CI tests only Ubuntu and
  macOS.
- Release workflow prerequisites already present: `v*` tag, `v$chartAppVersion` equality,
  `contents: write`, `id-token: write` and `attestations: write`. It builds archives and provenance
  but does **not** publish or sign a container image, SBOM, Helm chart or registry artifact.
- The current local image was built from revision `6441054`, not the final `9b05ad0` tree; rebuild
  from the release tag after commit and attach keyless CI provenance/signature.
- No registry credentials or signing identity are configured. Publication requires an approved
  registry, keyless CI identity (or managed key), image signing, SBOM attachment and scan evidence.

### Staging gates versus documented alpha limitations

**Must be verified during staging before production:** production ingress/TLS header, body, idle,
connection and rate controls; NetworkPolicy/CNI enforcement; Secret rotation; PDB/HPA and
rollout/rollback; cgroup peak RSS/OOM under the production limit; and a live multi-cluster/proxy
exercise against the intended deployment.

**May remain documented alpha limitations:** no offline routing simulation or exact key-movement
claim; no Lua execution or dynamic proxy-route analysis; no automatic remediation; no binary
protocol; no production-traffic evidence for the analyzers; one independent MCP client matrix; the
SDK's `Session termination failed: 202` warning; and proxy counter semantics varying by build.

### Exact release sequence after approval

1. Approve the tag, release and image-publication plan; the rename and private CI are complete.
2. Create a fresh post-commit tree archive and history bundle.
3. Tag and push:
   ```sh
   git tag -a v0.1.0-alpha.9 -m "MemCacheRoute MCP Server 0.1.0-alpha.9"
   git push origin main
   git push origin v0.1.0-alpha.9
   ```
4. Let CI/release build archives and provenance; verify the tag matches chart `appVersion`.
5. Accept or reject the Rekor deviation, then publish/sign the image, SBOM, scans and Helm artifact
   under the approved registry/CI identity.
6. Deploy to the isolated staging cluster, run the staging gates above, and record the result.
7. Only then approve production readiness; production currently remains **NOT VERIFIED**.

## Remaining release blockers

1. **No release tag or GitHub Release.** Private `main` CI passed at `34beb5c`; local tags
   still end at `v0.1.0-alpha.8`, and no post-commit tree/history backup exists yet.
2. **No published image signature or CI provenance.** Local SBOMs, vulnerability/secret scans and a
   local Cosign blob signature exist, but the current local image was built from revision `6441054`,
   not the final tree, and the image is not published or signed by CI.
3. **Helm runtime is only locally smoke-tested.** The chart installed and ran on
   kind v1.37.0 with Secret projection, fsGroup, non-root/read-only security and working auth.
   Production ingress, NetworkPolicy CNI enforcement, PDB/HPA behavior, rollout/rollback and token
   rotation remain unverified.
4. **Production reverse-proxy controls are unverified.** A reference nginx lab test passed
   body (413), header (400), idle (2.0 s), connection (503) and rate (429) limits while preserving
   MCP. The actual production ingress/TLS configuration and limits are still not supplied or tested.
5. **Peak RSS is sampled, not proven.** The current-tree image completed 47,388 calls in 30 s with
   a sampled peak of 9.04 MiB under a 256 MiB limit and no OOM, but this is not a cgroup high-water
   measurement or a production-limit/OOM test. The 96 MiB reservation budget is not an RSS cap.
6. **No image/chart publication pipeline, no live-proxy CI job and no Windows test-suite job.**
   Release archives are built and smoke-tested by the workflow, but cross-platform live behavior and
   real proxy stats are not exercised in CI.
7. **Residual operational risks:** audit lines can be dropped under queue/disk pressure (counters
   expose it); very large topologies may hit the 65 s/120 s tool deadlines or mcrouter bounds; real
   multi-record DNS resolver behavior and strict-parser compatibility with unusual proxies need a
   live environment.
8. **No release signing identity.** The Cosign evidence used ephemeral local keys that were deleted
   after verification. Publishing requires an approved CI keyless identity or a managed signing key;
   local test keys must not be reused for release.
9. **Unpublished history consolidation is not executed.** The three pre-expansion commits still
   contain the earlier Python cache/benchmark artifacts; history consolidation requires explicit
   approval. Published history is preserved either way.
10. **Public Rekor entries require policy review.** Three immutable `hashedrekord` entries exist for
    local evidence blobs (log indexes 3657074412, 3657085188, 3657100932). They contain no secrets or
    identities, but they were created before publication was approved.
11. **Expanded alpha analyzers have one synthetic lab pass only.** Capacity, slabs, timeline,
    routing, cluster comparison, migration advice, TKO analysis and the corrected proxy adapter
    were exercised against the isolated lab and real mcrouter/failover/proxy states, but not
    production traffic or multi-cluster infrastructure.
12. **Routing simulation is unsupported.** The project has no validated offline consistent-hash
    simulator and does not claim behavioral equivalence from config parsing; live trace validation is
    the supported path.
13. **MCP integration remains partial beyond the implemented surface.** Resources, static prompts
    and `server_info` structured output work with the repository harness and an independent Python
    MCP SDK (legacy 2025-11-25 and auto 2026-07-28). Sampling, elicitation, tasks, subscriptions,
    list-changed notifications, pagination, extensions and structured output for other tools are not
    implemented. Only one independent client implementation was tested; the SDK logs
    `Session termination failed: 202` on DELETE although the session ends.
14. **Cluster comparison and migration advice are partial.** One live lab comparison and one
    live-router migration review passed, but there is no production or multi-cluster migration
    evidence. No exact key-movement simulation is claimed.

## Consolidated reports

The following development reports were consolidated into this record and the maintained guides
(`docs/ARCHITECTURE.md`, `docs/TOOLS.md`, `docs/DIAGNOSTICS.md`, `docs/CONFIGURATION.md`,
`docs/DEPLOYMENT.md`, `docs/OPERATIONS.md`, `docs/TROUBLESHOOTING.md`,
`docs/CONTAINER-SECURITY.md`):

- `FINAL-QA-REPORT.md`
- `P1-LIVE-INTEGRATION-REPORT.md`
- `FINAL-STABILIZATION-REPORT.md`
- `PRODUCTION-READINESS-REVIEW.md`
- `WP-01-IMPLEMENTATION-REPORT.md`
- `WP-02-IMPLEMENTATION-REPORT.md`
- `WP-02-R1-VERIFICATION.md`
- `WP-03-IMPLEMENTATION-REPORT.md`
- `WP-04-IMPLEMENTATION-REPORT.md`
- `WP-06A-IMPLEMENTATION-REPORT.md` through `WP-06F-IMPLEMENTATION-REPORT.md`

## Recommendation

**NO-GO for release.** **CONDITIONAL GO for controlled staging** after the tree is committed/tagged,
the image is published with CI-backed signature/provenance, the Rekor entries are accepted or
addressed by policy, and the CI workflow runs on that commit. The proxy blocker is fixed and retested;
the local kind Helm smoke, reference nginx controls and sampled RSS result remove the "never
exercised" uncertainty but do not replace production ingress/CNI, cgroup high-water or multi-cluster
evidence. The repository rename is complete. Production readiness stays **NOT VERIFIED**.
