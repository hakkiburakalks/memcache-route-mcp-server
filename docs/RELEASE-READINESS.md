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

The actual GitHub repository slug/URL is unchanged (`hakkiburakalks/memcached-mcp-server`) until the
remote rename to `memcache-route-mcp-server` is explicitly approved and performed; package/clone
commands in the docs therefore keep the current URL.

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
| `cargo test --workspace --no-fail-fast` | **244 passed, 0 failed, 0 ignored** |
| `cargo audit` | PASS — 1402 advisories, 127 dependencies |
| `python -I scripts/check-licenses.py` | PASS — 122 dependency licences accepted |
| `cargo build --release --locked -p mcp-server` | PASS |
| Release binary smoke test | PASS — `smoke ok` with the new MCP identity |
| Helm `lint --strict` / valid render | PASS |
| Helm PDB/HPA/NetworkPolicy render | PASS (static) |
| `docker compose -f tests/compat/docker-compose.yml config --quiet` | PASS |
| Markdown links/anchors | PASS — all 56 links resolve |
| Version consistency | PASS — `0.1.0-alpha.9` in workspace, `Cargo.lock`, Chart version/appVersion and changelog |
| Local history consolidation | PASS — 3 commits ahead, 0 behind, clean working tree |
| `git diff --check` (worktree and `origin/main..HEAD`) | PASS |
| Current branding image build/runtime | PASS — `memcached-mcp:0.1.0-alpha.9`, read-only rootfs, healthy `/healthz` |
| Source/dependency SBOM | PASS — 137 SPDX packages / 139 CycloneDX components |
| Image SBOM | PASS — scratch image (1 filesystem package; dependencies covered by source SBOM) |
| Trivy image/source vulnerability scan | PASS — 0 vulnerabilities |
| Trivy secret scans | PASS — 0 secrets in image/source |
| Cosign evidence signature | PASS — ephemeral-key blob signature verified; public Rekor entries disclosed below |

The 244-test harness includes 15 live tests that self-skip without lab variables; about **229
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
| memcached 1.4.39 | core live 3/3; MCP e2e 37/37; `meta: false` | PASS |
| memcached 1.5.22 | core live 3/3; MCP e2e 37/37; `meta: false` | PASS |
| memcached 1.6.45 | core live 3/3; MCP e2e 37/37; `meta: true` | PASS |
| Eviction (4 MB server) | 1/1; critical eviction finding observed | PASS |
| mcrouter 34.0.0 live | 1/1 | PASS |
| mcrouter-enabled MCP e2e | 37/37, 0 env-skips | PASS |
| Failover integration test | **5/5 consecutive runs** with `mc-a` stopped | PASS |
| Hard failure | plain pool fails loudly; failover stores on `mc-b` | PASS |
| MCP diagnosis | `down_without_failover` / `failover_active` | PASS |

The failover test was fixed without weakening the client: `Client::store` still retires a
connection after a `SERVER_ERROR`; the test now reconnects before follow-up reads.

## Live MCP and image evidence

- 14 of 18 read tools were invoked against real services; all returned `isError: false` and the
  declared `schema_version: "1.0"` where applicable.
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

Read-only inspection of `https://rekor.sigstore.dev/api/v1/log/entries?logIndex=…` confirmed:

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

**Verified backups created during this review:**

- Tree: `C:\Users\burak\AppData\Local\Temp\memcache-route-supplychain\tree-20261103-062017.tgz`
  — 126 entries / 91 files, SHA-256
  `E87E1D989319E7D2527FECFB2E5C6ADE668A1B6CE169FED63C67D2A6F6A79F47`; key-file hashes matched
  after extraction. Excludes `.git`, `target`, `node_modules`, `.claude-flow` and `.swarm`.
- History: `C:\Users\burak\AppData\Local\Temp\memcache-route-supplychain\history-20261103-062017.bundle`
  — SHA-256 `D989E53CFE8900820E0A136D53FB4B182BD8AAACCD404C393CC6D7A0F8E683FA`;
  `git bundle verify` reports a complete history. It contains `HEAD`/`main` (`6441054`),
  `origin/main` (`ef65d55`) and tags `v0.1.0-alpha.1`–`v0.1.0-alpha.8`. Reflogs, hooks and local
  config are not part of a bundle; the live `.git` directory remains intact.

Together, the tree archive and Git bundle cover all current release files and all local-only
commits/tags. The previous backup alone is insufficient.

### Consolidation result

Local history consolidation completed on `main`; published history was not rewritten.

| Commit | Subject | Scope |
|---|---|---|
| `0f9ffbf` | Harden runtime security, reliability and diagnostics | Rust crates, Cargo metadata/lock, tests |
| `2d78eb1` | MemCacheRoute branding and consolidated documentation | README, changelog, security/contribution docs, `docs/` |
| `HEAD` | Release hygiene, packaging and verification | Dockerfile, Helm, workflows, scripts, fixtures, ignore rules, cleanup record, `.serena` removal |

- `origin/main` remains `ef65d55`; HEAD is exactly **3 commits ahead and 0 behind**.
- Working tree is clean; no staging/commit/push/tag beyond the approved three local commits.
- No generated `.pyc`, benchmark output, `.serena` state, SBOM, signing key or temporary evidence is
  present in the commit tree.
- Tags remain `v0.1.0-alpha.1`–`v0.1.0-alpha.8`; no alpha.9 tag was created.

### Tree comparison and recovery

- Pre-consolidation tree archive: 91 files, 126 entries, SHA-256
  `8D045B81229BA6012A7CE7F86612B038822CEADB51656A097364EB45BC4427F1`.
- Final tree: 91 files. All source and test files are byte-identical to the archive. The only
  differences are the final whitespace/metadata updates in `LICENSE`,
  `REPOSITORY-CLEANUP-REPORT.md` and `docs/RELEASE-READINESS.md`; no source, test, fixture, Helm or
  workflow file differs or is missing.
- Full pre-consolidation history: `history-final-20261103-062507.bundle`, SHA-256
  `DF4C78CD4D44C2CFDB75F7B16699FC70D57AF1FD3FED918CF84674D46F295082`; `git bundle verify`
  reports a complete history containing `6441054`, `origin/main` (`ef65d55`) and all tags.
- Recovery path: clone the verified bundle into a fresh directory or use the live `git reflog` to
  return to the pre-consolidation state. No hard reset or destructive recovery is required.

The actual GitHub repository rename to `memcache-route-mcp-server` and all URL/source-label updates
remain blocked until the remote rename is approved.

### Release content review

- Final tree contains **32 Rust source/test files** (including 10 integration-test files), **16
  Markdown documents**, Helm chart/templates, workflows, scripts and fixtures.
- Compared with `origin/main`: 63 tracked paths changed plus 24 untracked release files; the only
  tracked deletions are `.serena/` (agent state); Python cache and benchmark output are removed from
  the tree.
- Intended source is present: protocol/client/memory, diagnostics/RCA/snapshots/efficiency/
  remediation/history, mcrouter cluster/failover, MCP auth/audit/HTTP/tools/metrics.
- Intended tests are present: unit, hostile, e2e, security, metrics, deadlines, memory budget,
  eviction, live and failover.
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

## Publication commands and approvals

The following are **not executed** and require separate approval:

1. Approve the GitHub repository rename to `memcache-route-mcp-server`; then update the clone URL
   in `CONTRIBUTING.md`, the OCI source label and release documentation.
2. Approve Plan A or Plan B, create the resulting commit set, then tag and push:
   ```sh
   git tag -a v0.1.0-alpha.9 -m "MemCacheRoute MCP Server 0.1.0-alpha.9"
   git push origin main
   git push origin v0.1.0-alpha.9
   ```
3. Review and accept the public Rekor entries (or document the policy exception), then approve
   publishing the image, SBOM/scan results and CI signature/provenance under the approved
   registry/CI identity. Local build, SBOM, scan and blob-signing evidence is complete; nothing was
   published.
4. Approve an isolated staging cluster and reverse-proxy test; validate Secret projection,
   NetworkPolicy, PDB/HPA, rollout/rollback and token rotation.
5. Approve the CI run and release publication only after the above gates pass.

## Remaining release blockers

1. **No CI/release run and no release tag for this tree.** HEAD is `6441054`, seven commits ahead
   of `origin/main`; local tags end at `v0.1.0-alpha.8`. The working tree is still uncommitted.
2. **No published image signature or CI provenance.** Local SBOMs, vulnerability/secret scans and a
   local Cosign blob signature exist, but the image is not published and has no keyless CI
   signature, attestation or registry provenance.
3. **No Helm/Kubernetes runtime evidence.** Lint/render passes, but Secret projection/fsGroup,
   NetworkPolicy CNI enforcement, PDB/HPA, rollout/rollback, probes and token rotation were not run
   on a live cluster.
4. **Reverse-proxy controls are mandatory but unverified.** HTTP header-read, idle and connection
   limits are delegated to the production ingress; no proxy configuration or runtime test is
   included.
5. **No peak-RSS/OOM proof.** The 96 MiB reservation budget is not an RSS cap and the 256 MiB
   container limit is not measured; Linux/container peak RSS and OOM behavior remain unverified.
6. **No image/chart publication pipeline and no Windows test-suite CI job.** Release archives are
   built and smoke-tested by the workflow, but cross-platform live behavior is not exercised in CI.
7. **Residual operational risks:** audit lines can be dropped under queue/disk pressure (counters
   expose it); very large topologies may hit the 65 s/120 s tool deadlines or mcrouter bounds; real
   multi-record DNS resolver behavior and strict-parser compatibility with unusual proxies need a
   live environment.
8. **No release signing identity.** The Cosign evidence used ephemeral local keys that were deleted
   after verification. Publishing requires an approved CI keyless identity or a managed signing key;
   local test keys must not be reused for release.
9. **Remote repository rename is pending.** The actual slug/URL and OCI source label stay on
   `memcached-mcp-server` until the GitHub rename to `memcache-route-mcp-server` is approved and
   performed.
10. **Unpublished history consolidation is not executed.** The seven local commits still contain the
    Python cache/benchmark artifacts; Plan A/B above requires explicit approval. Published history is
    preserved either way.
11. **Public Rekor entries require policy review.** Three immutable `hashedrekord` entries exist for
    local evidence blobs (log indexes 3657074412, 3657085188, 3657100932). They contain no secrets or
    identities, but they were created before publication was approved.

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

**NO-GO for release.** **CONDITIONAL GO for controlled staging** after the consolidation plan is
approved and executed, the tree is committed/tagged, the image is published with CI-backed
signature/provenance, the Rekor entries are accepted or addressed by policy, and the CI workflow runs
on that commit. Helm runtime and the remote repository rename remain release gates unless the project
explicitly accepts them as documented risks. Production readiness stays **NOT VERIFIED**.
