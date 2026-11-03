# Security policy

MemCacheRoute MCP Server is a Rust MCP server for Memcached and mcrouter diagnostics. It is
read-only by default and has no automatic remediation.

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's private vulnerability
reporting ("Security" tab of the repository, "Report a vulnerability"). Include the version
(release tag or commit), the configuration that matters (transport, permissions, switches) and the
smallest steps that show the problem.

You can expect an acknowledgement within a few days. This is a volunteer project and there is no
bounty. Fixes for confirmed issues are released as a new tag, and the advisory credits the
reporter unless asked otherwise.

## Supported versions

The project is pre-1.0 (`0.1.0-alpha.N`). Only the latest tag receives fixes.

## Threat model in short

The server lets an MCP client (usually an AI assistant) inspect cache servers. What it defends:

- **A client that should not change anything.** Write tools are not listed unless
  `MEMCACHED_MCP_ALLOW_WRITE=1`, need the `write` permission and an allowed key prefix. Read
  tools only send commands from a fixed set; arguments that end up on a command line (stats
  group, keys) are validated, and stats groups are an allowlist. The RCA tools are read-only
   analyses over the same stats/config snapshots and return aggregate evidence, not values, keys,
   tokens, pool names or destination names. Incident snapshots contain only selected numeric
   metrics and opaque topology IDs; the server never writes them to disk, and comparison accepts
   size/version-checked snapshot objects.
- **A client that should not reach arbitrary hosts.** Targets must be listed in
  `MEMCACHED_MCP_ALLOWLIST`; link-local, unspecified and multicast addresses (cloud metadata
  endpoints) are refused even if a name resolves to them; the connection goes to the checked
  address. Private and loopback networks are allowed because that is where memcached runs.
- **An unauthenticated network caller (HTTP).** Bearer tokens (stored as SHA-256 hashes), Host
  header check, per-user request and session limits, throttled failed-login audit lines.
- **A metrics stampede or slow upstream.** `/metrics` has a process-wide request cap, bounded
  fan-out, an overall deadline and a singleflight TTL cache. Tool connections have a separate
  process-wide upstream budget; exhaustion fails closed. Failed refreshes return 503 and are
  never replaced with an expired cached body; an unreachable target is `*_up 0`.
- **A misbehaving memcached or mcrouter.** Replies have per-line and total byte budgets for
  stats, metadump and values; a malformed, timed-out or over-budget read retires the connection,
  so leftovers are never taken as the next answer. Metadata lookups on classic servers discard
  the value in bounded chunks instead of allocating it. A process-wide reservation budget
  (`MEMCACHED_MCP_MEMORY_BUDGET_MB`) fails closed when large reply buffers, STAT maps, metadump
  scans or the `/metrics` cache cannot be reserved.
- **Resource exhaustion across clients.** A process-wide upstream connection budget, per-user
  request/session caps and bounded `/metrics` fan-out limit concurrent work. Each command has a
  whole-operation deadline so a slow-dripping upstream cannot hold a request indefinitely; each
  MCP tool also has a whole-call deadline, and POST bodies have a read deadline. Audit output is
  rate-capped per process and per identity, fields are clipped, and a bounded async writer keeps a
  slow disk off the Tokio runtime. Limits are per pod, see
  [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#several-replicas).

What it does not do, and you must provide:

- **TLS.** The HTTP transport is plain. Bind to loopback or put a TLS-terminating proxy in front.
  Binding elsewhere requires `MEMCACHED_MCP_HTTP_ALLOW_PLAINTEXT=1`.
- **Authentication to memcached.** The memcached text protocol has none here; restrict network
  access to memcached itself (NetworkPolicy, firewall).
- **Protection from a user who holds a valid `read` token.** Reads can include `sample_keys` totals
  and (with the extra switch and permission) key names. Give tokens the least permissions needed.
- **Replica-wide limits.** Session and request limits are per process; see
  [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#several-replicas).
- **Image supply-chain guarantees.** Build images from a reviewed digest, generate an SBOM and
  scan them before deployment; see [docs/CONTAINER-SECURITY.md](docs/CONTAINER-SECURITY.md). The
  project does not publish an image yet.

Audit lines record key names and outcomes, never values or tokens. Container and Kubernetes
hardening, secret rotation, rollout/rollback and incident steps are in
[docs/OPERATIONS.md](docs/OPERATIONS.md).
