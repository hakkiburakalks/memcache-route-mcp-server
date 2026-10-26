# memcached-mcp

An [MCP](https://modelcontextprotocol.io) server for Memcached and mcrouter, written in Rust. It gives an AI assistant a safe way to inspect cache servers and diagnose problems. Read-only by default.

Status: early. See [COMPATIBILITY.md](COMPATIBILITY.md) for what has actually been tested.

## Safety model

- **Read-only by default.** Write tools (`set_key`, `delete_key`, `touch_key`) are not even listed unless `MEMCACHED_MCP_ALLOW_WRITE=1`. There is no flush tool.
- **Write prefixes.** With `MEMCACHED_MCP_WRITE_PREFIX` (comma-separated, e.g. `tmp:,scratch:`) writes are limited to keys starting with one of the prefixes; others are refused before any connection is made. Without it, any key on an allowlisted server can be written and the server warns at startup.
- **Audit trail.** Writes, rejected targets and denied requests are logged as JSON lines (with the calling user in HTTP mode) to `MEMCACHED_MCP_AUDIT_LOG` (or stderr). Key names and outcomes are recorded, never values or tokens. Reads are not audited.
- **Authenticated over HTTP.** The HTTP transport requires a bearer token (see below); stdio relies on whoever can start the process.
- **Allowlist.** The server only connects to `host:port` pairs listed in `MEMCACHED_MCP_ALLOWLIST` (comma-separated). With an empty list every target is rejected.
- **Key sampling is opt-in and private by default.** `sample_keys` exists only with `MEMCACHED_MCP_ALLOW_KEY_SAMPLING=1` and then returns prefix totals, not key names. Individual key names additionally need `MEMCACHED_MCP_ALLOW_KEY_NAMES=1`. The audit log records that a sample ran, never which keys it saw.
- **No values.** `get_key_metadata` returns metadata (existence, size, flags and, where supported, TTL and access info), never the value.
- **Capability probing.** Features are detected by asking the server (`version`, `mn`), not guessed from the version number.

## Tools

| Tool | What it does |
| --- | --- |
| `server_info` | Version and whether meta commands are supported |
| `get_stats` | `stats`, optionally a group (`settings`, `items`, `slabs`, ...) |
| `get_key_metadata` | Does a key exist; size and flags, plus TTL, last access, fetched-before and CAS on servers with meta commands |
| `diagnose_node` | Hit ratio, evictions vs memory, connection limits, eviction skew |
| `compare_nodes` | Outlier item counts and hit ratios across 3+ nodes |
| `mcrouter_get_stats` | mcrouter stats and destination health |
| `mcrouter_inspect_config` | Running mcrouter config: pools, servers, config problems |
| `mcrouter_compare_destinations` | Looks at each memcached behind an mcrouter and flags outliers and per-node problems (needs `MEMCACHED_MCP_DEST_MAP`) |
| `mcrouter_diagnose_failover` | Is there a failover handle, is anything down, and what that means for reads and writes |
| `mcrouter_trace_key_route` | Which destination a key routes to (asks mcrouter itself); says so when the destination is down |
| `sample_keys` | What is stored: items, bytes and never-fetched counts per key prefix, from the LRU crawler's metadata dump. Only with `MEMCACHED_MCP_ALLOW_KEY_SAMPLING=1` |
| `set_key`, `delete_key`, `touch_key` | Writes; only with `MEMCACHED_MCP_ALLOW_WRITE=1` |

`sample_keys` puts load on the server (it uses the LRU crawler), reads at most `max_scan` items (10,000 by default, 100,000 at most) and says so when it stopped early. The crawler's order is not random, so a partial scan is biased. Pass `uniform: true` to read the whole dump instead and keep a random sample of `max_scan` items: the totals are then scaled-up estimates for the whole cache (a full crawl, capped at 2 million items or 60 seconds; if the cap is hit the result says it is not random). It needs the crawler to be enabled, which it is on 1.5 and 1.6 but not by default on 1.4 (`-o lru_crawler`).

Diagnostic thresholds are heuristics and have not been tuned on production traffic. Looking up a key's metadata still counts in the server's global `get_hits`/`get_misses` totals, though it leaves the item's LRU position and fetched-before state alone.

## Remote use (Streamable HTTP)

By default the server speaks MCP over stdio. For shared or remote use, run it as an HTTP service:

```
MEMCACHED_MCP_HTTP_TOKEN="<at least 24 random characters>" MEMCACHED_MCP_ALLOWLIST=... memcached-mcp --http 127.0.0.1:8080
```

The endpoint is `/mcp`. Clients must send `Authorization: Bearer <token>`; requests without it get 401 and are written to the audit log (peer address only, never the token).

- The token is mandatory; the server refuses to start without one of at least 24 characters.
- There is no TLS. Binding to anything other than loopback is refused unless `MEMCACHED_MCP_HTTP_ALLOW_PLAINTEXT=1`, because the token would cross the network in clear text. Put a TLS-terminating proxy in front and bind to loopback.
- `Host` headers are checked against loopback names on every route (including `/metrics`) to block DNS rebinding. Behind a proxy, list the public hostnames in `MEMCACHED_MCP_HTTP_ALLOWED_HOSTS` (comma-separated).
- Failed logins are written to the audit log, at most 20 lines per second; the rest are summarised in one line, so a flood of bad tokens cannot fill the disk.
- A single shared token means one identity with full access. For per-user access see below.

### Per-user tokens and permissions

Instead of `MEMCACHED_MCP_HTTP_TOKEN`, point `MEMCACHED_MCP_HTTP_TOKEN_FILE` at a JSON file of users (set one of the two, not both). Only SHA-256 hashes of the tokens are stored. Issue a token with:

```
memcached-mcp new-token alice read,metrics        # never expires
memcached-mcp new-token alice read,metrics 30     # stops working after 30 days
```

It prints the token once (give it to Alice) and the entry to add to the file:

```json
{"users": [{"name": "alice", "token_sha256": "...", "permissions": ["read", "metrics"], "expires_at": 1795000000}]}
```

`expires_at` is optional, in unix seconds. From that moment the token is refused exactly like an unknown one (401, audited), and the server warns at startup about users whose token has already expired. To rotate, issue a new token, replace the user's entry and restart.

| Permission | Allows |
| --- | --- |
| `read` | every read-only tool, including the mcrouter ones, except `sample_keys` |
| `sample` | `sample_keys` (prefix totals) |
| `key_names` | key names from `sample_keys` (also needs `sample`) |
| `write` | `set_key`, `delete_key`, `touch_key` |
| `metrics` | `/metrics` |

A permission never widens the server-wide switches: writes still need `MEMCACHED_MCP_ALLOW_WRITE=1` (and the prefix limit), sampling still needs `MEMCACHED_MCP_ALLOW_KEY_SAMPLING=1`. The audit log records the user name on every entry, including denials. The file is read at startup; restart to change users. Tokens are 256 random bits, so a fast hash is enough. Rotation is manual: there is no revocation without editing the file and restarting.

### Prometheus metrics

In HTTP mode the server can also expose memcached counters at `/metrics`, so Prometheus keeps the history and you get trends and alerting without this project storing anything:

```
MEMCACHED_MCP_METRICS_TARGETS="10.0.1.5:11211,10.0.1.6:11211"   # each must also be in MEMCACHED_MCP_ALLOWLIST
```

```yaml
scrape_configs:
  - job_name: memcached
    authorization: { credentials: "<the same token>" }
    static_configs: [{ targets: ["127.0.0.1:8080"] }]
```

`/metrics` uses the same bearer token and is absent unless targets are configured. It exports raw counters and gauges (`memcached_get_hits_total`, `memcached_evictions_total`, `memcached_used_bytes`, ...) labelled by `instance`, plus `memcached_up` (0 when a target is unreachable). Ratios and rates are left to PromQL, e.g. `rate(memcached_get_hits_total[5m]) / (rate(memcached_get_hits_total[5m]) + rate(memcached_get_misses_total[5m]))`. Scrapes are not written to the audit log. mcrouter instances can be added with `MEMCACHED_MCP_MCROUTER_METRICS_TARGETS` (also allowlisted); they export `mcrouter_up`, destination counts (`mcrouter_destinations`, `_up`, `_down`, `_suspect`), client connections, routed get/set/delete counts, queue depth and memory. Per-destination detail is not exported, because mcrouter's `stats` does not report it. The output passes `promtool check metrics`.

## mcrouter destinations

mcrouter names its destinations as it sees them (often container or service names such as `mc-a:11211`), which this server may not be able to resolve. To inspect the memcached nodes behind an mcrouter, map those names to reachable addresses, and allowlist the addresses too:

```
MEMCACHED_MCP_DEST_MAP="mc-a:11211=10.0.1.5:11211,mc-b:11211=10.0.1.6:11211"
MEMCACHED_MCP_ALLOWLIST="10.0.0.9:5000,10.0.1.5:11211,10.0.1.6:11211"
```

Destinations without a mapping are reported as `unmapped` rather than guessed.

## Install

Download a binary for Linux, macOS or Windows from the releases page, or build from source:

```
cargo build --release -p mcp-server
```

## Docker

```
docker build -t memcached-mcp .
```

The image is a single static binary on `scratch` (about 7 MB), running as user 65532 with no shell. stdio is the default:

```
docker run -i --rm -e MEMCACHED_MCP_ALLOWLIST=cache:11211 memcached-mcp
```

For HTTP, the process has to bind `0.0.0.0` inside the container, which the server refuses unless `MEMCACHED_MCP_HTTP_ALLOW_PLAINTEXT=1`. Publish the port on loopback only, or put a TLS proxy in front:

```
docker run -d -p 127.0.0.1:8080:8080 \
  -e MEMCACHED_MCP_ALLOWLIST=cache:11211 -e MEMCACHED_MCP_HTTP_TOKEN=... \
  -e MEMCACHED_MCP_HTTP_ALLOW_PLAINTEXT=1 memcached-mcp --http 0.0.0.0:8080
```

Both modes were tried against a memcached on the same Docker network. The image is built in CI but not published anywhere, and it has not been run on a Kubernetes cluster (see the Helm chart below).

## Kubernetes (Helm)

A chart is in `deploy/helm/memcached-mcp`. It runs the HTTP transport as a non-root, read-only-filesystem pod and refuses to render without an allowlist and an existing Secret holding the credentials:

```
kubectl create secret generic memcached-mcp-auth --from-file=tokens.json
helm install mcp deploy/helm/memcached-mcp \
  --set image.repository=registry.example.com/memcached-mcp --set image.tag=0.1.0-alpha.4 \
  --set 'allowlist={memcached-0.memcached:11211}' \
  --set auth.existingSecret=memcached-mcp-auth
```

The pod speaks plain HTTP, so expose the Service only through a TLS-terminating ingress and add its public name to `allowedHosts` (the Service's own DNS names, such as `mcp-memcached-mcp.<namespace>.svc`, are accepted automatically so in-cluster clients and Prometheus work). To limit who can reach the pod, set `networkPolicy.enabled=true` and list the allowed peers in `networkPolicy.allowFrom` (this only has an effect on a CNI that enforces NetworkPolicy). The chart lints and renders in CI, and was installed on a local kind cluster to check that the pod starts with the read-only filesystem, that the token file mounts, and that clients using the Service DNS name get through the Host check. It has not run on a production cluster. The image is not published, so you have to build and push it yourself.

## Use with Claude Code

```
claude mcp add memcached -e MEMCACHED_MCP_ALLOWLIST=127.0.0.1:11211 -- /path/to/memcached-mcp
```

## Develop

```
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

Live tests are skipped unless pointed at a server. Start the test servers and set the variables:

```
docker compose -f tests/compat/docker-compose.yml up -d
MEMCACHED_ADDR=127.0.0.1:11216 MEMCACHED_SMALL_ADDR=127.0.0.1:11217 MCROUTER_ADDR=127.0.0.1:11218 cargo test
```

The dead-destination test needs `mc-a` stopped first (CI does this too):

```
docker compose -f tests/compat/docker-compose.yml stop mc-a
MCROUTER_PLAIN_ADDR=127.0.0.1:11218 MCROUTER_FAILOVER_ADDR=127.0.0.1:11222 cargo test -p mcrouter --test failover
```

Layout: `memcached-protocol` (codec, no I/O), `memcached-core` (client), `diagnostics` and `mcrouter` (pure analysis), `mcp-server` (the binary).
