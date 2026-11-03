# Troubleshooting

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| `... is not in MEMCACHED_MCP_ALLOWLIST` | the exact `host:port` string is not listed | add the entry exactly as the client writes it (names are not normalised) |
| Server exits at startup with `MEMCACHED_MCP_ALLOWLIST entry '...'` | entry without a port, port 0, a URL/path/userinfo, malformed DNS label, unbracketed IPv6, or a link-local address | fix the entry; `MEMCACHED_MCP_ALLOW_LINK_LOCAL=1` only if memcached really runs on a link-local address |
| `resolves only to link-local, unspecified or multicast addresses; refused` | the name points at a metadata or otherwise blocked address | use a real address; this is the protection against metadata endpoints |
| `resolving ... timed out` | DNS did not answer within 3 s | check the resolver; in Kubernetes check CoreDNS |
| `cannot connect to ... address(es) within 3s` | all checked IPv4/IPv6 addresses were unreachable | check the target and network; the error names the last attempt |
| `operation deadline exceeded` | the server dripped a reply past the 60 s whole-command deadline | check the Memcached server/network; the connection is retired and the call fails closed |
| `... exceeded the ... deadline` from a tool | the whole tool call exceeded `MEMCACHED_MCP_TOOL_TIMEOUT_MS` or `MEMCACHED_MCP_MULTI_TOOL_TIMEOUT_MS` | inspect upstream latency; raise the deadline only after confirming the workload, and remember per-command limits still apply |
| HTTP 415/413 or a closed POST | malformed/oversized body, or the POST body exceeded `MEMCACHED_MCP_HTTP_BODY_TIMEOUT_MS` | check client framing; use a normal client and do not drip a body |
| TCP connection stalls before HTTP headers | header/idle protection is delegated to the reverse proxy/ingress | enforce header-read, idle and connection limits in the proxy |
| `route key contains syntax ...` | `mcrouter_trace_key_route` key contains comma, parentheses, backslash, whitespace or control characters | use a key that can be represented in mcrouter's `route(op,key)` expression |
| `route key is too long` | the generated route probe would exceed 250 bytes | shorten the key; memcached's key limit includes the mcrouter prefix |
| HTTP 401 | missing, wrong or expired token | tokens expire at `expires_at`; the audit log says `denied: missing, wrong or expired bearer token` |
| HTTP 403 `forbidden host` | `Host` header not accepted | add the name to `MEMCACHED_MCP_HTTP_ALLOWED_HOSTS` (Helm: `allowedHosts`) |
| HTTP 429 | the user has too many requests in flight | retry after a second; raise `MEMCACHED_MCP_HTTP_MAX_CONCURRENT` if legitimate |
| HTTP 503 `too many open sessions` | global or per-user session cap | close idle sessions (they idle out after 5 minutes) or raise the caps |
| `forbidden: '<user>' does not have the '<perm>' permission` | the token lacks the permission | issue a token with it (`memcached-mcp new-token NAME PERMS`) |
| Token change has no effect | file not updated in the pod, or the new file does not parse | the audit log shows `token file reloaded` or `token file changed but is invalid`; Kubernetes needs up to about a minute to propagate a Secret |
| `get_stats` says `stats group must be one of ...` | only read-only groups are allowed | use one of the listed groups |
| `ttl_seconds must be at most 2592000` | memcached would read a longer TTL as a timestamp | use at most 30 days, or compute the expiry yourself |
| `connection closed by server` after an earlier timeout | the connection was retired after a failed read | retry; each call opens a fresh connection |
| `compare_needs_three_nodes` | outlier detection needs 3 nodes | pass at least 3 addresses |
| Diagnosis says `hit_ratio_insufficient_data` | fewer than 1000 gets since start | wait for traffic |
| `evictions` is `info` on a busy cache | few evictions over a long uptime | expected; look at the average rate in the message |
| `mcrouter_compare_destinations` lists destinations as `unmapped` | no `MEMCACHED_MCP_DEST_MAP` entry | map mcrouter's name to a reachable, allowlisted address |
| `/metrics` is 404 | no metrics targets configured | set `MEMCACHED_MCP_METRICS_TARGETS` or `MEMCACHED_MCP_MCROUTER_METRICS_TARGETS` |
| Pod restarts slowly | an older image without graceful shutdown | use a build that handles SIGTERM (builds after alpha.8) |

Run with `MEMCACHED_MCP_AUDIT_LOG=/path` (or watch stderr) to see denials. Everything the server
refuses is audited; successful reads are not. Audit output is capped at 100 lines/s process-wide;
if you see `more audit lines were dropped`, ship logs with a collector rather than relying on the
local file. `Bearer`/`bearer` are accepted case-insensitively.
