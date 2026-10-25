# Compatibility

"Verified" means the `live` integration test passes in CI against that server image. Everything else is a target, not a guarantee.

| Server | Status | Notes |
| --- | --- | --- |
| memcached 1.6.x | Verified (1.6.45) | Meta commands detected via `mn` |
| memcached 1.5.x | Verified (1.5.22) | No meta commands |
| memcached 1.4.x | Verified (1.4.39) | No meta commands |
| memcached 1.2 / 1.3 | Untested | Experimental, no real-server tests yet |
| mcrouter | Not started | |
| AWS ElastiCache | Not tested | |

Capabilities are probed at runtime (`version`, `mn`), not inferred from the version number.

## Host platforms

| Platform | Status |
| --- | --- |
| Linux | CI build and test |
| macOS | CI build and test |
| Windows | Develops and tests locally; no CI or release binary yet |
