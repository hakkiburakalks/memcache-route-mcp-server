# Contributing

Thanks for helping with **MemCacheRoute MCP Server**. The project aims to be a small, safe,
well-tested MCP server for Memcached and mcrouter; changes that make it safer or more correct are
the most welcome.

## Set up

```
git clone https://github.com/hakkiburakalks/memcached-mcp-server
cd memcached-mcp-server
cargo build
cargo test            # unit tests and tests that need no memcached
```

Tests that talk to a real server are skipped unless their variables are set:

```
docker run -d --name mc -p 11216:11211 memcached:1.6 -o lru_crawler
MEMCACHED_ADDR=127.0.0.1:11216 cargo test --workspace

docker compose -f tests/compat/docker-compose.yml up -d mcrouter mcrouter-failover
MCROUTER_ADDR=127.0.0.1:11218 MCROUTER_BACKENDS=127.0.0.1:11219,127.0.0.1:11220,127.0.0.1:11221 \
  cargo test --workspace
```

The load and chaos laboratory is described in [docs/OPERATIONS.md](docs/OPERATIONS.md#load-and-chaos-laboratory).

## Before you open a pull request

```
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

- Keep changes small and focused. Explain the why in the commit message.
- A bug fix comes with a test that fails without it. A new rule or limit comes with a test on both
  sides of its threshold.
- Anything that puts text on a memcached command line must be validated; add it to the hostile
  input tests (`crates/memcached-core/tests/hostile.rs`, the e2e `read_tools_cannot_smuggle_commands`).
- Do not weaken a safety check to make a test pass. If a check is wrong, fix the check and say so.
- Do not claim compatibility or runtime behaviour that was not observed; see
  [COMPATIBILITY.md](COMPATIBILITY.md).
- New dependencies need a reason; prefer the standard library and what is already in `Cargo.lock`.
- Documentation is in English. Examples must run as written.

## Layout

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Licence

By contributing you agree that your work is licensed under the Apache License 2.0, like the rest
of the project.
