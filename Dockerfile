# Static musl binary in an empty image: no shell, no package manager, runs as a non-root user.

FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p mcp-server

FROM scratch
COPY --from=build /src/target/release/memcached-mcp /memcached-mcp
USER 65532:65532
# stdio by default. For HTTP, pass `--http 0.0.0.0:8080` plus MEMCACHED_MCP_HTTP_TOKEN and
# MEMCACHED_MCP_HTTP_ALLOW_PLAINTEXT=1, and publish the port on loopback or behind a TLS proxy.
EXPOSE 8080
ENTRYPOINT ["/memcached-mcp"]
