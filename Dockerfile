# syntax=docker/dockerfile:1
# Static musl binary in an empty image: no shell, no package manager, runs as a non-root user.
#
#   docker build -t memcached-mcp:local .
#   docker build --build-arg VERSION=0.1.0-alpha.9 --build-arg REVISION=$(git rev-parse HEAD) \
#                --build-arg CREATED=$(date -u +%Y-%m-%dT%H:%M:%SZ) -t ... .
#
# Builds natively for the platform it runs on (rust:alpine is multi-arch), so
# `docker buildx build --platform linux/amd64,linux/arm64` yields both architectures.
#
# The Rust builder is pinned by both version and multi-arch manifest digest. Update both
# together; see docs/CONTAINER-SECURITY.md. Alpine packages fetched by apk are not pinned to
# versions, so the base digest narrows but does not fully guarantee bit-for-bit reproducibility.

ARG RUST_IMAGE=rust:1.95-alpine@sha256:606fd313a0f49743ee2a7bd49a0914bab7deedb12791f3a846a34a4711db7ed2
FROM ${RUST_IMAGE} AS build
ENV CARGO_INCREMENTAL=0
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# Cache mounts keep the registry and build directory between builds; the binary is copied out
# because the target directory is not part of the image layer.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p mcp-server \
    && cp target/release/memcached-mcp /memcached-mcp

FROM scratch
ARG RUST_IMAGE
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=1970-01-01T00:00:00Z
LABEL org.opencontainers.image.title="MemCacheRoute MCP Server" \
      org.opencontainers.image.description="AI-powered diagnostics and troubleshooting for Memcached and mcrouter." \
      org.opencontainers.image.source="https://github.com/hakkiburakalks/memcached-mcp-server" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      com.memcache-route-mcp.build.rust-image="${RUST_IMAGE}"
COPY --chmod=0555 --from=build /memcached-mcp /memcached-mcp
COPY --chmod=0444 LICENSE /LICENSE
USER 65532:65532
# stdio by default. For HTTP, pass `--http 0.0.0.0:8080` plus MEMCACHED_MCP_HTTP_TOKEN (or
# MEMCACHED_MCP_HTTP_TOKEN_FILE) and MEMCACHED_MCP_HTTP_ALLOW_PLAINTEXT=1, and publish the port on
# loopback or behind a TLS proxy. Probe with GET /healthz (the image has no shell for HEALTHCHECK).
EXPOSE 8080
ENTRYPOINT ["/memcached-mcp"]
