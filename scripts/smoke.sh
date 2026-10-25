#!/usr/bin/env bash
# Runs a built binary and checks that it starts, speaks MCP over stdio and issues tokens.
# Needs no memcached. Usage: scripts/smoke.sh path/to/memcached-mcp[.exe]
set -euo pipefail
bin="$1"

out=$( { printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  sleep 1
  printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
  sleep 1; } | MEMCACHED_MCP_ALLOWLIST=127.0.0.1:11211 "$bin" )

echo "$out" | grep -q '"name":"memcached-mcp"' || { echo "no server info in: $out"; exit 1; }
echo "$out" | grep -q '"name":"server_info"' || { echo "no tools listed in: $out"; exit 1; }
if echo "$out" | grep -q '"name":"set_key"'; then echo "write tools must be hidden by default"; exit 1; fi

tok=$("$bin" new-token smoke read)
echo "$tok" | grep -q '"token_sha256"' || { echo "new-token failed: $tok"; exit 1; }

if "$bin" --http 127.0.0.1:0 2>/dev/null; then echo "HTTP must refuse to start without a token"; exit 1; fi
echo "smoke ok: $bin"
