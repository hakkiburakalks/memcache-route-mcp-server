#!/usr/bin/env bash
# Runs one traffic profile against the lab. Usage:
#   ./run-load.sh PROFILE [loadgen options]      e.g. ./run-load.sh read-heavy --duration 30
# Profiles: read-heavy balanced write-heavy hot-key memory-pressure eviction-heavy
# Default target is mcrouter; add --target mc1:11211 (repeatable) to go straight to memcached.
set -euo pipefail
cd "$(dirname "$0")"
profile="${1:?usage: run-load.sh PROFILE [loadgen options]}"; shift
args=("$@")
case " ${args[*]:-} " in *" --target "*) ;; *) args+=(--target mcrouter:5000) ;; esac
exec docker compose --profile load run --rm loadgen --profile "$profile" "${args[@]}"
