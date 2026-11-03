#!/usr/bin/env bash
# Release-independent image checks: inspect the local image, write an SBOM and scan it.
# Never starts Docker, never pushes, never deploys. Exits 2 (BLOCKED) when a prerequisite is
# missing so a CI/manual gate cannot mistake "not run" for "passed".
set -euo pipefail

image="${1:-}"
if [ -z "$image" ]; then
  echo "usage: $0 <local-image-reference>" >&2
  exit 64
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "BLOCKED: docker CLI is not installed" >&2
  exit 2
fi
if ! docker info >/dev/null 2>&1; then
  echo "BLOCKED: Docker daemon is not reachable; refusing to start it" >&2
  exit 2
fi
if ! docker image inspect "$image" >/dev/null 2>&1; then
  echo "BLOCKED: image is not present locally: $image" >&2
  exit 2
fi

user="$(docker image inspect "$image" --format '{{.Config.User}}')"
echo "image_user=$user"
if [ "$user" != "65532:65532" ]; then
  echo "FAIL: image user is '$user', expected 65532:65532" >&2
  exit 1
fi

# A digest is only present after a registry push/pull; this is informational for a local build.
docker image inspect "$image" --format 'repo_digest={{if .RepoDigests}}{{index .RepoDigests 0}}{{else}}<none>{{end}}'

out_dir="${OUT_DIR:-container-security}"
mkdir -p "$out_dir"

if ! command -v syft >/dev/null 2>&1; then
  echo "BLOCKED: syft is not installed; cannot generate an SBOM" >&2
  exit 2
fi
syft "$image" -o "spdx-json=$out_dir/sbom.spdx.json"
echo "SBOM=$out_dir/sbom.spdx.json"

if ! command -v trivy >/dev/null 2>&1; then
  echo "BLOCKED: trivy is not installed; vulnerability scan did not run" >&2
  exit 2
fi
trivy image --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed \
  --exit-code 1 "$image"
echo "PASS: image checks completed"
