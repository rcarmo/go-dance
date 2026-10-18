#!/usr/bin/env bash
# Select this native Linux runner's architecture; Windows is cross-compiled here.
set -euo pipefail
arch=${1:?usage: release-config.sh amd64|arm64 output.yml}
output=${2:?output configuration required}
case "$arch" in
  amd64) other=arm64; expected_machine=x86_64 ;;
  arm64) other=amd64; expected_machine=aarch64 ;;
  *) echo "unsupported release architecture: $arch" >&2; exit 1 ;;
esac
machine=$(uname -m)
if [[ "$arch" == arm64 && "$machine" == arm64 ]]; then machine=aarch64; fi
if [[ "$(uname -s)" != Linux || "$machine" != "$expected_machine" || "$(go env GOOS)" != linux || "$(go env GOARCH)" != "$arch" ]]; then
  echo "Linux $arch releases require a matching native Linux runner" >&2
  exit 1
fi
# The shared configuration has one build with both supported architectures.
# Do not cross-compile Linux for the other architecture on this runner.
sed "/^      - ${other}$/d" .goreleaser.yml > "$output"
if [[ $(grep -c "^      - ${arch}$" "$output") != 1 ]] || grep -q '^      - darwin$' "$output"; then
  echo "unexpected release target configuration" >&2
  exit 1
fi
