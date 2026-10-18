#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
mkdir "$tmp/bin"
cat > "$tmp/bin/uname" <<'MOCK'
#!/usr/bin/env bash
case "$*" in
  -m) printf '%s\n' "$TEST_MACHINE" ;;
  -s) printf '%s\n' "${TEST_KERNEL:-Linux}" ;;
  *) exit 1 ;;
esac
MOCK
cat > "$tmp/bin/go" <<'MOCK'
#!/usr/bin/env bash
case "$*" in
  'env GOOS') printf '%s\n' "${TEST_GOOS:-linux}" ;;
  'env GOARCH') printf '%s\n' "$TEST_ARCH" ;;
  *) exit 1 ;;
esac
MOCK
chmod +x "$tmp/bin/uname" "$tmp/bin/go"
for arch in amd64 arm64; do
  case "$arch" in amd64) machine=x86_64; other=arm64;; arm64) machine=aarch64; other=amd64;; esac
  PATH="$tmp/bin:$PATH" TEST_MACHINE="$machine" TEST_ARCH="$arch" \
    bash scripts/release-config.sh "$arch" "$tmp/$arch.yml"
  grep -q "^      - $arch$" "$tmp/$arch.yml"
  grep -q '^      - linux$' "$tmp/$arch.yml"
  grep -q '^      - windows$' "$tmp/$arch.yml"
  if grep -Eq "^      - ($other|darwin)$" "$tmp/$arch.yml"; then
    echo "unexpected target in $arch configuration" >&2; exit 1
  fi
done
if PATH="$tmp/bin:$PATH" TEST_MACHINE=x86_64 TEST_ARCH=amd64 \
  bash scripts/release-config.sh arm64 "$tmp/wrong-host.yml" 2>/dev/null; then
  echo 'accepted cross-compilation for a Linux release target' >&2; exit 1
fi
if PATH="$tmp/bin:$PATH" TEST_MACHINE=x86_64 TEST_ARCH=amd64 TEST_GOOS=windows \
  bash scripts/release-config.sh amd64 "$tmp/windows-host.yml" 2>/dev/null; then
  echo 'accepted a Windows release runner' >&2; exit 1
fi
if PATH="$tmp/bin:$PATH" TEST_MACHINE=aarch64 TEST_ARCH=arm64 TEST_KERNEL=Darwin \
  bash scripts/release-config.sh arm64 "$tmp/darwin-host.yml" 2>/dev/null; then
  echo 'accepted a Darwin release runner' >&2; exit 1
fi
printf 'PASS: native AMD64/ARM64 Linux target selection; Windows cross-compilation only; Darwin omitted.\n'
