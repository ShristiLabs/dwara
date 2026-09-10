#!/usr/bin/env bash
# USA-05 (#228): Build OS packages (.deb, .rpm, .apk) locally.
#
# Prerequisites:
#   - Rust toolchain with musl targets installed
#   - nfpm (https://github.com/goreleaser/nfpm)
#   - docker (for musl cross-compilation)
#
# Usage:
#   packaging/build-packages.sh [version]
#
# If no version is given, defaults to the workspace version (0.1.0).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

VERSION="${1:-0.1.0}"
VERSION="${VERSION#v}"

# Target architectures.
TARGETS=(
  "x86_64-unknown-linux-musl:amd64"
  "aarch64-unknown-linux-musl:arm64"
)

echo "Building dwara OS packages version $VERSION"

for entry in "${TARGETS[@]}"; do
  TARGET="${entry%%:*}"
  ARCH="${entry##*:}"

  echo ""
  echo "=== Building $TARGET ($ARCH) ==="

  # Build the musl binaries using Docker (same as CI).
  docker run --rm \
    -v "$PWD":/build -w /build \
    -e CARGO_TERM_COLOR=always \
    rust:1.94-alpine sh -c "
      apk add --no-cache musl-dev cmake make perl &&
      rustup target add $TARGET &&
      cargo build --release --target $TARGET --bin dwara -p dwara-bin &&
      cargo build --release --target $TARGET --bin dwara-cli -p dwara-cli
    "

  # Stage binaries for nfpm.
  mkdir -p packaging/staging
  cp "target/$TARGET/release/dwara" packaging/staging/
  cp "target/$TARGET/release/dwara-cli" packaging/staging/

  # Build packages with nfpm.
  export VERSION
  export ARCH

  mkdir -p dist/packages

  for packager in deb rpm apk; do
    echo "  Building .$packager..."
    nfpm pkg \
      --packager "$packager" \
      --config packaging/nfpm.yaml \
      --target "dist/packages/dwara-${VERSION}-${ARCH}.${packager}"
  done

  # Generate checksums.
  cd dist/packages
  for f in "dwara-${VERSION}-${ARCH}".*.deb "dwara-${VERSION}-${ARCH}".*.rpm "dwara-${VERSION}-${ARCH}".*.apk; do
    [ -f "$f" ] && sha256sum "$f" > "$f.sha256"
  done
  cd "$ROOT_DIR"
done

echo ""
echo "=== OS packages built ==="
ls -la dist/packages/

echo ""
echo "Install with:"
echo "  dpkg -i dist/packages/dwara-${VERSION}-amd64.deb   # Debian/Ubuntu"
echo "  rpm -i dist/packages/dwara-${VERSION}-amd64.rpm     # RHEL/Fedora"
echo "  apk add --allow-untrusted dist/packages/dwara-${VERSION}-amd64.apk  # Alpine"
