#!/bin/sh
# Wrapper around quickstart/gen-certs.sh — generates TLS certs for demos.
# Reuses the same cert set so demos are compatible with the quickstart.
set -eu
cd "$(dirname "$0")"
SCRIPT_DIR="$(pwd)"
CERTS_DIR="$SCRIPT_DIR/certs"

# Symlink to the quickstart gen-certs.sh
QUICKSTART_GEN="$(cd "$SCRIPT_DIR/../../quickstart" && pwd)/gen-certs.sh"

if [ ! -f "$QUICKSTART_GEN" ]; then
  echo "ERROR: quickstart/gen-certs.sh not found at $QUICKSTART_GEN"
  exit 1
fi

# Run gen-certs in the quickstart dir (it writes to ./certs relative to itself)
QUICKSTART_DIR="$(dirname "$QUICKSTART_GEN")"
( cd "$QUICKSTART_DIR" && sh gen-certs.sh )

# Symlink the certs into our shared dir
ln -sfn "$QUICKSTART_DIR/certs" "$CERTS_DIR"
echo "certs available at $CERTS_DIR"
