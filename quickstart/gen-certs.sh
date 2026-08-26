#!/bin/sh
# Quickstart TLS material (DW-026): self-signed certificate for localhost.
# The gateway terminates TLS with this pair; curl then trusts it via
# --cacert. NOT for production — a real deployment brings its own CA
# (e.g. Let's Encrypt, an internal CA, or the admin API's cert workflow).
#
# Ownership: docker-compose.yml runs the gateway as the nonroot UID/GID
# 65532, so on Linux the bind-mounted certs must be readable by that UID.
# When run as root/sudo this script hands certs/ over directly; otherwise
# it prints the chown to run. On macOS, Docker Desktop's VirtioFS share
# maps host ownership into the VM, so no chown is needed there.
set -eu
cd "$(dirname "$0")"
mkdir -p certs
# Private key stays owner-only (umask + explicit chmod belt-and-braces);
# the certificate is public material (served to every TLS client).
umask 077
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout certs/server.key -out certs/server.crt \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
chmod 600 certs/server.key
chmod 644 certs/server.crt
case "$(uname)" in
  Linux)
    # 0755 on the dir gives traversal only (no listing); the key itself
    # stays 0600 and becomes readable by the container once owned by
    # 65532. Never make the key world-readable instead of doing this.
    chmod 755 certs
    if chown -R 65532:65532 certs 2>/dev/null; then
      echo "wrote certs/server.crt and certs/server.key (owned by 65532:65532)"
    else
      echo "wrote certs/server.crt and certs/server.key" >&2
      echo "Linux hosts: sudo chown -R 65532:65532 certs" >&2
      echo "(docker compose runs the gateway as 65532:65532; key stays 0600)" >&2
    fi
    ;;
  *)
    echo "wrote certs/server.crt and certs/server.key"
    ;;
esac
