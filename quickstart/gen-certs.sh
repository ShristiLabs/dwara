#!/bin/sh
# Quickstart TLS material (DW-026): self-signed certificate for localhost
# plus a client CA and client certificate for the admin API's mTLS.
# The gateway terminates TLS with the server pair; curl then trusts it
# via --cacert. The client CA + client cert let curl authenticate to the
# mTLS-only admin API (--cert client.crt --key client.key). NOT for
# production — a real deployment brings its own CA (e.g. Let's Encrypt,
# an internal CA, or the admin API's cert workflow).
#
# Ownership: docker-compose.yml runs the gateway as the nonroot UID/GID
# 65532, so on Linux the bind-mounted certs must be readable by that UID.
# When run as root/sudo this script hands certs/ over directly; otherwise
# it prints the chown to run. On macOS, Docker Desktop's VirtioFS share
# maps host ownership into the VM, so no chown is needed there.
set -eu
cd "$(dirname "$0")"
mkdir -p certs
# Private keys stay owner-only (umask + explicit chmod belt-and-braces);
# certificates are public material (served to every TLS client).
umask 077

# --- Server certificate (TLS termination) ---
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout certs/server.key -out certs/server.crt \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
chmod 600 certs/server.key
chmod 644 certs/server.crt

# --- Client CA + client certificate (admin API mTLS) ---
# The client CA signs the client cert; the gateway trusts the CA
# (admin.tls.client_ca_file) and the curl client presents the signed
# cert (admin.tls requires mutual TLS — no plaintext admin).
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout certs/client-ca.key -out certs/client-ca.crt \
  -subj "/CN=dwara-quickstart-client-ca"
openssl req -newkey rsa:2048 -nodes \
  -keyout certs/client.key -out certs/client.csr \
  -subj "/CN=dwara-admin-client"
openssl x509 -req -in certs/client.csr \
  -CA certs/client-ca.crt -CAkey certs/client-ca.key \
  -CAcreateserial -days 365 -out certs/client.crt
chmod 600 certs/client.key certs/client-ca.key
chmod 644 certs/client.crt certs/client-ca.crt
rm -f certs/client.csr certs/client-ca.srl
case "$(uname)" in
  Linux)
    # 0755 on the dir gives traversal only (no listing); the key itself
    # stays 0600 and becomes readable by the container once owned by
    # 65532. Never make the key world-readable instead of doing this.
    chmod 755 certs
    if chown -R 65532:65532 certs 2>/dev/null; then
      echo "wrote certs/ (server + client CA + client cert, owned by 65532:65532)"
    else
      echo "wrote certs/ (server + client CA + client cert)" >&2
      echo "Linux hosts: sudo chown -R 65532:65532 certs" >&2
      echo "(docker compose runs the gateway as 65532:65532; keys stay 0600)" >&2
    fi
    ;;
  *)
    echo "wrote certs/ (server + client CA + client cert)"
    ;;
esac
