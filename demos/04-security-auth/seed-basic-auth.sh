#!/bin/bash
# seed-basic-auth.sh — Seed a Basic-auth credential into the gateway state DB.
#
# Basic auth credentials are store-managed in dwara (not config-declared):
# the username is the lookup selector (hex(sha256(username))) and the
# password is hashed through the same path as API keys
# (sha256:<hex(sha256(password))>). This script inserts the demo
# credential (admin:secret123) for the basic-user consumer into the
# state DB after the gateway has started and seeded the consumer.
#
# The state DB is at ./data/state.db (mounted from /var/lib/dwara in
# the container). The gateway's in-memory credential cache is populated
# lazily on first lookup, so inserting before any Basic auth request
# ensures the first lookup reads from disk and finds the credential.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB="${SCRIPT_DIR}/data/state.db"
USERNAME="admin"
PASSWORD="secret123"
CONSUMER="basic-user"

echo "=== seed-basic-auth ==="

# Wait for the gateway to be ready (consumer must exist in the store).
source "${SCRIPT_DIR}/../_shared/helpers.sh"
wait_for http://localhost:8080/public/ 30 || {
  echo "ERROR: gateway not ready, cannot seed Basic credential"
  exit 1
}

# Wait for the state DB to exist.
for i in $(seq 1 10); do
  if [ -f "$DB" ]; then
    break
  fi
  sleep 1
done
if [ ! -f "$DB" ]; then
  echo "ERROR: state DB not found at $DB"
  exit 1
fi

# Insert the Basic credential using Python3 (sqlite3 + hashlib built-in).
# selector = hex(sha256("admin"))     — the username
# hash     = sha256:<hex(sha256("secret123"))>  — the password (unpeppered)
python3 - "$DB" "$USERNAME" "$PASSWORD" "$CONSUMER" <<'PYEOF'
import hashlib
import sqlite3
import sys
import time

db_path = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]
consumer_name = sys.argv[4]

# Compute the selector: hex(sha256(username))
selector = hashlib.sha256(username.encode()).hexdigest()

# Compute the stored hash: sha256:<hex(sha256(password))>
password_hash = "sha256:" + hashlib.sha256(password.encode()).hexdigest()

now = int(time.time())

conn = sqlite3.connect(db_path)

# Look up the consumer ID.
row = conn.execute(
    "SELECT id FROM consumers WHERE name = ?", (consumer_name,)
).fetchone()
if row is None:
    print(f"ERROR: consumer '{consumer_name}' not found in state DB")
    conn.close()
    sys.exit(1)

consumer_id = row[0]

# Check if the credential already exists (idempotent).
existing = conn.execute(
    "SELECT id FROM credentials WHERE consumer_id = ? AND selector = ? AND revoked_at IS NULL",
    (consumer_id, selector),
).fetchone()

if existing is not None:
    print(f"Basic credential for '{consumer_name}' (username: {username}) already seeded (id={existing[0]})")
else:
    conn.execute(
        "INSERT INTO credentials (consumer_id, kind, hash, salt, selector, created_at, source_ref) "
        "VALUES (?, ?, ?, NULL, ?, ?, NULL)",
        (consumer_id, "api_key", password_hash, selector, now),
    )
    conn.commit()
    print(f"Seeded Basic credential for '{consumer_name}' (username: {username}, id={conn.lastrowid})")

conn.close()
PYEOF

echo "Basic auth credential seeded: ${USERNAME}:*** (consumer: ${CONSUMER})"
