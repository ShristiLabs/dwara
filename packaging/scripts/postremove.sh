#!/bin/sh
# USA-05 (#228): post-remove script for dwara OS packages.
# Removes the systemd unit and optionally the data directory.
set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

echo "dwara removed. Data directory /var/lib/dwara preserved."
echo "Remove it manually if no longer needed: rm -rf /var/lib/dwara"

exit 0
