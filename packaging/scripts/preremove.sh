#!/bin/sh
# USA-05 (#228): pre-remove script for dwara OS packages.
# Stops the dwara service before removal.
set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop dwara || true
    systemctl disable dwara || true
fi

exit 0
