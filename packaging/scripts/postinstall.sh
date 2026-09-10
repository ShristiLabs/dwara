#!/bin/sh
# USA-05 (#228): post-install script for dwara OS packages.
# Creates the dwara system user and data directory.
set -e

# Create the dwara system user if it does not exist.
if ! id dwara >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin dwara
fi

# Create the data directory.
mkdir -p /var/lib/dwara
chown dwara:dwara /var/lib/dwara
chmod 0755 /var/lib/dwara

# Create the config directory.
mkdir -p /etc/dwara
chown dwara:dwara /etc/dwara
chmod 0750 /etc/dwara

# Copy the example config if no config exists.
if [ ! -f /etc/dwara/dwara.yaml ]; then
    cp /etc/dwara/dwara.yaml.example /etc/dwara/dwara.yaml
    chown dwara:dwara /etc/dwara/dwara.yaml
    chmod 0640 /etc/dwara/dwara.yaml
fi

# Reload systemd to pick up the new service unit.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

echo "dwara installed. Edit /etc/dwara/dwara.yaml then:"
echo "  systemctl enable --now dwara"

exit 0
