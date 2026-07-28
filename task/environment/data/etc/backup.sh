#!/bin/bash
# Nightly backup of the app cache configuration and a Redis snapshot marker.
# Invoked as root by /etc/cron.d/app-backup.
set -u

DEST=/var/backups/app
mkdir -p "$DEST"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
cp -f /opt/webapp/webapp.conf "$DEST/webapp.conf.$stamp" 2>/dev/null || true
echo "backup $stamp" > "$DEST/last_backup.txt"

# Make the snapshot easy for any operator to read back.
chmod -R 777 "$DEST"
