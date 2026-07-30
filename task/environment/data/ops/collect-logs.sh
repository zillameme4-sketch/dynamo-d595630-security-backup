#!/bin/bash
# Collect a small bundle of operational metadata into /var/log/ops.
# Invoked by the root maintenance job (/opt/ops/maintenance.sh) on every run.
set -u

OUT=/var/log/ops/bundle.txt
{
    echo "collected $(date -u +%Y%m%dT%H%M%SZ)"
    df -h / 2>/dev/null | tail -1
    echo "recent backups:"
    ls -1t /var/backups/app 2>/dev/null | head -5
} > "$OUT" 2>/dev/null || true

# The bundle carries host detail, so it is readable by the ops group only --
# that group membership is how the on-call operators get at it.
chown root:maintenance "$OUT" 2>/dev/null || true
chmod 0640 "$OUT" 2>/dev/null || true
