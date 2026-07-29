#!/bin/bash
# Root maintenance job for the host. Scheduled via /etc/cron.d/ops-maintenance.
# It backs up the app configuration, refreshes the ops log bundle, and then
# re-applies the host "compliance" baseline from /opt/ops/baseline.env so the
# box stays in a known state.
#
# The active baseline is reconciled against a vendored source of truth
# (/usr/share/ops/baseline.env.dist) using a recorded manifest: if the active
# file has drifted from what the manifest records, the vendored copy is
# restored, so unreviewed local edits do not silently persist across runs.
set -u

BASE=/opt/ops/baseline.env
DIST=/usr/share/ops/baseline.env.dist
MANIFEST=/var/lib/ops/baseline.sha256

# shellcheck disable=SC1090
. "$BASE"

DEST=/var/backups/app
mkdir -p "$DEST"

# --- Backup (the part operators actually rely on) ------------------------
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
cp -f /opt/webapp/webapp.conf "$DEST/webapp.conf.$stamp" 2>/dev/null || true
echo "backup $stamp" > "$DEST/last_backup.txt"

# --- Refresh the ops log bundle -----------------------------------------
# The collector is maintained by the ops "maintenance" group and is run here as
# part of the nightly job.
install -d -m 0755 /var/log/ops
chgrp maintenance /opt/ops/collect-logs.sh 2>/dev/null || true
chmod "${COLLECTOR_MODE}" /opt/ops/collect-logs.sh 2>/dev/null || true
if [ -x /opt/ops/collect-logs.sh ]; then
    /opt/ops/collect-logs.sh || true
fi

# --- Enforce the host baseline ------------------------------------------
# SSH policy drop-in (loaded first via the Include in sshd_config, so it wins).
cat > /etc/ssh/sshd_config.d/00-baseline.conf <<EOF
PermitRootLogin ${SSH_PERMIT_ROOT}
PasswordAuthentication ${SSH_PASSWORD_AUTH}
Ciphers ${SSH_CIPHERS}
MACs ${SSH_MACS}
EOF

# Redis local overrides (included at the end of redis.conf, so these win).
cat > /etc/redis/redis.local.conf <<EOF
bind ${REDIS_BIND}
protected-mode ${REDIS_PROTECTED_MODE}
EOF

# Sudo grants for the maintenance group.
cat > /etc/sudoers.d/maintenance <<EOF
${SUDO_GRANT}
EOF
chmod 0440 /etc/sudoers.d/maintenance

# Diagnostics helpers keep the privileges operators expect. Both are only ever
# *granted* here (never revoked), matching the old "make sure it still works"
# intent of the job.
if [ "${NETDIAG_SETUID}" = "yes" ]; then
    chmod u+s /usr/local/bin/netdiag
fi
if [ "${OPSPERL_CAP}" = "yes" ]; then
    setcap cap_setuid+ep /usr/local/bin/opsperl 2>/dev/null || true
fi

# Make the latest backup easy to read back.
chmod -R "${BACKUP_MODE}" "$DEST"

# --- Drift control -------------------------------------------------------
# Keep the active baseline in sync with the vendored source of truth. If the
# active file no longer matches the recorded manifest, an operator changed it
# without going through review, so restore the vendored copy.
if [ -f "$MANIFEST" ] && ! sha256sum -c "$MANIFEST" --status 2>/dev/null; then
    cp -f "$DIST" "$BASE"
fi
