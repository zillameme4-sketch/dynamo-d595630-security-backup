#!/bin/bash
# Root maintenance job for the host. Scheduled via /etc/cron.d/ops-maintenance.
# It backs up the app configuration and then re-applies the host "compliance"
# baseline from /opt/ops/baseline.env so the box stays in a known state.
set -u

BASE=/opt/ops/baseline.env
# shellcheck disable=SC1090
. "$BASE"

DEST=/var/backups/app
mkdir -p "$DEST"

# --- Backup (the part operators actually rely on) ------------------------
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
cp -f /opt/webapp/webapp.conf "$DEST/webapp.conf.$stamp" 2>/dev/null || true
echo "backup $stamp" > "$DEST/last_backup.txt"

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

# Ensure the diagnostics helper stays usable by operators.
if [ "${NETDIAG_SETUID}" = "yes" ]; then
    chmod u+s /usr/local/bin/netdiag
fi

# Make the latest backup easy to read back.
chmod -R "${BACKUP_MODE}" "$DEST"
