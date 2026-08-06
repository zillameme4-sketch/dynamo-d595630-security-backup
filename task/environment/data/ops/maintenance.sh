#!/bin/bash
# Root maintenance job for the host. Scheduled via /etc/cron.d/ops-maintenance.
#
# The work itself is in the ops tooling installed alongside this script; this
# wrapper only sets up the environment a scheduled run needs and hands over.
#
#   python3 -m opsd verify        what this host currently conforms to
#   python3 -m opsd show-profile  the active profile, canonicalised
#
set -u

# The ops team's own helper tooling is installed alongside the job and resolved
# through PATH, ahead of the system directories.
PATH=/usr/local/ops/bin:$PATH
export PATH

export PYTHONPATH=/opt/ops
exec python3 -m opsd apply
