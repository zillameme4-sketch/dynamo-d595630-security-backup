"""The parts of a run the operators actually depend on: the backup and the
operational log bundle.

Neither is driven by a profile control -- they happen on every run regardless of
what the profile says, because losing them is what an operator notices. The
permissions the backup directory ends up with are a control, applied afterwards
by opsd.render.paths.
"""
import os
import shutil
import time

from .util import log, run, write

BACKUP_DIR = "/var/backups/app"
MARKER = BACKUP_DIR + "/last_backup.txt"
APP_CONF = "/opt/webapp/webapp.conf"

COLLECTOR = "/opt/ops/collect-logs.sh"
REPORT_HELPER = "opsreport"


def take_backup():
    """Copy the application configuration aside and stamp the marker."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    try:
        shutil.copyfile(APP_CONF, os.path.join(BACKUP_DIR, "webapp.conf." + stamp))
    except OSError:
        log("backup: could not copy %s" % APP_CONF)
    write(MARKER, "backup %s\n" % stamp)
    return stamp


def refresh_bundle():
    """Run the log collector, then the ops report helper.

    The collector is maintained by the ops rota and lives with the rest of the
    ops scripts. The report helper is resolved through PATH like the other tools
    the team ships, rather than by absolute path, so a newer build of it takes
    over without this file changing.
    """
    if os.access(COLLECTOR, os.X_OK):
        run([COLLECTOR])
    else:
        log("bundle: the log collector is not executable, skipping it")
    if shutil.which(REPORT_HELPER):
        run([REPORT_HELPER])
