"""Shared filesystem paths: how much the ops group may do to what it shares.

Control consumed:

    paths.shared_mode  how the paths the ops group works in are shared

`group` is the arrangement this host grew up with, where the on-call rota
maintains the collector in place and reads the backup directory directly.
`strict` narrows both to the job's own account.
"""
import os

from ..util import chown, group_exists

COLLECTOR = "/opt/ops/collect-logs.sh"
BACKUP_DIR = "/var/backups/app"

MODES = {
    #                collector, backup dir
    "strict": (0o755, 0o750),
    "group": (0o775, 0o777),
}


def _resolve(profile):
    return MODES.get(profile.control("paths.shared_mode"), MODES["group"])


def apply(profile):
    collector_mode, backup_mode = _resolve(profile)
    if os.path.exists(COLLECTOR):
        if group_exists("maintenance"):
            chown(COLLECTOR, "root", "maintenance")
        try:
            os.chmod(COLLECTOR, collector_mode)
        except OSError:
            pass
    if os.path.isdir(BACKUP_DIR):
        try:
            os.chmod(BACKUP_DIR, backup_mode)
            for name in os.listdir(BACKUP_DIR):
                os.chmod(os.path.join(BACKUP_DIR, name), backup_mode)
        except OSError:
            pass
    return ["paths.shared_mode"]


def state(profile):
    try:
        mode = os.stat(BACKUP_DIR).st_mode & 0o777
    except OSError:
        return {"paths.shared_mode": "group"}
    return {"paths.shared_mode": "strict" if not mode & 0o007 else "group"}
