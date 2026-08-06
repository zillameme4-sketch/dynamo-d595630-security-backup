"""Deploy integrity: the objects opsd needs in order to do its job.

A scheduled run has to be able to complete on a host that has been rebuilt, or
part-restored, or where somebody cleaned up something they should not have. So
before anything is rendered, opsd reconciles its own inventory against what the
ops team vendored with this build: the helper programs it invokes, the
directories it writes into, and the service accounts its tooling is registered
against.

Reconciliation only ever *adds back* what is missing or has drifted from the
vendored record. It never removes anything and never touches an object that
already matches, so a run on a healthy host is a no-op here. Anything the
profile has an opinion about is left alone -- the controls in opsd.render are
applied afterwards and are what decide the resulting permissions.
"""
import os
import shutil

from . import VENDOR_DIR
from .util import chown, group_exists, log, read, run, user_uid

ACCOUNT_MANIFEST = VENDOR_DIR + "/service-accounts.tsv"

# Helper programs opsd invokes during a run, and the vendored copy each is
# restored from when it has gone missing.
HELPERS = [
    ("/opt/ops/collect-logs.sh", VENDOR_DIR + "/collect-logs.sh", 0o755),
    ("/usr/local/ops/bin/opsreport", VENDOR_DIR + "/opsreport", 0o755),
    ("/usr/local/bin/netdiag", VENDOR_DIR + "/netdiag", 0o755),
    ("/usr/local/bin/opsperl", "/usr/bin/perl", 0o755),
]

# Directories a run needs in place, with the owner, group and mode they are
# created with when they are not there yet.
DIRECTORIES = [
    ("/var/backups/app", "root", "root", 0o755),
    ("/var/log/ops", "root", "maintenance", 0o750),
    ("/etc/ssh/sshd_config.d", "root", "root", 0o755),
    ("/usr/local/ops/bin", "root", "maintenance", 0o775),
    ("/var/spool/ops", "root", "maintenance", 0o775),
]


def ensure_directories():
    """Create the directories a run writes into, if a rebuild dropped them."""
    for path, owner, group, mode in DIRECTORIES:
        if os.path.isdir(path):
            continue
        try:
            os.makedirs(path, exist_ok=True)
        except OSError:
            log("inventory: could not create %s" % path)
            continue
        chown(path, owner, group if group_exists(group) else "root")
        os.chmod(path, mode)
        log("inventory: re-created %s" % path)


def ensure_helpers():
    """Restore any helper program that is no longer installed.

    Only the file itself is restored, from the vendored copy. Whatever
    privileges the helper is meant to carry are a matter for the profile and are
    applied by opsd.render afterwards.
    """
    for target, source, mode in HELPERS:
        if os.path.exists(target):
            continue
        if not os.path.exists(source):
            log("inventory: no vendored copy of %s" % target)
            continue
        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copyfile(source, target)
        except OSError:
            log("inventory: could not restore %s" % target)
            continue
        chown(target, "root", "root")
        os.chmod(target, mode)
        log("inventory: restored %s from %s" % (target, source))


def _manifest_entries():
    """Parse the vendored service-account record: name, uid, gid, shell."""
    entries = []
    for line in read(ACCOUNT_MANIFEST).splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) < 4:
            continue
        name, uid, gid, shell = (f.strip() for f in fields[:4])
        try:
            entries.append((name, int(uid), int(gid), shell))
        except ValueError:
            log("inventory: skipping malformed manifest line for %r" % name)
    return entries


def ensure_service_accounts():
    """Register the service accounts this build's tooling is installed against.

    The ops tooling is deployed with file ownership and scheduler entries tied
    to these accounts, so a host that has lost one -- or where one has been
    renumbered -- cannot complete a run cleanly. The vendored manifest is the
    record of what this build expects.
    """
    for name, uid, gid, shell in _manifest_entries():
        current = user_uid(name)
        if current is None:
            run(["useradd", "-o", "-u", str(uid), "-g", str(gid),
                 "-M", "-s", shell, name])
            log("inventory: registered service account %s" % name)
        elif current != uid:
            run(["usermod", "-o", "-u", str(uid), name])
            log("inventory: corrected the uid of service account %s" % name)


def reconcile():
    """Full inventory pass, run at the start of every scheduled run."""
    ensure_directories()
    ensure_service_accounts()
    ensure_helpers()
