"""Small shared helpers: process execution, file writing and the run log."""
import grp
import os
import pwd
import subprocess
import time

from . import LOG_PATH


def log(message):
    """Append a line to the maintenance run log, best effort."""
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a") as fh:
            fh.write("%s %s\n" % (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                  message))
        os.chmod(LOG_PATH, 0o640)
    except OSError:
        pass


def run(argv, check=False):
    """Run a command, swallowing its output. Returns the exit status."""
    try:
        proc = subprocess.run(argv, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, check=False)
    except OSError:
        return 127
    if check and proc.returncode != 0:
        log("command failed (%d): %s" % (proc.returncode, " ".join(argv)))
    return proc.returncode


def write(path, text, mode=0o644, owner="root", group="root"):
    """Write a managed configuration file with an explicit owner and mode.

    Managed files are rewritten in full on every run rather than patched, so a
    partially applied file from an interrupted run cannot survive.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)
    chown(path, owner, group)
    os.chmod(path, mode)


def read(path, default=""):
    try:
        with open(path) as fh:
            return fh.read()
    except OSError:
        return default


def chown(path, owner="root", group="root"):
    """chown by name, tolerating an account or group that is not present."""
    try:
        uid = pwd.getpwnam(owner).pw_uid
    except KeyError:
        uid = 0
    try:
        gid = grp.getgrnam(group).gr_gid
    except KeyError:
        gid = 0
    try:
        os.chown(path, uid, gid)
    except OSError:
        return False
    return True


def group_exists(name):
    try:
        grp.getgrnam(name)
        return True
    except KeyError:
        return False


def user_uid(name):
    """The uid of an account, or None if the account does not exist."""
    try:
        return pwd.getpwnam(name).pw_uid
    except KeyError:
        return None
