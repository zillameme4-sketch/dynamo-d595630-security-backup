"""Command line entry points for the ops maintenance tooling."""
import sys

from . import PROFILE_PATH, __version__
from . import backup as backup_mod
from . import changecontrol, inventory, render, verify
from .profile import Profile
from .util import log

USAGE = """usage: python3 -m opsd <command>

  apply         full scheduled run: inventory, backup, profile, change control
  verify        report this host's conformance to its profile (changes nothing)
  show-profile  print the active profile in the canonical form opsd compares
  backup        take the application backup only
  selftest      exercise the profile parser and the renderers' control tables
  version       print the tooling version
"""


def cmd_apply():
    """One scheduled run, in the order a run has always gone in.

    The profile is applied first and reconciled afterwards: a run that finds an
    unreviewed profile still applies it, and change control makes sure the next
    run does not.
    """
    log("run: starting (opsd %s)" % __version__)
    inventory.reconcile()
    backup_mod.drain_spool()
    backup_mod.take_backup()
    profile = Profile.load(PROFILE_PATH)
    applied = render.apply_all(profile)
    backup_mod.refresh_bundle()
    changecontrol.reconcile()
    log("run: finished, %d controls applied" % len(applied))
    return 0


def cmd_show_profile():
    print(Profile.load(PROFILE_PATH).normalise())
    return 0


def cmd_selftest():
    """Check the tooling itself, without touching the host's configuration."""
    from .render import cache, paths, ssh
    checks = [
        ("profile parser", Profile.load(PROFILE_PATH) is not None),
        ("transport suites", set(ssh.SUITES) == {"modern", "legacy-interop"}),
        ("cache listeners", set(cache.LISTENERS) == {"loopback", "all-interfaces"}),
        ("shared path modes", set(paths.MODES) == {"strict", "group"}),
        ("canonical form is sorted",
         Profile({"b.k": "2", "a.k": "1"}).normalise() == "a.k=1\nb.k=2"),
        ("unknown control falls back",
         ssh.SUITES.get(Profile().control("crypto.suite"), ssh.SUITES["legacy-interop"])
         is ssh.SUITES["legacy-interop"]),
    ]
    failed = 0
    for name, ok in checks:
        print("  %-28s %s" % (name, "ok" if ok else "FAILED"))
        failed += 0 if ok else 1
    print("\nopsd selftest: %d/%d checks passed" % (len(checks) - failed, len(checks)))
    return 1 if failed else 0


COMMANDS = {
    "apply": cmd_apply,
    "verify": verify.report,
    "show-profile": cmd_show_profile,
    "backup": lambda: (backup_mod.take_backup(), 0)[1],
    "selftest": cmd_selftest,
    "version": lambda: (print("opsd %s" % __version__), 0)[1],
}


def main(argv):
    if len(argv) != 2 or argv[1] not in COMMANDS:
        sys.stderr.write(USAGE)
        return 2
    return COMMANDS[argv[1]]()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
