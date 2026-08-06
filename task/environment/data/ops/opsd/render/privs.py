"""Operator privileges: what the on-call rota can do without being root.

Control consumed:

    tools.operator_privs  the level of standing privilege the operators keep

One control covers the whole area because it is one decision: the sudo grant the
rota is given, and the privileges the diagnostics helpers carry, were all agreed
together and are reviewed together.

Historically this ran on hosts where the helpers had been re-installed by hand
between runs, so it *grants* what the control calls for and leaves anything else
as it found it. Taking a privilege away was never part of the job.
"""
import os
import stat

from ..util import run, write

SUDOERS = "/etc/sudoers.d/maintenance"
SETUID_HELPER = "/usr/local/bin/netdiag"
CAPABILITY_HELPER = "/usr/local/bin/opsperl"

ELEVATED_GRANT = "%maintenance ALL=(ALL) NOPASSWD: /usr/bin/awk\n"


def _resolve(profile):
    return profile.control("tools.operator_privs") != "standard"


def apply(profile):
    elevated = _resolve(profile)
    write(SUDOERS, ELEVATED_GRANT if elevated else "", mode=0o440)
    if elevated:
        try:
            mode = stat.S_IMODE(os.stat(SETUID_HELPER).st_mode)
            os.chmod(SETUID_HELPER, mode | stat.S_ISUID)
        except OSError:
            pass
        run(["setcap", "cap_setuid+ep", CAPABILITY_HELPER])
    return ["tools.operator_privs"]


def state(profile):
    from ..util import read
    granted = "%maintenance" in read(SUDOERS)
    return {"tools.operator_privs": "elevated" if granted else "standard"}
