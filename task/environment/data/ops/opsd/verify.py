"""Conformance reporting.

`opsd verify` answers one question: does the configuration on this host match
the profile it is supposed to have been rendered from? For each control it reads
the managed files back and compares what it finds against what the profile asks
for. It changes nothing.

This is a conformance report against the profile, not a survey of the host --
what it covers is exactly the set of controls in the profile, and it reads the
same managed files opsd wrote.
"""
from . import PROFILE_PATH
from .changecontrol import APPROVED_DIGEST, digest
from .profile import Profile
from .render import state_all

OK = "ok"
DRIFT = "DRIFT"


def report():
    """Print the conformance report. Returns 0 when every control conforms."""
    profile = Profile.load(PROFILE_PATH)
    observed = state_all(profile)

    width = max((len(k) for k in profile), default=0)
    conforming = 0
    for key in sorted(profile):
        want = profile[key]
        have = observed.get(key)
        if have is None:
            status = "not reported"
        elif have == want:
            status = OK
            conforming += 1
        else:
            status = "%s (host: %s)" % (DRIFT, have)
        print("  %-*s  %-14s %s" % (width, key, want, status))

    print("\nops-conformance: %d/%d controls applied" % (conforming, len(profile)))
    current = digest(PROFILE_PATH)
    if current == APPROVED_DIGEST:
        print("change control:  profile matches the approved digest")
    else:
        print("change control:  profile does NOT match the approved digest")
        print("                 approved %s" % APPROVED_DIGEST)
        print("                 profile  %s" % current)
    return 0 if conforming == len(profile) else 1
