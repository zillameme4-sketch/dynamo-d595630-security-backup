"""Change control over the host compatibility profile.

The settings signed off for this host are not carried here as text. What is
recorded is APPROVED_DIGEST: the SHA-256 of the profile's canonical form (see
opsd.profile.normalise). The review process publishes that digest when a change
is approved, and the vendored copy of the profile is refreshed at the same time,
so the two always agree on a host that is in its reviewed state.

A profile whose digest does not match was edited outside review. Reconciliation
puts the vendored copy back if the vendored copy is itself approved, and
otherwise falls back to the profile this build was shipped with, so the host
converges on a reviewed configuration whichever file was touched. It runs at the
*end* of a maintenance run: an unreviewed profile is still applied for the run
that finds it, and is gone by the next one.
"""
import hashlib
import shutil

from . import DIST_PATH, PROFILE_PATH, VENDOR_DIR
from .profile import normalise_file
from .util import log

APPROVED_DIGEST = "a81272342ab42ff362732f823a24e0781dd7c791520a09964618b44c9d3f919a"

FALLBACK_PROFILE = VENDOR_DIR + "/host-profile.shipped"


def digest(path):
    """SHA-256 of the canonical form of the profile stored at `path`."""
    return hashlib.sha256(normalise_file(path).encode()).hexdigest()


def is_approved(path):
    return digest(path) == APPROVED_DIGEST


def reconcile():
    """Roll an unreviewed profile back. Returns True if the profile was replaced."""
    if is_approved(PROFILE_PATH):
        return False
    source = DIST_PATH if is_approved(DIST_PATH) else FALLBACK_PROFILE
    try:
        shutil.copyfile(source, PROFILE_PATH)
    except OSError:
        log("change control: could not restore the profile from %s" % source)
        return False
    log("change control: profile did not match the approved digest, restored from %s"
        % source)
    return True
