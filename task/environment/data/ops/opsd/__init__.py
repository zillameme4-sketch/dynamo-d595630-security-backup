"""opsd -- the ops team's host maintenance tooling.

This package is what /opt/ops/maintenance.sh runs. It is responsible for three
things on every scheduled run:

  * taking the application backup the operators rely on;
  * refreshing the operational log bundle;
  * re-applying the host compatibility profile, so the box stays in the state
    change control signed off on.

The profile lives at /etc/ops/host-profile.conf and is a flat key = value file.
Each key is a *control*: an ops-level statement of intent that this package
translates into whatever concrete configuration the services on this host need.
The translation lives in opsd.render; the profile itself never mentions a
service, a file path or a directive, which is deliberate -- the same profile is
carried across rebuilds while the underlying daemons change underneath it.

Change control is enforced in opsd.changecontrol: the settings approved for this
host are recorded as a digest, and a profile that does not match is treated as
an unreviewed local edit.

Entry points (see opsd.__main__):

    python3 -m opsd apply         full scheduled run
    python3 -m opsd verify        report the host's conformance to the profile
    python3 -m opsd show-profile  print the active profile as opsd reads it
    python3 -m opsd backup        take the backup only
    python3 -m opsd selftest      exercise the renderers against a scratch root
"""

__version__ = "3.4.2"

PROFILE_PATH = "/etc/ops/host-profile.conf"
DIST_PATH = "/usr/share/ops/host-profile.dist"
VENDOR_DIR = "/usr/share/ops/vendor"
LOG_PATH = "/var/log/ops/opsd.log"
