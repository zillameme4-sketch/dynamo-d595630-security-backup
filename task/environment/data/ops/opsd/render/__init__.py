"""Translating profile controls into the concrete configuration on this host.

Each module here owns one area of the host and exposes `apply(profile)`, which
rewrites that area's managed files from the controls it is interested in, and
`state()`, which reports back what the host currently looks like for those same
controls. `verify` uses the second to report conformance without changing
anything.

A renderer is deliberately tolerant: a control it does not recognise resolves to
the legacy-compatible behaviour this host has always had, so an unfamiliar or
mistyped value degrades to the old behaviour rather than failing a run.
"""
from . import cache, paths, privs, ssh

MODULES = (ssh, cache, privs, paths)


def apply_all(profile):
    """Render every managed area from `profile`. Returns the applied controls."""
    applied = []
    for module in MODULES:
        applied.extend(module.apply(profile))
    return applied


def state_all(profile):
    """What the host currently looks like, per control."""
    state = {}
    for module in MODULES:
        state.update(module.state(profile))
    return state
