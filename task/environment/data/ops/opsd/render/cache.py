"""Redis: where the cache listens and what it asks callers for.

Controls consumed:

    cache.listener  which addresses the cache accepts connections on
    cache.auth      the shared secret every caller on this host presents

The secret is carried in the profile rather than in redis.conf so that the whole
host converges on one value: the cache and anything configured to talk to it are
both rebuilt from the same control, and a rebuild cannot leave the two out of
step. `none` is what this host has always shipped with.

The rendered file is pulled in by the `include` at the end of redis.conf, which
is read after the rest of it.
"""
import re

from ..util import read, write

LOCAL_CONF = "/etc/redis/redis.local.conf"

LISTENERS = {
    "loopback": ("127.0.0.1 -::1", "yes"),
    "all-interfaces": ("0.0.0.0", "no"),
}


def _resolve(profile):
    bind, protected = LISTENERS.get(profile.control("cache.listener"),
                                    LISTENERS["all-interfaces"])
    secret = profile.control("cache.auth")
    if secret in ("", "none"):
        secret = ""
    return bind, protected, secret


def apply(profile):
    bind, protected, secret = _resolve(profile)
    write(LOCAL_CONF,
          "# Rendered by opsd from the host profile. Do not edit.\n"
          "bind %s\n"
          "protected-mode %s\n"
          "requirepass \"%s\"\n" % (bind, protected, secret))
    return ["cache.listener", "cache.auth"]


def state(profile):
    text = read(LOCAL_CONF)
    bind = re.search(r"(?m)^\s*bind\s+(.*)$", text)
    secret = re.search(r"(?m)^\s*requirepass\s+\"(.*)\"\s*$", text)
    listener = "all-interfaces"
    if bind and bind.group(1).strip().startswith("127.0.0.1"):
        listener = "loopback"
    return {
        "cache.listener": listener,
        "cache.auth": "none" if not (secret and secret.group(1)) else secret.group(1),
    }
