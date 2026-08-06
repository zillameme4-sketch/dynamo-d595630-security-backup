"""SSH: remote administration, credential policy and transport primitives.

Controls consumed:

    access.remote_admin       who may open an administrative session
    access.credential_policy  what the server accepts as proof of identity
    access.legacy_clients     the standing exemption for the datacentre range
    crypto.suite              which transport primitives are offered

The first three are separate controls because they were signed off separately;
the exemption in particular predates the credential policy and was renewed on
its own ticket, so it is carried on its own key.

opsd owns /etc/ssh/sshd_config.d entirely. The Include at the top of
sshd_config loads that directory ahead of the rest of the main file, so anything
in there that opsd did not put there is an unmanaged override; the directory is
emptied before the managed drop-in is written.
"""
import glob
import os
import re

from ..util import log, read, write

DROPIN_DIR = "/etc/ssh/sshd_config.d"
DROPIN = DROPIN_DIR + "/00-baseline.conf"
MAIN = "/etc/ssh/sshd_config"

EXEMPTION_MARK = "# --- legacy client exemption (managed by opsd) ---"
EXEMPTION_RANGE = "10.0.0.0/8"

SUITES = {
    "modern": {
        "ciphers": ("chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,"
                    "aes128-gcm@openssh.com,aes256-ctr"),
        "macs": ("hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,"
                 "umac-128-etm@openssh.com"),
        "kex": ("curve25519-sha256,curve25519-sha256@libssh.org,"
                "ecdh-sha2-nistp256,diffie-hellman-group16-sha512"),
    },
    "legacy-interop": {
        "ciphers": "aes256-ctr,aes128-ctr,aes256-cbc,aes128-cbc,3des-cbc",
        "macs": "hmac-sha2-256,hmac-sha1,hmac-md5,hmac-sha1-96",
        "kex": ("curve25519-sha256,diffie-hellman-group14-sha256,"
                "diffie-hellman-group14-sha1"),
    },
}


def _resolve(profile):
    permit_root = "no" if profile.control("access.remote_admin") == "restricted" else "yes"
    password_auth = "no" if profile.control("access.credential_policy") == "keys-only" else "yes"
    exemption = profile.control("access.legacy_clients") != "denied"
    suite = SUITES.get(profile.control("crypto.suite"), SUITES["legacy-interop"])
    return permit_root, password_auth, exemption, suite


def _strip_exemption(text):
    """Drop the managed block from the tail of the main configuration."""
    index = text.find(EXEMPTION_MARK)
    return text if index < 0 else text[:index]


def apply(profile):
    permit_root, password_auth, exemption, suite = _resolve(profile)

    for stale in glob.glob(DROPIN_DIR + "/*.conf"):
        try:
            os.unlink(stale)
        except OSError:
            log("ssh: could not clear the unmanaged drop-in %s" % stale)
    write(DROPIN,
          "PermitRootLogin %s\n"
          "PasswordAuthentication %s\n"
          "Ciphers %s\n"
          "MACs %s\n"
          "KexAlgorithms %s\n"
          % (permit_root, password_auth, suite["ciphers"], suite["macs"], suite["kex"]))

    # The exemption has to sit at the end of the main file. A Match block runs
    # to the end of whatever file it appears in, so from the drop-in -- which is
    # Included at the top -- it would swallow every directive after it, several
    # of which are not permitted inside a Match block at all.
    body = _strip_exemption(read(MAIN))
    if not body.endswith("\n"):
        body += "\n"
    if exemption:
        body += ("%s\nMatch Address %s\n    PasswordAuthentication yes\n"
                 % (EXEMPTION_MARK, EXEMPTION_RANGE))
    write(MAIN, body)

    return ["access.remote_admin", "access.credential_policy",
            "access.legacy_clients", "crypto.suite"]


def state(profile):
    """Read the managed drop-in back, the way an auditor reads `sshd -T`."""
    dropin = read(DROPIN)
    body = read(MAIN)

    def directive(name):
        match = re.search(r"(?mi)^\s*%s\s+(\S+)" % name, dropin)
        return match.group(1) if match else "(unset)"

    weak = SUITES["legacy-interop"]["ciphers"].split(",")[-1]
    return {
        "access.remote_admin": "restricted" if directive("PermitRootLogin") == "no" else "permissive",
        "access.credential_policy": ("keys-only" if directive("PasswordAuthentication") == "no"
                                     else "legacy"),
        "access.legacy_clients": "denied" if EXEMPTION_MARK not in body else "allowed",
        "crypto.suite": "legacy-interop" if weak in dropin else "modern",
    }
