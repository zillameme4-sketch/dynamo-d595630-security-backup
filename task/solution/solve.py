#!/usr/bin/env python3
"""Reference hardening pass for the multi-service host.

The subtlety: a root maintenance job (/opt/ops/maintenance.sh -> the `opsd`
package in /opt/ops) re-applies a host compatibility profile on every scheduled
run, and the verifier runs it during grading. Editing only the live
configuration is silently reverted. Worse, opsd.changecontrol holds the SHA-256
of the profile it considers approved and, on any mismatch, restores the vendored
copy (/usr/share/ops/host-profile.dist) -- or, if that copy is not approved
either, the profile this build shipped with. So mirroring secure values across
the profile and the vendored copy is not enough: the recorded digest has to
agree, or the reconciliation has to be neutralised outright. opsd also owns
/etc/ssh/sshd_config.d, clearing any drop-in it did not place, so SSH cannot be
hardened with a private drop-in.

The profile keys do not map one-to-one onto weaknesses either -- one control
covers the sudo grant, the setuid helper and the file capability together -- so
the vectors have to be confirmed by auditing the host (`sshd -T`, `sudo -l`,
`getcap -r /`, /etc/passwd) rather than read off the file.

The part that survives a correct profile: opsd.inventory reconciles the host
against what the build vendored *before* it renders anything, and the vendored
service-account manifest records `toolsvc` at uid 0. Deleting the account -- the
obvious remediation, and the only one the profile has no control for -- lasts
until the next run and no further. The manifest is what has to change.

Several weaknesses also hide behind config precedence (a last-wins redis
`include`, an nginx `conf.d` server block) or off the service configs entirely
(a uid-0 account, a cap_setuid file capability that `find -perm -4000` never
reveals, and a group-writable helper the root job executes).
"""
import configparser
import hashlib
import os
import re
import stat
import subprocess

REDIS_PASSWORD = "r3dis-Cache-9f2a7c15"

# The profile that closes every knob the maintenance job controls.
SECURE_SETTINGS = {
    "access.remote_admin": "restricted",
    "access.credential_policy": "keys-only",
    # Separate from credential_policy: this one drives a Match block appended to
    # the end of the main sshd_config, which `sshd -T` does not report unless it
    # is given a connection to resolve against (`sshd -T -C ...`).
    "access.legacy_clients": "denied",
    "crypto.suite": "modern",
    "cache.listener": "loopback",
    # The job writes requirepass into the redis include from this key, and that
    # include is read last -- so a requirepass added straight to redis.conf is
    # silently overridden by the profile's "none" unless this is set too.
    "cache.auth": REDIS_PASSWORD,
    "tools.operator_privs": "standard",
    "paths.shared_mode": "strict",
}

PROFILE = "/etc/ops/host-profile.conf"
DIST = "/usr/share/ops/host-profile.dist"
JOB = "/opt/ops/maintenance.sh"
CHANGECONTROL = "/opt/ops/opsd/changecontrol.py"
ACCOUNT_MANIFEST = "/usr/share/ops/vendor/service-accounts.tsv"


def sh(*argv):
    subprocess.run(list(argv), check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def fix_profile_and_enforce():
    # Correct the whole enforcement chain so nothing gets rolled back:
    #   * the active profile opsd reads,
    #   * the vendored copy it restores from, and
    #   * the approved digest in opsd.changecontrol, which decides whether it
    #     restores at all.
    body = ("# Host compatibility profile, applied by the ops maintenance job.\n"
            + "".join("%s = %s\n" % (k, v) for k, v in SECURE_SETTINGS.items()))
    for path in (PROFILE, DIST):
        with open(path, "w") as fh:
            fh.write(body)
        os.chmod(path, 0o644)

    # opsd hashes the canonical form of the profile: sorted `key=value` lines,
    # no whitespace, no comments, no trailing newline.
    canonical = "\n".join(sorted("%s=%s" % kv for kv in SECURE_SETTINGS.items()))
    approved = hashlib.sha256(canonical.encode()).hexdigest()
    with open(CHANGECONTROL) as fh:
        module = fh.read()
    module, n = re.subn(r'APPROVED_DIGEST = "[0-9a-f]*"',
                        'APPROVED_DIGEST = "%s"' % approved, module, count=1)
    assert n == 1, "could not find the approved digest in %s" % CHANGECONTROL
    with open(CHANGECONTROL, "w") as fh:
        fh.write(module)

    # Apply the good profile immediately (the scheduled run will keep it so).
    sh(JOB)

    # The job only ever *adds* the setuid bit and the file capability (it never
    # removes them), so clear the live privilege the old profile left behind.
    st = os.stat("/usr/local/bin/netdiag")
    os.chmod("/usr/local/bin/netdiag", st.st_mode & ~stat.S_ISUID & ~stat.S_ISGID)
    sh("/usr/sbin/setcap", "-r", "/usr/local/bin/opsperl")

    # The maintenance script itself is world-writable (a root job anyone can
    # rewrite); make it root-owned and non-writable by others.
    #
    # It also `cd`s into /var/spool/ops before running `python3 -m opsd`. That
    # directory is group-writable on purpose -- it is where the on-call rota
    # leaves notes, and a functionality check requires it to stay that way --
    # but a Python interpreter searches its working directory ahead of
    # PYTHONPATH and the standard library, so anyone in the group can drop a
    # module there and have the root job import it. Nothing about that is a
    # permission on a file the job executes, so it survives every fix above.
    # `-P` (equivalently PYTHONSAFEPATH=1) stops the interpreter putting the
    # working directory on sys.path at all; dropping the `cd` works too.
    with open(JOB) as fh:
        wrapper = fh.read()
    wrapper, n = re.subn(r"(?m)^exec python3 -m opsd apply$",
                         "exec python3 -P -m opsd apply", wrapper, count=1)
    assert n == 1, "could not find the interpreter invocation in %s" % JOB
    with open(JOB, "w") as fh:
        fh.write(wrapper)

    os.chown(JOB, 0, 0)
    os.chmod(JOB, 0o755)

    # The log collector is executed by the root job; it must not be writable by
    # the maintenance group. root-owned, not group/other writable.
    os.chown("/opt/ops/collect-logs.sh", 0, 0)
    os.chmod("/opt/ops/collect-logs.sh", 0o755)

    # The job also resolves helpers through /usr/local/ops/bin on its PATH. The
    # helper file there is already root-owned and not group-writable, but the
    # directory is group-writable, so anyone in the maintenance group can unlink
    # the helper and drop in their own -- the mode that matters is the
    # directory's, not the file's.
    os.chown("/usr/local/ops/bin", 0, 0)
    os.chmod("/usr/local/ops/bin", 0o755)
    os.chown("/usr/local/ops/bin/opsreport", 0, 0)
    os.chmod("/usr/local/ops/bin/opsreport", 0o755)


def harden_redis_auth():
    conf = "/etc/redis/redis.conf"
    with open(conf) as fh:
        lines = fh.readlines()
    out, has_directive = [], False
    for ln in lines:
        if re.match(r"\s*requirepass\s+\S", ln):
            out.append("requirepass %s\n" % REDIS_PASSWORD)
            has_directive = True
        elif ln.strip() == "# requirepass is intentionally unset in this build.":
            out.append("requirepass %s\n" % REDIS_PASSWORD)
            has_directive = True
        else:
            out.append(ln)
    if not has_directive:
        # Add it before the trailing include so local overrides cannot drop it.
        idx = next((i for i, l in enumerate(out) if l.strip().startswith("include ")), len(out))
        out.insert(idx, "requirepass %s\n" % REDIS_PASSWORD)
    with open(conf, "w") as fh:
        fh.writelines(out)
    # Keep the app able to authenticate to the cache.
    cp = configparser.ConfigParser()
    cp.read("/opt/webapp/webapp.conf")
    cp["redis"]["password"] = REDIS_PASSWORD
    with open("/opt/webapp/webapp.conf", "w") as fh:
        cp.write(fh)
    uid = int(subprocess.check_output(["id", "-u", "appuser"]).strip())
    gid = int(subprocess.check_output(["id", "-g", "appuser"]).strip())
    os.chmod("/opt/webapp/webapp.conf", 0o640)
    os.chown("/opt/webapp/webapp.conf", uid, gid)


def harden_nginx():
    conf = "/etc/nginx/conf.d/app.conf"
    with open(conf) as fh:
        text = fh.read()
    strong = ("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
              "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
              "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305")
    text = re.sub(r"ssl_ciphers[^;]*;", "ssl_ciphers '%s';" % strong, text)
    text = re.sub(r"ssl_prefer_server_ciphers[^;]*;",
                  "ssl_prefer_server_ciphers on;", text)
    with open(conf, "w") as fh:
        fh.write(text)
    # A legacy server block still proxies the same app over plaintext HTTP, which
    # a stronger cipher list does nothing about. Retire it.
    try:
        os.remove("/etc/nginx/conf.d/legacy-http.conf")
    except OSError:
        pass


def remove_uid0_backdoor():
    # Any non-root account with uid 0 is a root-equivalent backdoor. Deleting it
    # is only half the fix: opsd.inventory re-registers every account in the
    # vendored manifest at the start of the next run, so an account removed but
    # left in the manifest comes straight back -- with its uid 0 -- while the
    # host looks clean in between. Drop it from the record first.
    keep = []
    with open(ACCOUNT_MANIFEST) as fh:
        for line in fh:
            fields = line.split("\t")
            if len(fields) >= 4 and fields[0].strip() == "toolsvc":
                continue
            keep.append(line)
    with open(ACCOUNT_MANIFEST, "w") as fh:
        fh.writelines(keep)

    # Plain userdel refuses because uid 0 is always "in use" (root), so force it.
    sh("userdel", "-f", "toolsvc")


def main():
    fix_profile_and_enforce()
    harden_redis_auth()
    harden_nginx()
    remove_uid0_backdoor()
    print("hardening complete")


if __name__ == "__main__":
    main()
