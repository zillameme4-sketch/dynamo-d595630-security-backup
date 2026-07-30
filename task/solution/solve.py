#!/usr/bin/env python3
"""Reference hardening pass for the multi-service host.

The subtlety: a root maintenance job (/opt/ops/maintenance.sh) re-applies a host
compatibility profile on every scheduled run, and the verifier runs it during
grading. Editing only the live configuration is silently reverted. Worse, the
job compares the active profile (/etc/ops/host-profile.conf) against the set of
settings approved *inside the job itself* and, on any mismatch, rolls the profile
back to the vendored copy (/usr/share/ops/host-profile.dist) at the end of the
run. So mirroring secure values across the profile and the vendored copy is not
enough either: the approved set in the job has to agree, or the enforcement has
to be neutralised outright. The job also owns /etc/ssh/sshd_config.d, clearing
any drop-in it did not place, so SSH cannot be hardened with a private drop-in.

The profile keys do not map one-to-one onto weaknesses either -- one knob covers
the sudo grant, the setuid helper and the file capability together -- so the
vectors have to be confirmed by auditing the host (`sshd -T`, `sudo -l`,
`getcap -r /`, /etc/passwd) rather than read off the file.

Several weaknesses also hide behind config precedence (a last-wins redis
`include`, an nginx `conf.d` server block) or off the service configs entirely
(a uid-0 account, a cap_setuid file capability that `find -perm -4000` never
reveals, and a group-writable helper the root job executes).
"""
import configparser
import os
import re
import stat
import subprocess

REDIS_PASSWORD = "r3dis-Cache-9f2a7c15"

# The profile that closes every knob the maintenance job controls.
SECURE_SETTINGS = {
    "access.remote_admin": "restricted",
    "access.credential_policy": "keys-only",
    "crypto.suite": "modern",
    "cache.listener": "loopback",
    "tools.operator_privs": "standard",
    "paths.shared_mode": "strict",
}

PROFILE = "/etc/ops/host-profile.conf"
DIST = "/usr/share/ops/host-profile.dist"
JOB = "/opt/ops/maintenance.sh"


def sh(*argv):
    subprocess.run(list(argv), check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def fix_profile_and_enforce():
    # Correct the whole enforcement chain so nothing gets rolled back:
    #   * the active profile the job reads,
    #   * the vendored copy it rolls back to, and
    #   * the approved set baked into the job, which decides whether it rolls
    #     back at all.
    body = ("# Host compatibility profile, applied by the ops maintenance job.\n"
            + "".join("%s = %s\n" % (k, v) for k, v in SECURE_SETTINGS.items()))
    for path in (PROFILE, DIST):
        with open(path, "w") as fh:
            fh.write(body)
        os.chmod(path, 0o644)

    # The job compares `sort`ed key=value lines, so the approved block has to be
    # in that exact form.
    approved = "\n".join(sorted("%s=%s" % kv for kv in SECURE_SETTINGS.items()))
    with open(JOB) as fh:
        job = fh.read()
    job, n = re.subn(r'APPROVED="[^"]*"', 'APPROVED="%s"' % approved, job, count=1)
    assert n == 1, "could not find the approved set in %s" % JOB
    with open(JOB, "w") as fh:
        fh.write(job)

    # Apply the good profile immediately (the scheduled run will keep it so).
    sh(JOB)

    # The job only ever *adds* the setuid bit and the file capability (it never
    # removes them), so clear the live privilege the old profile left behind.
    st = os.stat("/usr/local/bin/netdiag")
    os.chmod("/usr/local/bin/netdiag", st.st_mode & ~stat.S_ISUID & ~stat.S_ISGID)
    sh("/usr/sbin/setcap", "-r", "/usr/local/bin/opsperl")

    # The maintenance script itself is world-writable (a root job anyone can
    # rewrite); make it root-owned and non-writable by others.
    os.chown(JOB, 0, 0)
    os.chmod(JOB, 0o755)

    # The log collector is executed by the root job; it must not be writable by
    # the maintenance group. root-owned, not group/other writable.
    os.chown("/opt/ops/collect-logs.sh", 0, 0)
    os.chmod("/opt/ops/collect-logs.sh", 0o755)


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


def remove_uid0_backdoor():
    # Any non-root account with uid 0 is a root-equivalent backdoor. Plain
    # userdel refuses because uid 0 is always "in use" (root), so force it.
    sh("userdel", "-f", "toolsvc")


def main():
    fix_profile_and_enforce()
    harden_redis_auth()
    harden_nginx()
    remove_uid0_backdoor()
    print("hardening complete")


if __name__ == "__main__":
    main()
