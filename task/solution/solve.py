#!/usr/bin/env python3
"""Reference hardening pass for the multi-service host.

The subtlety: a root maintenance job (/opt/ops/maintenance.sh) re-applies a
saved baseline (/opt/ops/baseline.env) on every scheduled run, and the verifier
runs it during grading. Editing only the live configuration is silently
reverted. Worse, the job reconciles the active baseline against a vendored
source of truth (/usr/share/ops/baseline.env.dist) using a checksum manifest
(/var/lib/ops/baseline.sha256): if the active baseline no longer matches the
manifest, the vendored copy is restored -- so editing baseline.env alone is
*also* reverted. The fix must correct the whole enforcement chain (active
baseline + vendored copy + manifest) as well as the current live state.

Several weaknesses also hide behind config precedence (a last-wins redis
`include`, an nginx `conf.d` server block) or off the service configs entirely
(a uid-0 account, group-based sudo, a cap_setuid file capability that `find
-perm -4000` never reveals, and a group-writable helper the root job executes).
"""
import configparser
import os
import re
import stat
import subprocess

REDIS_PASSWORD = "r3dis-Cache-9f2a7c15"

SECURE_BASELINE = '''# Corrected host baseline.
SSH_PERMIT_ROOT="no"
SSH_PASSWORD_AUTH="no"
SSH_CIPHERS="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr"
SSH_MACS="hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com"
REDIS_BIND="127.0.0.1 -::1"
REDIS_PROTECTED_MODE="yes"
SUDO_GRANT=""
NETDIAG_SETUID="no"
OPSPERL_CAP="no"
COLLECTOR_MODE="0755"
BACKUP_MODE="0750"
'''

BASELINE = "/opt/ops/baseline.env"
DIST = "/usr/share/ops/baseline.env.dist"
MANIFEST = "/var/lib/ops/baseline.sha256"


def sh(*argv):
    subprocess.run(list(argv), check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def fix_baseline_and_enforce():
    # Correct the whole enforcement chain so nothing gets reverted:
    #   * the active baseline the job sources,
    #   * the vendored source of truth the job reconciles against, and
    #   * the checksum manifest that decides whether a restore happens.
    for path in (BASELINE, DIST):
        with open(path, "w") as fh:
            fh.write(SECURE_BASELINE)
        os.chmod(path, 0o644)
    # Recompute the manifest so the active baseline matches it (no restore), the
    # same way the build recorded it.
    with open(MANIFEST, "w") as fh:
        subprocess.run(["sha256sum", BASELINE], check=True, stdout=fh)

    # Apply the good baseline immediately (the scheduled run will keep it so).
    sh("/opt/ops/maintenance.sh")

    # The job only ever *adds* the setuid bit and the file capability (it never
    # removes them), so clear the live privilege the old baseline left behind.
    st = os.stat("/usr/local/bin/netdiag")
    os.chmod("/usr/local/bin/netdiag", st.st_mode & ~stat.S_ISUID & ~stat.S_ISGID)
    sh("/usr/sbin/setcap", "-r", "/usr/local/bin/opsperl")

    # The maintenance script itself is world-writable (a root job anyone can
    # rewrite); make it root-owned and non-writable by others.
    os.chown("/opt/ops/maintenance.sh", 0, 0)
    os.chmod("/opt/ops/maintenance.sh", 0o755)

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
    fix_baseline_and_enforce()
    harden_redis_auth()
    harden_nginx()
    remove_uid0_backdoor()
    print("hardening complete")


if __name__ == "__main__":
    main()
