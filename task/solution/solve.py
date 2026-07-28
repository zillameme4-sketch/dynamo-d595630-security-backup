#!/usr/bin/env python3
"""Reference hardening pass for the multi-service host.

The subtlety: a root maintenance job (/opt/ops/maintenance.sh) re-applies an
insecure baseline (/opt/ops/baseline.env) on every scheduled run, and the
verifier runs it during grading. Fixing only the live configuration is silently
reverted, so the fix must correct the baseline (or neutralise the enforcement)
as well as the current state. Several weaknesses also hide behind config
precedence (a last-wins redis `include`, an nginx `conf.d` server block) or off
the service configs entirely (a uid-0 account, group-based sudo).
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
BACKUP_MODE="0750"
'''


def sh(*argv):
    subprocess.run(list(argv), check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def fix_baseline_and_enforce():
    # Correct the enforced baseline, then run the maintenance job so the good
    # baseline is applied immediately (the scheduled run will keep it that way).
    with open("/opt/ops/baseline.env", "w") as fh:
        fh.write(SECURE_BASELINE)
    os.chmod("/opt/ops/baseline.env", 0o644)
    sh("/opt/ops/maintenance.sh")
    # The enforcement only *adds* the setuid bit (never removes it), so strip
    # the live bit that the previous baseline left behind.
    st = os.stat("/usr/local/bin/netdiag")
    os.chmod("/usr/local/bin/netdiag", st.st_mode & ~stat.S_ISUID & ~stat.S_ISGID)
    # The maintenance script itself is world-writable (a root job anyone can
    # rewrite); make it root-owned and non-writable by others.
    os.chown("/opt/ops/maintenance.sh", 0, 0)
    os.chmod("/opt/ops/maintenance.sh", 0o755)


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
