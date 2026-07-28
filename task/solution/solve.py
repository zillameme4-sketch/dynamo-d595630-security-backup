#!/usr/bin/env python3
"""Reference hardening pass for the multi-service host.

Closes each planted weakness with the minimal change that keeps the service
chain (SSH key login, nginx -> app -> Redis, the root backup job) working:

  * SSH   — neutralise the legacy drop-in so the *effective* config disables
            root login and password auth and drops weak ciphers/MACs/kex.
  * Redis — bind to loopback only, enable protected-mode, require a password,
            and set the *same* password in the app config so the app still
            reaches the cache.
  * nginx — restrict TLS to forward-secret AEAD cipher suites.
  * sudo  — drop the passwordless GTFOBins (`find`) grant.
  * SUID  — remove the setuid bit from the diagnostics helper.
  * cron  — make the backup script and crontab root-owned/non-writable and stop
            the script from re-creating world-writable output (the drift bug).
"""
import configparser
import os
import re
import stat
import subprocess

REDIS_PASSWORD = "r3dis-Cache-9f2a7c15"


def write(path, text, mode=0o644, uid=0, gid=0):
    with open(path, "w") as fh:
        fh.write(text)
    os.chmod(path, mode)
    os.chown(path, uid, gid)


# ---------------------------------------------------------------- SSH --------
def harden_ssh():
    hardened = """# Hardened by the security pass. Loaded first via the Include directive, so
# these effective values win over the base file.
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
"""
    write("/etc/ssh/sshd_config.d/00-legacy.conf", hardened, mode=0o644)


# --------------------------------------------------------------- Redis -------
def harden_redis():
    conf = "/etc/redis/redis.conf"
    with open(conf) as fh:
        lines = fh.readlines()
    out, seen = [], {"bind": False, "protected-mode": False, "requirepass": False}
    for ln in lines:
        key = ln.strip().split(" ", 1)[0] if ln.strip() else ""
        if key == "bind":
            out.append("bind 127.0.0.1 -::1\n")
            seen["bind"] = True
        elif key == "protected-mode":
            out.append("protected-mode yes\n")
            seen["protected-mode"] = True
        elif key == "requirepass":
            out.append("requirepass %s\n" % REDIS_PASSWORD)
            seen["requirepass"] = True
        else:
            out.append(ln)
    if not seen["bind"]:
        out.append("bind 127.0.0.1 -::1\n")
    if not seen["protected-mode"]:
        out.append("protected-mode yes\n")
    if not seen["requirepass"]:
        out.append("requirepass %s\n" % REDIS_PASSWORD)
    write(conf, "".join(out), mode=0o640, uid=_uid("redis"), gid=_gid("redis"))

    # Keep the app able to authenticate to the cache.
    cp = configparser.ConfigParser()
    cp.read("/opt/webapp/webapp.conf")
    cp["redis"]["password"] = REDIS_PASSWORD
    with open("/opt/webapp/webapp.conf", "w") as fh:
        cp.write(fh)
    os.chmod("/opt/webapp/webapp.conf", 0o640)
    os.chown("/opt/webapp/webapp.conf", _uid("appuser"), _gid("appuser"))


# --------------------------------------------------------------- nginx -------
def harden_nginx():
    conf = "/etc/nginx/nginx.conf"
    with open(conf) as fh:
        text = fh.read()
    strong = ("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
              "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
              "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305")
    text = re.sub(r"ssl_ciphers[^;]*;", "ssl_ciphers '%s';" % strong, text)
    text = re.sub(r"ssl_protocols[^;]*;", "ssl_protocols TLSv1.2 TLSv1.3;", text)
    text = re.sub(r"ssl_prefer_server_ciphers[^;]*;",
                  "ssl_prefer_server_ciphers on;", text)
    write(conf, text, mode=0o644)


# ---------------------------------------------------------------- sudo -------
def harden_sudo():
    conf = "/etc/sudoers.d/appops"
    with open(conf) as fh:
        lines = fh.readlines()
    kept = [ln for ln in lines if "NOPASSWD: /usr/bin/find" not in ln]
    write(conf, "".join(kept), mode=0o440)


# ---------------------------------------------------------------- SUID -------
def harden_setuid():
    path = "/usr/local/bin/netdiag"
    mode = os.stat(path).st_mode
    os.chmod(path, mode & ~stat.S_ISUID & ~stat.S_ISGID)


# ---------------------------------------------------------------- cron -------
def harden_backup():
    script = "/opt/backup/backup.sh"
    with open(script) as fh:
        text = fh.read()
    # Remove the world-writable drift and use a safe fixed umask + perms.
    text = text.replace('chmod -R 777 "$DEST"', 'chmod 0750 "$DEST"')
    if "umask" not in text:
        text = text.replace("set -u\n", "set -u\numask 027\n")
    write(script, text, mode=0o755)
    write("/etc/cron.d/app-backup", open("/etc/cron.d/app-backup").read(), mode=0o644)

    dest = "/var/backups/app"
    if os.path.isdir(dest):
        os.chmod(dest, 0o750)
        for name in os.listdir(dest):
            p = os.path.join(dest, name)
            if os.path.isfile(p):
                os.chmod(p, 0o640)


# --------------------------------------------------------------- helpers -----
def _uid(name):
    return int(subprocess.check_output(["id", "-u", name]).strip())


def _gid(name):
    return int(subprocess.check_output(["id", "-g", name]).strip())


def main():
    harden_ssh()
    harden_redis()
    harden_nginx()
    harden_sudo()
    harden_setuid()
    harden_backup()
    print("hardening complete")


if __name__ == "__main__":
    main()
