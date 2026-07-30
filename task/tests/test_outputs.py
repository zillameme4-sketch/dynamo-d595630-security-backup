"""Verifier for the host-hardening task.

First runs the root maintenance job (`/opt/ops/maintenance.sh`) exactly as the
scheduler would, then boots sshd, redis, nginx and the internal web app from
their on-disk configuration (whatever the agent left behind), then:

  * attacks every planted weakness — each attack must now fail; and
  * exercises the legitimate service chain — it must still work.

Running the maintenance job first is the point: a fix that only edits the live
configuration is reverted by the job's baseline enforcement and fails. Reward is
all-or-nothing. Grading is behavioral (services are executed and probed);
permission/account vectors are checked on the concrete objects an attacker abuses.
"""
import json
import os
import re
import stat
import subprocess

import pytest

import servicelib as S

# Unambiguously weak primitives (none appear in modern OpenSSH defaults, so a
# config that simply reverts to defaults is not penalised).
WEAK_SSH_CRYPTO = [
    "hmac-md5", "hmac-md5-96", "hmac-sha1-96",
    "3des-cbc", "aes128-cbc", "aes256-cbc", "arcfour", "arcfour128",
    "arcfour256", "blowfish-cbc", "cast128-cbc",
    "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
]
# Non-forward-secret (RSA key-exchange) suites the hardened server must refuse.
WEAK_TLS_CIPHERS = ("AES256-GCM-SHA384:AES128-GCM-SHA256:"
                    "AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA")


@pytest.fixture(scope="session", autouse=True)
def enforce():
    """Run the scheduled root maintenance job before any grading, as cron would."""
    subprocess.run(["/opt/ops/maintenance.sh"], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    yield


@pytest.fixture(scope="session")
def services(enforce):
    svc = S.Services()
    ready = svc.start()
    yield svc, ready
    svc.stop()


def _handshake_ok(proc):
    return "-----BEGIN CERTIFICATE-----" in proc.stdout


def _sshd_effective():
    p = subprocess.run(["sshd", "-T", "-f", "/etc/ssh/sshd_config"],
                       capture_output=True, text=True)
    assert p.returncode == 0, "sshd rejected the configuration:\n%s" % p.stderr
    cfg = {}
    for line in p.stdout.splitlines():
        if " " in line:
            k, v = line.split(" ", 1)
            cfg[k.strip().lower()] = v.strip()
    return cfg


# ============================ hardening vectors =============================
def test_ssh_root_login_disabled(enforce):
    """SSH: the effective config must refuse root login (survives the baseline job)."""
    assert _sshd_effective().get("permitrootlogin") == "no", \
        "effective PermitRootLogin is not 'no' — an override or the baseline job still allows root login"


def test_ssh_password_auth_disabled(enforce):
    """SSH: the effective config must disable password authentication."""
    assert _sshd_effective().get("passwordauthentication") == "no", \
        "effective PasswordAuthentication is not 'no'"


def test_ssh_weak_crypto_removed(enforce):
    """SSH: no weak cipher/MAC/KEX primitive may remain in the effective config."""
    cfg = _sshd_effective()
    blob = " ".join([cfg.get("ciphers", ""), cfg.get("macs", ""),
                     cfg.get("kexalgorithms", "")]).lower()
    present = sorted({w for w in WEAK_SSH_CRYPTO
                      if re.search(r"(^|[,\s])%s($|[,\s])" % re.escape(w), blob)})
    assert not present, "weak SSH primitives still offered: %s" % present


def test_redis_requires_authentication(services):
    """Redis: an unauthenticated client on loopback must be rejected."""
    _, ready = services
    assert ready["redis"], "redis did not start from its configuration"
    reply = S.redis_command("127.0.0.1", 6379, ["PING"])
    assert not reply.startswith("+PONG"), \
        "redis answered PING without authentication (no requirepass set): %r" % reply
    assert "NOAUTH" in reply or reply.startswith("-ERR") or reply.startswith("ERR-CONN"), \
        "redis is reachable unauthenticated: %r" % reply


def test_redis_not_exploitable_on_public_interface(services):
    """Redis: it must not be usable unauthenticated on the container's public IP."""
    _, ready = services
    assert ready["redis"], "redis did not start from its configuration"
    ip = S.primary_ip()
    reply = S.redis_command(ip, 6379, ["PING"], timeout=3.0)
    assert not reply.startswith("+PONG"), \
        "redis is exposed unauthenticated on public interface %s: %r" % (ip, reply)


def test_sudo_no_gtfobins_escalation():
    """sudo: lowuser must not reach root through a passwordless GTFOBins grant.

    The grant is on the `maintenance` group (which lowuser belongs to), not on
    lowuser directly, and targets awk — which trivially spawns a root shell."""
    proc = S.run_as("lowuser",
                    r"""sudo -n /usr/bin/awk 'BEGIN{system("id")}' 2>&1""")
    combined = (proc.stdout + proc.stderr)
    assert "uid=0(root)" not in combined, \
        "lowuser escalated to root via 'sudo awk': %s" % combined.strip()


def test_setuid_helper_not_root():
    """SUID: running the diagnostics helper as lowuser must not grant euid 0.

    Removing the helper outright is a valid (stronger) remediation, so an absent
    binary closes the vector; what must never hold is a setuid-root helper an
    unprivileged user can still execute."""
    helper = "/usr/local/bin/netdiag"
    if not os.path.exists(helper):
        return  # helper deleted: nothing left for lowuser to escalate through
    st = os.stat(helper)
    assert not (st.st_uid == 0 and st.st_mode & stat.S_ISUID), \
        "%s is still setuid-root" % helper
    proc = S.run_as("lowuser", helper)
    m = re.search(r"euid=(\d+)", proc.stdout)
    if m:
        assert m.group(1) != "0", \
            "netdiag still runs with euid 0 for an unprivileged user (setuid bit set)"


def test_no_file_capability_privesc(enforce):
    """SUID-equivalent: a Linux file capability must not let lowuser reach root.

    `find -perm -4000` does not reveal capabilities, so a cap_setuid binary is
    an easy vector to miss. The ops perl copy carries cap_setuid unless the
    baseline stops re-applying it *and* the live capability is cleared."""
    proc = S.run_as("lowuser",
                    r'''/usr/local/bin/opsperl -e '$>=0;$<=0;exec "/usr/bin/id"' 2>&1''')
    out = proc.stdout + proc.stderr
    assert "uid=0(root)" not in out, \
        "lowuser escalated to root via a file capability on /usr/local/bin/opsperl: %s" \
        % out.strip()


def test_root_job_helper_not_user_writable(enforce):
    """A file the root maintenance job executes must not be writable by a
    non-root user; otherwise lowuser plants code that the job runs as root.

    lowuser (in the ops `maintenance` group) tries to overwrite the collector
    with a payload, then the root job runs; the payload must not execute as
    root. The plant is attempted even if the collector was deleted, since a
    writable /opt/ops would let lowuser simply re-create it. State is restored
    afterwards."""
    collector = "/opt/ops/collect-logs.sh"
    sentinel = "/run/collector_pwned"  # /run is root-owned; only root can create here
    try:
        os.remove(sentinel)
    except OSError:
        pass
    existed = os.path.exists(collector)
    original = None
    orig_mode = None
    if existed:
        with open(collector, "rb") as fh:
            original = fh.read()
        orig_mode = stat.S_IMODE(os.stat(collector).st_mode)
    try:
        plant = ("cat > %s <<'PLEOF'\n"
                 "#!/bin/bash\n"
                 "id -u > %s 2>/dev/null || true\n"
                 "PLEOF\n") % (collector, sentinel)
        S.run_as("lowuser", plant)
        subprocess.run(["/opt/ops/maintenance.sh"], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pwned = os.path.exists(sentinel)
    finally:
        if existed:
            with open(collector, "wb") as fh:
                fh.write(original)
            os.chmod(collector, orig_mode)
        else:
            try:
                os.remove(collector)  # drop anything lowuser managed to create
            except OSError:
                pass
        try:
            os.remove(sentinel)
        except OSError:
            pass
    assert not pwned, \
        "lowuser planted code in %s, a file the root maintenance job executes as root" % collector


def test_no_uid0_backdoor_account():
    """Accounts: no account other than root may have uid 0."""
    offenders = []
    with open("/etc/passwd") as fh:
        for line in fh:
            parts = line.split(":")
            if len(parts) >= 3 and parts[2] == "0" and parts[0] != "root":
                offenders.append(parts[0])
    assert not offenders, "non-root uid-0 (root-equivalent) account(s) present: %s" % offenders


def test_tls_weak_ciphers_rejected(services):
    """TLS: nginx must refuse legacy / non-forward-secret cipher suites."""
    _, ready = services
    assert ready["nginx"], "nginx did not start from its configuration"
    proc = S.openssl_probe("127.0.0.1", 443, ["-tls1_2", "-cipher", WEAK_TLS_CIPHERS])
    assert not _handshake_ok(proc), \
        "nginx negotiated a weak cipher from {%s}" % WEAK_TLS_CIPHERS


def test_maintenance_script_not_writable(enforce):
    """cron: the root-run maintenance script and crontab must not be writable by others.

    A path that was removed outright cannot be rewritten by anyone, so it is not
    a finding; the script itself must still exist, because the job has to run."""
    assert os.path.exists("/opt/ops/maintenance.sh"), \
        "the maintenance script is gone — the scheduled root job can no longer run"
    for path in ("/opt/ops/maintenance.sh", "/etc/cron.d/ops-maintenance"):
        if not os.path.exists(path):
            continue
        st = os.stat(path)
        assert st.st_uid == 0, "%s must be root-owned" % path
        assert not (st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)), \
            "%s is group/other-writable (a root job anyone can rewrite)" % path


def test_backup_output_not_world_writable_after_run(enforce):
    """cron: running the maintenance job must not (re-)create world-writable output."""
    subprocess.run(["/opt/ops/maintenance.sh"], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    dest = "/var/backups/app"
    st = os.stat(dest)
    assert not (st.st_mode & stat.S_IWOTH), \
        "%s is world-writable after the maintenance job ran" % dest
    for name in os.listdir(dest):
        p = os.path.join(dest, name)
        assert not (os.stat(p).st_mode & stat.S_IWOTH), \
            "%s is world-writable after the maintenance job ran" % p


# ============================== functionality ==============================
def test_ssh_key_login_works(services):
    """Functionality: appuser must still log in over SSH using its key."""
    _, ready = services
    assert ready["sshd"], "sshd did not start from its configuration"
    proc = S.ssh_run("appuser", "127.0.0.1", "echo READY", key=S.KEY_PATH)
    assert proc.returncode == 0 and "READY" in proc.stdout, \
        "key-based SSH login for appuser is broken: rc=%s err=%s" % (proc.returncode, proc.stderr.strip())


def test_app_roundtrips_through_redis(services):
    """Functionality: HTTPS -> nginx -> app -> redis must return the cached value."""
    _, ready = services
    assert ready["nginx"] and ready["app"], "nginx/app did not start"
    proc = subprocess.run(
        ["curl", "-sS", "-k", "--max-time", "10", "https://127.0.0.1/status"],
        capture_output=True, text=True)
    assert proc.returncode == 0, "curl to the TLS endpoint failed: %s" % proc.stderr.strip()
    data = json.loads(proc.stdout)
    assert data.get("cache") == "healthy", \
        "app did not round-trip through redis (check redis auth / app config consistency): %s" % proc.stdout


def test_tls_modern_handshake_works(services):
    """Functionality: a modern TLS client must still complete a handshake."""
    _, ready = services
    assert ready["nginx"], "nginx did not start from its configuration"
    proc = S.openssl_probe("127.0.0.1", 443, ["-tls1_2"])
    assert _handshake_ok(proc), "modern TLS 1.2 handshake fails against nginx"


def test_maintenance_job_still_produces_output(enforce):
    """Functionality: the maintenance job must still run and write its backup.

    The marker is cleared first so a stale file from an earlier run cannot stand
    in for the work: neutralising the baseline enforcement is a legitimate fix,
    gutting the backup the operators rely on is not."""
    assert os.path.exists("/opt/ops/maintenance.sh"), \
        "the maintenance script is gone — the job can no longer take its backup"
    marker = "/var/backups/app/last_backup.txt"
    try:
        os.remove(marker)
    except OSError:
        pass
    subprocess.run(["/opt/ops/maintenance.sh"], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert os.path.isfile(marker), \
        "the maintenance job no longer writes its backup marker %s" % marker
    assert os.path.getsize(marker) > 0, "backup marker is empty"
