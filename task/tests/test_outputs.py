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


def _weak_ssh_primitives(cfg):
    """The weak transport primitives left in an effective sshd configuration.

    Judged by class rather than by a fixed list of names, so a primitive that
    happens not to be enumerated anywhere is still caught: CBC-mode, RC4 /
    arcfour, DES / 3DES, Blowfish, CAST and null ciphers; MD5-, RIPEMD-based,
    truncated (`-96`) and null MACs; and SHA-1 or group1 key exchange. Every
    one of these is unambiguously weak and none of them appear in the OpenSSH
    defaults, so a configuration that simply falls back to the distribution
    default is not penalised.
    """
    def entries(key):
        return [e for e in (cfg.get(key) or "").split(",") if e]

    def base(name):
        return name.split("@")[0].lower()

    weak = []
    for name in entries("ciphers"):
        b = base(name)
        if (b.endswith("-cbc") or b.startswith(("arcfour", "rc4", "3des", "des-",
                                                "blowfish", "cast", "idea"))
                or b == "none"):
            weak.append(name)
    for name in entries("macs"):
        b = base(name)
        if "md5" in b or "ripemd" in b or b.endswith("-96") or b == "none":
            weak.append(name)
    for name in entries("kexalgorithms"):
        b = base(name)
        if b.endswith("-sha1") or "group1-" in b or b.endswith("group1") or "rsa1024" in b:
            weak.append(name)
    return sorted(set(weak))


# The connections the effective SSH policy is resolved for. A Match block that
# hands password authentication back to one address range does not show up in
# plain `sshd -T` output at all, and an exemption written for some other range
# is the same weakness — so the policy is read the way sshd resolves it for a
# real login, from several unrelated ranges including this host's own.
SSH_PROBE_ADDRESSES = ("10.0.0.5", "172.16.4.9", "192.168.10.7", "203.0.113.9")

_TLS_SUITES = {}  # filled once from the library, see below


def _tls_suite_catalogue():
    """Every pre-TLS 1.3 suite the local library can offer, tagged with the two
    properties this task grades: an ephemeral key exchange (forward secrecy)
    and an AEAD cipher.

    Read out of OpenSSL's own metadata rather than written down here, so the
    check is a statement about suite *properties* and not a denylist that a
    suite can simply not be on. TLS 1.3 suites (`Kx=any`) are excluded: they
    are ephemeral and AEAD by construction, and are not selectable through the
    `-cipher` option anyway.
    """
    if _TLS_SUITES:
        return _TLS_SUITES
    proc = subprocess.run(["openssl", "ciphers", "-v", "ALL:COMPLEMENTOFALL:@SECLEVEL=0"],
                          capture_output=True, text=True)
    catalogue = {}
    for line in proc.stdout.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        attrs = dict(f.split("=", 1) for f in fields[1:] if "=" in f)
        kx, mac = attrs.get("Kx", ""), attrs.get("Mac", "")
        if kx == "any":
            continue
        catalogue[fields[0]] = (kx in ("ECDH", "DH"), mac == "AEAD")
    _TLS_SUITES.update(catalogue)
    return catalogue


def _weak_suite_offer():
    """A client offer containing every suite that is *not* both forward-secret
    and AEAD, at SECLEVEL 0 so the client filters nothing before the server
    chooses."""
    catalogue = _tls_suite_catalogue()
    weak = [name for name, (fs, aead) in catalogue.items() if not (fs and aead)]
    assert weak, "openssl offered no non-forward-secret/non-AEAD suite to probe with"
    return ":".join(sorted(weak)) + ":@SECLEVEL=0"


def _strong_suite(cipher):
    """A negotiated suite is strong here iff its key exchange is ephemeral and
    its cipher is AEAD. TLS 1.3 suites (`TLS_*`) are both by construction."""
    if not cipher:
        return False
    if cipher.startswith("TLS_"):
        return True
    fs, aead = _tls_suite_catalogue().get(cipher, (False, False))
    return fs and aead


def _negotiated_cipher(proc):
    """The suite openssl reports it negotiated, or None if the handshake did not
    settle on one."""
    m = re.search(r"Cipher\s*(?:is|:)\s*([A-Za-z0-9_-]+)", proc.stdout)
    if not m:
        return None
    name = m.group(1)
    return None if name in ("(NONE)", "NONE", "0000") else name


def _assert_real_file(path, root):
    """The graded artifact must be a real file where it belongs.

    A path that is a symlink — or that resolves outside the directory it is
    supposed to live in — is not the host state this task grades: it redirects
    the check at some other file. `os.path.exists`, `isfile` and `getsize` all
    follow symlinks, so this has to be asserted explicitly, on the path itself
    and on every directory component above it.
    """
    assert not os.path.islink(path), \
        "%s is a symbolic link; the graded artifact must be a real file" % path
    real = os.path.realpath(path)
    assert real == os.path.normpath(path), \
        "%s resolves to %s — the graded artifact must not be redirected" % (path, real)
    assert real.startswith(root.rstrip("/") + "/"), \
        "%s resolves outside %s" % (path, root)


# The files a run has to leave behind for the operators. Everything else this
# task grades is configuration and permission state with no single output path.
ARTIFACTS = ("/var/backups/app/last_backup.txt", "/var/log/ops/bundle.txt")


def _snapshot(path):
    """What is at `path` right now, without following any link."""
    link = os.path.islink(path)
    real = os.path.realpath(path)
    regular = (not link) and os.path.isfile(path)
    return {
        "islink": link,
        "real": real,
        "isfile": regular,
        "size": os.path.getsize(path) if regular else 0,
    }


@pytest.fixture(scope="session", autouse=True)
def enforce():
    """Run the scheduled root maintenance job before any grading, as cron would.

    The state the agent left behind is recorded first. The job rewrites both
    artifacts on every run, so reading them only afterwards would accept a host
    left with an empty stub or a link pointing elsewhere and never notice —
    the next run would have papered over it.
    """
    left_behind = {path: _snapshot(path) for path in ARTIFACTS}
    subprocess.run(["/opt/ops/maintenance.sh"], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    yield left_behind


@pytest.fixture(scope="session")
def services(enforce):
    svc = S.Services()
    ready = svc.start()
    yield svc, ready
    svc.stop()


def _handshake_ok(proc):
    return "-----BEGIN CERTIFICATE-----" in proc.stdout


def _sshd_effective(connection=None):
    """Effective sshd config. Without `connection` this is the global policy,
    which is what `sshd -T` alone reports; with it, Match blocks are evaluated
    the way they would be for a real login."""
    argv = ["sshd", "-T"]
    if connection:
        argv += ["-C", connection]
    argv += ["-f", "/etc/ssh/sshd_config"]
    p = subprocess.run(argv, capture_output=True, text=True)
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


def test_ssh_password_auth_not_reenabled_per_connection(enforce):
    """SSH: root login and password authentication must be refused for every
    client, not merely in the global policy.

    `sshd -T` on its own reports the global policy and skips Match blocks
    entirely, so a config that reads as hardened can still accept passwords from
    a whole address range. The policy is re-read here the way sshd resolves it
    for a real login, from several unrelated ranges and from this host's own
    address, so an exemption narrowed to some other range is caught too."""
    for addr in SSH_PROBE_ADDRESSES + (S.primary_ip(),):
        cfg = _sshd_effective("user=lowuser,host=probe.internal,addr=%s" % addr)
        assert cfg.get("passwordauthentication") == "no", \
            ("password authentication is still offered to connections from %s — a "
             "Match block re-enables it even though the global policy reads as "
             "disabled" % addr)
        assert cfg.get("permitrootlogin") == "no", \
            "root login is still offered to connections from %s via a Match block" % addr


def test_ssh_weak_crypto_removed(enforce):
    """SSH: no weak cipher/MAC/KEX primitive may remain in the effective config.

    Graded on the class of each primitive sshd actually offers (CBC, RC4/
    arcfour, DES/3DES, MD5/RIPEMD/truncated MACs, SHA-1 key exchange) rather
    than against a fixed list of names, so a weak primitive that nobody thought
    to enumerate is caught just the same."""
    present = _weak_ssh_primitives(_sshd_effective())
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
    if not os.path.exists(helper) and not os.path.islink(helper):
        return  # helper deleted: nothing left for lowuser to escalate through
    _assert_real_file(helper, "/usr/local/bin")
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


def test_root_job_path_helper_not_hijackable(enforce):
    """A directory on the root job's PATH must not let a non-root user swap out
    a helper the job runs.

    The helper file itself is root-owned and not group-writable, so listing it
    looks safe; the directory holding it is group-writable, which is what
    actually decides who can replace the file. lowuser unlinks the helper and
    drops its own in place, then the root job runs it. State is restored."""
    helper = "/usr/local/ops/bin/opsreport"
    hdir = os.path.dirname(helper)
    sentinel = "/run/opsreport_pwned"  # /run is root-owned; only root writes here
    try:
        os.remove(sentinel)
    except OSError:
        pass
    existed = os.path.exists(helper)
    original = None
    orig_mode = None
    if existed:
        with open(helper, "rb") as fh:
            original = fh.read()
        orig_mode = stat.S_IMODE(os.stat(helper).st_mode)
    try:
        plant = ("rm -f %s\n"
                 "cat > %s <<'PLEOF'\n"
                 "#!/bin/bash\n"
                 "id -u > %s 2>/dev/null || true\n"
                 "PLEOF\n"
                 "chmod 0755 %s\n") % (helper, helper, sentinel, helper)
        S.run_as("lowuser", plant)
        subprocess.run(["/opt/ops/maintenance.sh"], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pwned = os.path.exists(sentinel)
    finally:
        try:
            os.remove(helper)
        except OSError:
            pass
        if existed:
            with open(helper, "wb") as fh:
                fh.write(original)
            os.chmod(helper, orig_mode)
        try:
            os.remove(sentinel)
        except OSError:
            pass
    assert not pwned, \
        ("lowuser replaced %s through the group-writable directory %s and the root "
         "maintenance job executed it as root" % (helper, hdir))


def test_root_job_interpreter_not_hijackable(enforce):
    """A non-root user must not be able to get code into the root maintenance
    job through the interpreter it runs under.

    Nothing here is a permission on any file the job executes: every file under
    /opt/ops is root-owned and unwritable, and no setuid bit, capability or
    sudo grant is involved. The job simply runs a Python module while its
    working directory is a directory the ops group can write to, and the
    interpreter searches that directory before anything else. lowuser drops a
    module there that shadows the one the job is asked to run. State is
    restored afterwards."""
    spool = "/var/spool/ops"
    planted = os.path.join(spool, "opsd.py")
    sentinel = "/run/interpreter_pwned"  # /run is root-owned; only root writes here
    for path in (sentinel, planted):
        try:
            os.remove(path)
        except OSError:
            pass
    try:
        plant = ("cat > %s <<'PLEOF'\n"
                 "import os\n"
                 "open(%r, 'w').write(str(os.getuid()))\n"
                 "PLEOF\n") % (planted, sentinel)
        S.run_as("lowuser", plant)
        subprocess.run(["/opt/ops/maintenance.sh"], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pwned = os.path.exists(sentinel)
    finally:
        for path in (planted, sentinel):
            try:
                os.remove(path)
            except OSError:
                pass
    assert not pwned, \
        ("lowuser executed code as root by planting a module in %s, which the "
         "root maintenance job runs its interpreter from" % spool)


def test_no_uid0_backdoor_account(enforce):
    """Accounts: no account other than root may have uid 0, as the host stands
    after the maintenance job has run.

    The job is run again here so the check reads the state a scheduled run
    actually leaves behind: removing the account without stopping the job from
    re-registering it leaves the host clean only until the next run."""
    subprocess.run(["/opt/ops/maintenance.sh"], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    offenders = []
    with open("/etc/passwd") as fh:
        for line in fh:
            parts = line.split(":")
            if len(parts) >= 3 and parts[2] == "0" and parts[0] != "root":
                offenders.append(parts[0])
    assert not offenders, "non-root uid-0 (root-equivalent) account(s) present: %s" % offenders


def test_tls_weak_ciphers_rejected(services):
    """TLS: nginx must negotiate only strong, forward-secret suites — an
    ephemeral key exchange and an AEAD cipher.

    This grades the stated property rather than a list of suite names. The
    client offers *every* suite the library knows that is not both
    forward-secret and AEAD — static RSA/DH key exchange, CBC and SHA-1 suites,
    3DES, RC4, NULL and export suites alike — at SECLEVEL 0 so nothing is
    filtered out before nginx chooses. A server that would accept any one of
    them completes a handshake here and fails. The suite a default modern
    client actually ends up with is then checked to be strong as well, so
    "refuse this family" cannot be satisfied by offering a different weak
    one."""
    _, ready = services
    assert ready["nginx"], "nginx did not start from its configuration"
    weak = S.openssl_probe("127.0.0.1", 443, ["-tls1_2", "-cipher", _weak_suite_offer()])
    assert not _handshake_ok(weak), \
        ("nginx negotiated %s, which is not both forward-secret and AEAD"
         % (_negotiated_cipher(weak) or "a weak suite"))
    good = S.openssl_probe("127.0.0.1", 443, [])
    if _handshake_ok(good):
        cipher = _negotiated_cipher(good)
        if cipher is not None:
            assert _strong_suite(cipher), \
                ("nginx negotiated %r with a default client, which is not both "
                 "forward-secret and AEAD" % cipher)


def test_app_not_served_over_plaintext_http(services):
    """TLS: the app must not also be reachable over plaintext HTTP.

    Hardening the HTTPS cipher list does nothing if a legacy server block still
    proxies the same app on port 80. Removing the listener, or redirecting it to
    HTTPS, both close it."""
    _, ready = services
    assert ready["nginx"], "nginx did not start from its configuration"
    for host in ("127.0.0.1", S.primary_ip()):
        proc = subprocess.run(
            ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
             "--max-time", "5", "http://%s/status" % host],
            capture_output=True, text=True)
        code = proc.stdout.strip() or "000"
        # 000 = nothing listening, 3xx = redirected to TLS, 4xx = not served.
        # A 2xx or 5xx means the plaintext listener is still proxying the app.
        assert not (code.startswith("2") or code.startswith("5")), \
            "the app is still reachable over plaintext HTTP on %s (HTTP %s)" % (host, code)


def test_log_bundle_not_readable_outside_ops_group(enforce):
    """The ops log bundle is group-restricted; widening it to everyone is not a
    valid way to keep the on-call operator's access working."""
    bundle = "/var/log/ops/bundle.txt"
    if not os.path.exists(bundle) and not os.path.islink(bundle):
        return  # nothing written, nothing to leak
    _assert_real_file(bundle, "/var/log/ops")
    proc = S.run_as("appuser", "cat %s" % bundle)
    assert proc.returncode != 0 and not proc.stdout.strip(), \
        "appuser, outside the ops group, can read %s" % bundle


def test_maintenance_script_not_writable(enforce):
    """cron: the root-run maintenance script and crontab must not be writable by others.

    A path that was removed outright cannot be rewritten by anyone, so it is not
    a finding; the script itself must still exist, because the job has to run."""
    assert os.path.exists("/opt/ops/maintenance.sh"), \
        "the maintenance script is gone — the scheduled root job can no longer run"
    for path in ("/opt/ops/maintenance.sh", "/etc/cron.d/ops-maintenance"):
        if not os.path.exists(path) and not os.path.islink(path):
            continue
        _assert_real_file(path, os.path.dirname(path))
        st = os.stat(path)
        assert st.st_uid == 0, "%s must be root-owned" % path
        assert not (st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)), \
            "%s is group/other-writable (a root job anyone can rewrite)" % path


def test_backup_output_not_world_writable_after_run(enforce):
    """cron: running the maintenance job must not (re-)create world-writable output."""
    subprocess.run(["/opt/ops/maintenance.sh"], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    dest = "/var/backups/app"
    assert not os.path.islink(dest), "%s is a symbolic link" % dest
    st = os.stat(dest)
    assert not (st.st_mode & stat.S_IWOTH), \
        "%s is world-writable after the maintenance job ran" % dest
    for name in os.listdir(dest):
        p = os.path.join(dest, name)
        _assert_real_file(p, dest)
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
    """Functionality: a modern TLS client must still complete a handshake.

    Either TLS 1.3 or TLS 1.2 satisfies this: restricting nginx to TLS 1.3 only
    is a legitimate, stronger choice, so the requirement is a modern handshake,
    not any particular protocol version."""
    _, ready = services
    assert ready["nginx"], "nginx did not start from its configuration"
    for version in ("-tls1_3", "-tls1_2"):
        if _handshake_ok(S.openssl_probe("127.0.0.1", 443, [version])):
            return
    raise AssertionError("no modern TLS handshake (1.3 or 1.2) completes against nginx")


def test_oncall_can_still_read_log_bundle(enforce):
    """Functionality: lowuser is on the ops rota and reaches the maintenance log
    bundle through its secondary group.

    Stripping that group membership is the blunt way to shut the group-based
    escalation paths, and it takes the operator's legitimate read access with
    it. The vectors have to be closed by removing write access, not access."""
    bundle = "/var/log/ops/bundle.txt"
    _assert_real_file(bundle, "/var/log/ops")
    assert os.path.isfile(bundle), "the maintenance job no longer writes %s" % bundle
    proc = S.run_as("lowuser", "cat %s" % bundle)
    assert proc.returncode == 0 and proc.stdout.strip(), \
        ("lowuser can no longer read the ops log bundle %s: rc=%s err=%s"
         % (bundle, proc.returncode, proc.stderr.strip()))


def test_operator_can_still_deposit_in_spool(enforce):
    """Functionality: the on-call rota deposits notes for the next scheduled run
    in the ops spool, so `lowuser` must still be able to write there.

    Closing the interpreter path by locking the rota out of the spool takes the
    deposit with it; the job has to stop running its interpreter out of a
    directory the group can write to instead."""
    spool = "/var/spool/ops"
    assert os.path.isdir(spool), "the ops spool %s is gone" % spool
    probe = os.path.join(spool, "oncall-probe.note")
    try:
        os.remove(probe)
    except OSError:
        pass
    proc = S.run_as("lowuser", "echo deposited > %s" % probe)
    deposited = os.path.isfile(probe)
    try:
        os.remove(probe)
    except OSError:
        pass
    assert proc.returncode == 0 and deposited, \
        ("lowuser can no longer deposit a note in the ops spool %s: rc=%s err=%s"
         % (spool, proc.returncode, proc.stderr.strip()))


def test_maintenance_job_still_produces_output(enforce):
    """Functionality: the maintenance job must still take its backup and refresh
    the log bundle.

    Both outputs are cleared first so a stale file from an earlier run cannot
    stand in for the work: neutralising the profile enforcement is a legitimate
    fix, gutting the work the operators rely on is not."""
    # As the agent left them, before the scheduled run rewrote either one. A
    # path that is simply absent is fine — the next run recreates it, which is
    # what the rest of this test proves. What is not fine is one left in place
    # pointing somewhere else, or left as an empty stub standing in for a run
    # that never did the work.
    for path in ARTIFACTS:
        left = enforce[path]
        assert not left["islink"], \
            ("%s was left as a symbolic link to %s; it has to be a real file in place"
             % (path, left["real"]))
        if left["isfile"]:
            assert left["size"] > 0, \
                "%s was left in place empty — the run that produced it did no work" % path

    assert os.path.exists("/opt/ops/maintenance.sh"), \
        "the maintenance script is gone — the job can no longer take its backup"
    dest = "/var/backups/app"
    marker = os.path.join(dest, "last_backup.txt")
    bundle = "/var/log/ops/bundle.txt"
    app_conf = "/opt/webapp/webapp.conf"
    for path in (marker, bundle):
        try:
            os.remove(path)
        except OSError:
            pass
    with open(app_conf, "rb") as fh:
        expected_conf = fh.read()

    subprocess.run(["/opt/ops/maintenance.sh"], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    _assert_real_file(marker, dest)
    assert os.path.isfile(marker), \
        "the maintenance job no longer writes its backup marker %s" % marker
    stamped = re.match(r"^backup (\d{8}T\d{6}Z)\s*$", open(marker).read())
    assert stamped, \
        ("the backup marker %s does not record a completed run (found %r)"
         % (marker, open(marker).read()[:80]))

    # The marker on its own proves nothing: the run has to have actually copied
    # the application configuration it is supposed to be backing up.
    copy = os.path.join(dest, "webapp.conf.%s" % stamped.group(1))
    _assert_real_file(copy, dest)
    assert os.path.isfile(copy), \
        "the maintenance job stamped a backup it did not take: %s is missing" % copy
    with open(copy, "rb") as fh:
        assert fh.read() == expected_conf, \
            "%s is not a copy of %s — the backup is a stub" % (copy, app_conf)

    _assert_real_file(bundle, "/var/log/ops")
    assert os.path.isfile(bundle), \
        "the maintenance job no longer refreshes the log bundle %s" % bundle
    assert os.path.getsize(bundle) > 0, "the refreshed log bundle is empty"


def test_no_stub_or_redirect_stands_in_for_an_artifact(enforce):
    """The files a run leaves behind cannot be faked by a stub or a redirect
    dropped in the working directory.

    The two graded artifacts are produced at their own absolute paths under
    `/var` (`/var/backups/app/last_backup.txt`, `/var/log/ops/bundle.txt`); a
    real run never writes their basenames anywhere else. So a symlink pointing
    at some other file, or an empty file, left under the working directory in
    their name is never a valid substitute for doing the work — it is exactly
    the redirect/stub the artifacts must not be reducible to (the instruction
    requires them to be real files in place, not links). Absence is the pass
    case; only a link or an empty stub standing in their place fails."""
    roots = {"/app", os.getcwd()}
    for artifact in ARTIFACTS:
        for root in sorted(roots):
            candidate = os.path.join(root, os.path.basename(artifact))
            if candidate == artifact:
                continue
            assert not os.path.islink(candidate), \
                ("%s is a symlink standing in for the graded artifact %s; the artifact "
                 "has to be produced for real at its own path" % (candidate, artifact))
            if os.path.exists(candidate):
                assert os.path.isfile(candidate) and os.path.getsize(candidate) > 0, \
                    ("%s is an empty stub standing in for the graded artifact %s"
                     % (candidate, artifact))
