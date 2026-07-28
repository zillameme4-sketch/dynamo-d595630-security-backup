"""Helpers for the verifier: boot the host's services from their on-disk
configuration and provide small clients to probe them. The agent never sees
this file (tests/ is overlaid only at verify time)."""
import os
import socket
import subprocess
import time

KEY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys", "appuser_ed25519")


def primary_ip():
    """Best-effort primary non-loopback IPv4 address of this container."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _wait_port(host, port, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.2)
    return False


class Services:
    """Starts sshd, redis, the web app and nginx; tears them down on exit."""

    def __init__(self):
        self.procs = []

    def _spawn(self, argv):
        p = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.procs.append(p)
        return p

    def start(self):
        # Clear any stale listeners from a previous partial run.
        subprocess.run(["pkill", "-f", "sshd"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["pkill", "-x", "redis-server"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["pkill", "-f", "app.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["nginx", "-c", "/etc/nginx/nginx.conf", "-s", "quit"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)

        os.makedirs("/run/sshd", exist_ok=True)
        self._spawn(["/usr/sbin/sshd", "-D", "-e"])
        self._spawn(["redis-server", "/etc/redis/redis.conf"])
        self._spawn(["su", "-s", "/bin/bash", "appuser", "-c", "python3 /opt/webapp/app.py"])
        self._spawn(["nginx", "-c", "/etc/nginx/nginx.conf", "-g", "daemon off;"])

        ready = {
            "sshd": _wait_port("127.0.0.1", 22),
            "redis": _wait_port("127.0.0.1", 6379),
            "app": _wait_port("127.0.0.1", 8080),
            "nginx": _wait_port("127.0.0.1", 443),
        }
        return ready

    def stop(self):
        for p in self.procs:
            try:
                p.terminate()
            except Exception:
                pass
        for name in ("sshd", "app.py"):
            subprocess.run(["pkill", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["pkill", "-x", "redis-server"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["nginx", "-c", "/etc/nginx/nginx.conf", "-s", "quit"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def redis_command(host, port, args, auth=None, timeout=3.0):
    """Send one RESP command; return the decoded first reply line, or an
    'ERR-CONN:<reason>' sentinel if the socket cannot be established."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        return "ERR-CONN:%s" % exc.__class__.__name__
    try:
        f = s.makefile("rwb")
        if auth is not None:
            _resp_send(f, ["AUTH", auth])
            f.readline()
        _resp_send(f, args)
        return f.readline().decode(errors="replace").strip()
    finally:
        s.close()


def _resp_send(f, args):
    out = ["*%d\r\n" % len(args)]
    for a in args:
        a = str(a)
        out.append("$%d\r\n%s\r\n" % (len(a.encode()), a))
    f.write("".join(out).encode())
    f.flush()


def ssh_run(user, host, command, key=None, extra=None, timeout=15):
    """Run an SSH command. With key=None uses BatchMode (no key), used to prove
    password/interactive auth is refused."""
    argv = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=8"]
    if key:
        argv += ["-i", key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes"]
    else:
        argv += ["-o", "BatchMode=yes", "-o", "PreferredAuthentications=password,keyboard-interactive"]
    if extra:
        argv += extra
    argv += ["%s@%s" % (user, host), command]
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


def run_as(user, command, timeout=30):
    """Run a shell command as an unprivileged user via su."""
    return subprocess.run(["su", "-s", "/bin/bash", user, "-c", command],
                          capture_output=True, text=True, timeout=timeout)


def openssl_probe(host, port, args, timeout=12):
    """Attempt a TLS handshake with openssl s_client; return CompletedProcess.
    Handshake success is detected by the presence of the server certificate in
    the transcript."""
    argv = ["openssl", "s_client", "-connect", "%s:%d" % (host, port)] + args
    return subprocess.run(argv, input="Q\n", capture_output=True, text=True, timeout=timeout)
