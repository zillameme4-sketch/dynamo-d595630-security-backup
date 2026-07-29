You have root on a small internal host whose services have accumulated years of loose configuration and a drifted "compliance" baseline. Review the host and harden it, without breaking what runs on it.

The host runs, and must keep running, these services:

- an OpenSSH server;
- a Redis cache, used by the web app below;
- an nginx TLS reverse proxy, terminating HTTPS on 443 and proxying to the app on `127.0.0.1:8080`;
- an internal web app (`/opt/webapp/`, run as `appuser`) that serves `GET /status`, which round-trips a value through Redis.

Their configuration is on disk in the usual places under `/etc` and `/opt`. Part of the job is to find where the effective settings actually come from — some services pull in additional configuration that overrides what the primary file appears to say.

A **root maintenance job** also runs on this host on a schedule. It takes a backup that operators rely on, and it re-applies a saved configuration baseline so the box "stays in a known state." **The verifier runs this job as root before it grades.** Treat it as adversarial to sloppy fixes: it reconciles its baseline against a stored source of truth, so a change you make to the live configuration (or to the baseline) that the job later reverts does not count. Whatever you do must still hold *after* the job has run — and the job must still complete its backup.

Two local accounts exist besides root: `appuser`, which owns the app and is the only account that logs in over SSH (using a key already in its `authorized_keys`), and `lowuser`, an unprivileged account that also belongs to a secondary group used by the ops tooling. Assume an attacker has `lowuser`'s shell and audit every path from there to root — sudo grants, setuid-root programs, Linux file capabilities, group-writable files that a privileged job executes, and any other account that is root-equivalent.

Harden the host against standard misconfigurations across authentication, network exposure, privilege escalation, filesystem permissions, and transport security. The specific weaknesses are for you to discover. The verifier restarts every service from its on-disk configuration and actively tries to exploit weaknesses, so runtime-only changes do not count — fix the configuration and files on disk. Services are launched as: `/usr/sbin/sshd`, `redis-server /etc/redis/redis.conf`, `python3 /opt/webapp/app.py` (run as `appuser`), and `nginx -c /etc/nginx/nginx.conf`.

All of the following are graded pass/fail and must hold together, and must still hold after the maintenance job has run.

Security — each of these must be closed:
- Remote root login and password-based SSH authentication are refused, and the SSH server offers no weak cipher, MAC, or key-exchange algorithm.
- The Redis cache cannot be used without authentication, and it is not reachable unauthenticated on the host's public network interface.
- `lowuser` cannot escalate to root — through sudo, through any setuid-root program, through any Linux file capability, through any file that a privileged (root) scheduled job executes, or through any other account.
- No account other than root has uid 0.
- The maintenance script, its crontab, and any helper the maintenance job runs cannot be modified by non-root users, and running the maintenance job leaves no world-writable files behind.
- nginx negotiates only strong, forward-secret cipher suites.

Functionality — none of these may regress:
- `appuser` can still log in over SSH with its existing key and run a command.
- `GET https://127.0.0.1/status` through nginx returns JSON whose `cache` field equals `healthy` (the app must still reach Redis).
- Running the maintenance job still succeeds and writes its backup under `/var/backups/app`.

There are no output files to produce: the graded artifact is the resulting state of the host's configuration and files.
