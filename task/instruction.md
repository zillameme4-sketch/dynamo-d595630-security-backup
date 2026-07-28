You have root on a small internal host whose services have accumulated years of loose configuration. Review the host and harden it, without breaking what runs on it.

The host runs these services, with configuration on disk at:

- OpenSSH server — `/etc/ssh/sshd_config` plus drop-ins in `/etc/ssh/sshd_config.d/`.
- Redis cache — `/etc/redis/redis.conf`; used by the web app below.
- nginx TLS reverse proxy — `/etc/nginx/nginx.conf`, certificate and key in `/etc/nginx/certs/`, proxying to the app on `127.0.0.1:8080`.
- Internal web app — `/opt/webapp/app.py`, config `/opt/webapp/webapp.conf`; serves `GET /status`, which round-trips a value through Redis.
- Root backup job — `/opt/backup/backup.sh`, scheduled by `/etc/cron.d/app-backup`.

Two non-root accounts exist: `appuser` (owns the app and is the only account that logs in over SSH, using a key already in its `authorized_keys`) and `lowuser` (an unprivileged local account). Also review setuid-root programs on the host and the sudo grants under `/etc/sudoers.d/`.

Harden the host against standard misconfigurations across authentication, network exposure, privilege escalation (sudo and setuid), filesystem permissions, and transport security. The verifier restarts every service from its on-disk configuration and actively tries to exploit weaknesses, so runtime-only changes do not count — fix the configuration and files on disk. Services are launched as: `/usr/sbin/sshd`, `redis-server /etc/redis/redis.conf`, `python3 /opt/webapp/app.py` (run as `appuser`), and `nginx -c /etc/nginx/nginx.conf`. The backup job is run as `root` via `/opt/backup/backup.sh`.

All of the following are graded pass/fail and must hold together.

Security — each of these must be closed:
- Remote root login and password-based SSH authentication are refused, and the SSH server offers no weak cipher, MAC, or key-exchange algorithm.
- The Redis cache cannot be used without authentication, and it is not reachable unauthenticated on the host's public network interface.
- `lowuser` cannot escalate to root through sudo or through any setuid-root program.
- The backup script and its crontab cannot be modified by non-root users, and running the backup job leaves no world-writable files behind.
- nginx negotiates only strong, forward-secret cipher suites.

Functionality — none of these may regress:
- `appuser` can still log in over SSH with its existing key and run a command.
- `GET https://127.0.0.1/status` through nginx returns JSON whose `cache` field equals `healthy` (the app must still reach Redis).
- Running `/opt/backup/backup.sh` still succeeds and writes its output under `/var/backups/app`.

There are no output files to produce: the graded artifact is the resulting state of the host's configuration and files.
