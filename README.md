# dynamo/harden-multiservice-host

A Security / **security hardening** Harbor task. The whole task lives in
[`task/`](task/); everything else (`.github/`, `references/`) is review
infrastructure.

## What the task is

The agent is given root on a synthetic multi-service Linux host (built entirely
by [`task/environment/Dockerfile`](task/environment/Dockerfile)) that runs
`sshd`, `redis`, an `nginx` TLS reverse proxy in front of a small internal web
app, a root `cron` backup job, a setuid-root helper and `sudo` grants. The
image plants ~9 independent weaknesses across five layers — authentication
(SSH root/password login, weak ciphers/MACs/KEX), network exposure (Redis on
`0.0.0.0` with no auth), privilege escalation (a passwordless GTFOBins `sudo
find` grant and a setuid-root binary), filesystem permissions (a world-writable
root-executed backup script/crontab), and transport security (non-forward-secret
TLS cipher suites).

The agent must **harden the host in place without breaking the service chain**:
`appuser` key-based SSH login, the `HTTPS → nginx → app → Redis` round-trip, and
the backup job must all keep working.

## How it is graded

[`task/tests/test_outputs.py`](task/tests/test_outputs.py) boots every service
from its on-disk configuration and grades behaviorally: it *attacks* each planted
weakness (each attack must now fail) and *exercises* the real service chain (none
may regress). Reward is all-or-nothing, so partial remediation or over-hardening
(wiping keys, denying the app) both fail. The reference solution is
[`task/solution/solve.py`](task/solution/solve.py).

Validated locally: `harbor run -p task --agent oracle` → reward `1.0`;
`harbor run -p task --agent nop` → reward `0.0`.
