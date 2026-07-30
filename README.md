# dynamo/harden-multiservice-host

A Security / **security hardening** Harbor task. The whole task lives in
[`task/`](task/); everything else (`.github/`, `references/`) is review
infrastructure.

## What the task is

The agent is given root on a synthetic multi-service Linux host (built entirely
by [`task/environment/Dockerfile`](task/environment/Dockerfile)) that runs
`sshd`, `redis`, an `nginx` TLS reverse proxy in front of a small internal web
app, and a **root maintenance/cron job that re-applies an insecure baseline on
every run**. Weaknesses span five layers — authentication (SSH root/password
login, weak ciphers/MACs/KEX), network exposure (Redis effectively on `0.0.0.0`
with no auth, via a last-wins `include`), privilege escalation (a group-based
passwordless GTFOBins `sudo awk` grant, a setuid-root helper, a `cap_setuid+ep`
file capability that a `find -perm -4000` sweep never reveals, a group-writable
helper script the root job executes, and a leftover uid-0 account), filesystem
permissions (a world-writable root-run script and world-writable backup output),
and transport security (a non-forward-secret cipher suite in an nginx `conf.d`
server block).

The central difficulty: the verifier **runs the maintenance job before grading**,
so hardening only the live configuration is silently reverted. The job is also
*self-healing* — it reconciles the active baseline (`/opt/ops/baseline.env`)
against a vendored source of truth (`/usr/share/ops/baseline.env.dist`) through a
checksum manifest (`/var/lib/ops/baseline.sha256`) and restores the vendored
insecure copy on drift, so editing `baseline.env` alone is reverted too. A fix
has to correct the whole enforcement chain or neutralize the reconcile, while
keeping the backup working. Several vectors also hide behind config precedence
(SSH `Include`, redis/nginx includes) or off the service configs entirely
(`/etc/passwd`, file capabilities).

The agent must **harden the host in place without breaking the service chain**:
`appuser` key-based SSH login, the `HTTPS → nginx → app → Redis` round-trip, and
the maintenance job's backup must all keep working.

## How it is graded

[`task/tests/test_outputs.py`](task/tests/test_outputs.py) boots every service
from its on-disk configuration and grades behaviorally: it *attacks* each planted
weakness (each attack must now fail) and *exercises* the real service chain (none
may regress). All 17 checks must pass — reward is all-or-nothing, so partial
remediation and over-hardening (wiping keys, denying the app, gutting the
maintenance backup) both fail. Closing a vector by removing the vulnerable object
outright is accepted where it genuinely closes it. The reference solution is
[`task/solution/solve.py`](task/solution/solve.py).

Validated locally: `harbor run -p task --agent oracle` → reward `1.0`;
`harbor run -p task --agent nop` → reward `0.0`.
