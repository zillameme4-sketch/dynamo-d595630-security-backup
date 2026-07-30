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
helper script the root job executes, a root-owned helper on the job's PATH living
in a group-writable *directory* — the file's own mode looks clean, so hardening
it does not close the hole — and a leftover uid-0 account), filesystem
permissions (a world-writable root-run script and world-writable backup output),
and transport security (a non-forward-secret cipher suite in an nginx `conf.d`
server block).

The central difficulty: the verifier **runs the maintenance job before grading**,
so hardening only the live configuration is silently reverted. The job also
enforces change control *against itself* — it compares the active profile
(`/etc/ops/host-profile.conf`) against an approved set of settings hard-coded
inside the job, and on a mismatch rolls the profile back, falling back to
re-rendering the approved settings when the vendored copy
(`/usr/share/ops/host-profile.dist`) has been edited too. Mirroring secure values
across both data files is therefore undone as well: the approved set has to
agree, or the enforcement has to be neutralized, while the backup keeps working.
The job additionally owns `/etc/ssh/sshd_config.d` and clears any drop-in it did
not place, so SSH cannot be hardened with a private drop-in. The profile's keys
are ops-jargon and deliberately do not map one-to-one onto weaknesses — one knob
covers the sudo grant, the setuid helper and the file capability together — so
the vectors must be confirmed by auditing the host (`sshd -T`, `sudo -l`,
`getcap -r /`, `/etc/passwd`) rather than read off a file. Several also hide
behind config precedence (SSH `Include`, redis/nginx includes) or off the service
configs entirely (`/etc/passwd`, file capabilities).

Three of the escalation paths — the sudo grant, the writable collector and the
writable helper directory — all reach `lowuser` through one secondary group, so
the tempting single move is to drop it out of that group. The same membership is
how the on-call operator reads the maintenance log bundle, which is graded, so
the blunt fix regresses functionality: each path has to be closed by removing
what `lowuser` can *write*, not its access.

The agent must **harden the host in place without breaking the service chain**:
`appuser` key-based SSH login, the `HTTPS → nginx → app → Redis` round-trip, the
maintenance job's backup, and the on-call operator's read access to the log
bundle must all keep working.

## How it is graded

[`task/tests/test_outputs.py`](task/tests/test_outputs.py) boots every service
from its on-disk configuration and grades behaviorally: it *attacks* each planted
weakness (each attack must now fail) and *exercises* the real service chain (none
may regress). All 19 checks must pass — reward is all-or-nothing, so partial
remediation and over-hardening (wiping keys, denying the app, gutting the
maintenance backup) both fail. Closing a vector by removing the vulnerable object
outright is accepted where it genuinely closes it. The reference solution is
[`task/solution/solve.py`](task/solution/solve.py).

Validated locally: `harbor run -p task --agent oracle` → reward `1.0`;
`harbor run -p task --agent nop` → reward `0.0`.
