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
server block, plus a legacy plaintext `:80` block still proxying the same app).

The SSH password policy is enforced twice: alongside the global setting in the
drop-in, the job appends a `Match Address 10.0.0.0/8` block to the end of the
main `sshd_config` that hands password authentication back for that range.
`sshd -T` — how every auditor checks this — reports only the global policy and
skips `Match` blocks, so the config reads as hardened while real logins are still
offered a password. Resolving it needs `sshd -T -C user=…,addr=…`, and closing it
needs a profile control separate from the one that sets the global policy.

The Redis credential is the sharpest of them: the job renders `requirepass` into
the last-wins include from a profile key that ships as `none`, i.e.
`requirepass ""`, and an empty `requirepass` in a later include **silently
disables** an earlier one. Adding `requirepass` to `redis.conf` therefore leaves
the cache open while the file the agent reads back still shows the password — and
it breaks the app at the same time, since the app then authenticates against a
server that is not asking for a password.

The central difficulty: the verifier **runs the maintenance job before grading**,
so hardening only the live configuration is silently reverted. The job's logic is
an ops Python package, [`task/environment/data/ops/opsd/`](task/environment/data/ops/opsd/),
which `/opt/ops/maintenance.sh` invokes — a plausible, documented, working package
with a CLI and a conformance reporter, not a script that can be skimmed in one
read. Two things in it decide the task.

`opsd.changecontrol` enforces change control on the profile against a recorded
**SHA-256 of the profile's canonical form**. On a mismatch it restores the
vendored copy (`/usr/share/ops/host-profile.dist`), or, if that copy is not
approved either, the profile the build shipped with. Mirroring secure values
across both data files is therefore undone as well: the recorded digest has to be
recomputed from the canonicalisation the package documents, or the reconciliation
neutralized, while the backup and the log bundle keep working. Because the
approved configuration is stored only as a hash, it cannot be read off and copied.

`opsd.inventory` is the crux, and it survives a completely correct profile.
Before anything is rendered, it reconciles the host against what the build
vendored — the helper programs the job invokes, the directories a run needs, and
the **service accounts the tooling is registered against**, read from
`/usr/share/ops/vendor/service-accounts.tsv`, which records `toolsvc` at uid 0.
Deleting that account is the obvious remediation and the one weakness the profile
has no control for, so a fixer who closes everything else, sets every control,
recomputes the digest and re-runs the job still fails: the account is
re-registered, at uid 0, at the start of the run that grades them (renumbering it
is corrected back the same way, and deleting the group-writable helper *directory*
rather than fixing its mode re-creates it group-writable). Nothing is visible in
between — `/etc/passwd` is clean the whole time the fixer is looking at it — and
the host's own tooling confirms the wrong conclusion: `python3 -m opsd verify`
reports every control applied and the profile matching the approved digest,
because it is a conformance report against the profile and accounts are not one
of the profile's controls. The vendored record, or the code that reads it, is
what has to change.

And one weakness has no object at all. `/opt/ops/maintenance.sh` `cd`s into
`/var/spool/ops` before `python3 -m opsd apply` — the helpers it runs write
scratch files without a path, and the on-call rota collects them from the spool,
which is why the spool is group-writable and why a graded functionality check
requires it to stay that way. A Python interpreter searches its **working
directory ahead of `PYTHONPATH` and the standard library**, so anyone in that
group can drop a module there and have the root job import it. No sweep shows
it: no setuid bit, no capability, no sudo grant, no group-writable *file*, and —
unlike every other vector here — no wrong line of code anywhere. It exists only
in the interaction between a `cd` in a shell wrapper and a directory mode.
Locking the group out of the spool regresses the deposit check, so the fix is to
keep the working directory off `sys.path` (`-P` / `PYTHONSAFEPATH`) or not to run
the interpreter from the spool at all.

The job additionally owns `/etc/ssh/sshd_config.d` and clears any drop-in it did
not place, so SSH cannot be hardened with a private drop-in. The profile's keys
are ops-jargon and deliberately do not map one-to-one onto weaknesses — one
control covers the sudo grant, the setuid helper and the file capability together,
and `opsd` only ever *grants* those privileges, never revokes them — so the
vectors must be confirmed by auditing the host (`sshd -T`, `sudo -l`,
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
maintenance job's backup and log-bundle refresh, and the on-call operator's read
access to the bundle must all keep working.

## How it is graded

[`task/tests/test_outputs.py`](task/tests/test_outputs.py) boots every service
from its on-disk configuration and grades behaviorally: it *attacks* each planted
weakness (each attack must now fail) and *exercises* the real service chain (none
may regress). All 24 checks must pass — reward is all-or-nothing, so partial
remediation and over-hardening (wiping keys, denying the app, gutting the
maintenance backup or the log bundle) both fail. Closing a vector by removing the vulnerable object
outright is accepted where it genuinely closes it. Every graded path is rejected
if it is a symlink or resolves outside where it belongs, and the two files a run
leaves behind are snapshotted before the job runs, so an empty stub or a
redirected path cannot be papered over by the run that would rewrite it. The reference solution is
[`task/solution/solve.py`](task/solution/solve.py).

Validated locally: `harbor run -p task --agent oracle` → reward `1.0`;
`harbor run -p task --agent nop` → reward `0.0`.
