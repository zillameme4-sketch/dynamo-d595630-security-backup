# Backup — dynamo-d595630-security

Snapshot taken 2026-08-07 of the task repo `dynamo-d595630-security`
(Project Dynamo task `dynamo/harden-multiservice-host`).

## What is here

| Ref | Contents |
| --- | --- |
| `main` | full history of the upstream main branch (`e4ad03e`) |
| `submission` | full history of the working/submission branch (`fbe0326`, 23 commits) |
| `backup-20260807` (tag) | pins the snapshot point on `submission` |
| `snapshot-20260807` (this branch) | this note plus `SHA256SUMS.txt` |

The file content is preserved as real git history, not as an archive, so any
revision can be recovered with an ordinary `git checkout`.

## Source

- Origin: `handshake-project-dynamo/dynamo-d595630-security`
- Fork the work was pushed from: `zillameme4-sketch/dynamo-d595630-security`, branch `submission`
- Snapshot commit: `fbe03268ab7e09ec6c4887991943f86d6a3a6f28` (2026-08-07 12:46:27 +0000)

## Files covered

47 files, ~340 KB, listed with SHA-256 digests in `SHA256SUMS.txt`:

- `task/instruction.md`, `task/task.toml`
- `task/environment/` — Dockerfile, `.dockerignore`, and the seeded host data
  (`data/etc`, `data/ops` including the `opsd` package, `data/webapp`)
- `task/solution/` — `solve.sh`, `solve.py`
- `task/tests/` — `test.sh`, `test_outputs.py`, `servicelib.py`, `keys/`
- `README.md`, `references/`, `.github/`

Excluded: `.git`, `__pycache__`, `*.pyc`, `.pytest_cache`.

## Verifying

    git checkout backup-20260807
    git ls-files -z | sort -z | xargs -0 sha256sum > /tmp/now.txt
    diff /tmp/now.txt SHA256SUMS.txt

`SHA256SUMS.txt` paths are relative to the repository root and prefixed `./`.
