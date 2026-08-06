#!/bin/bash
# Runs inside the shared environment image. pytest is baked into the image, so
# nothing is installed here. Ground truth (the appuser private key, the service
# launcher) lives in tests/ and is overlaid at /tests only at verify time.
set -uo pipefail

mkdir -p /logs/verifier
chmod 700 /tests 2>/dev/null || true
chmod 600 /tests/keys/appuser_ed25519 2>/dev/null || true

REWARD=/logs/verifier/reward.txt

# The verifier runs the host's root maintenance job before it grades, because
# that job re-applying its baseline is the thing being graded against. The job
# is agent-writable by design, and it runs as root in this container -- so the
# grading material and the reward are protected here rather than assumed:
#
#   * /tests is fingerprinted before pytest starts and again after it finishes;
#     any change to the assertions, the launcher or the appuser key during the
#     run forces a 0 regardless of what pytest reported.
#   * the reward is written only by this script, from pytest's exit status,
#     after the fingerprint check -- never left as whatever was on disk. Any
#     file already at that path (including a symlink pointing elsewhere, or an
#     immutable placeholder) is cleared first and the write is read back, so a
#     reward this script did not produce is never the one that counts.
manifest() {
    find /tests -type f \
        ! -name '*.pyc' \
        ! -path '*/__pycache__/*' \
        ! -path '*/.pytest_cache/*' \
        -print0 2>/dev/null | LC_ALL=C sort -z | xargs -0 sha256sum 2>/dev/null | sha256sum
}

write_reward() {
    value="$1"
    chattr -i "$REWARD" 2>/dev/null || true
    rm -f "$REWARD" 2>/dev/null || true
    printf '%s\n' "$value" > "$REWARD" 2>/dev/null || true
    if [ "$(cat "$REWARD" 2>/dev/null)" != "$value" ]; then
        # The path is not ours to write. Take it out from under whatever is
        # holding it and try once more; if that still fails the run is not
        # gradable, and a reward nobody could write is not a pass.
        chattr -ia "$REWARD" 2>/dev/null || true
        unlink "$REWARD" 2>/dev/null || rm -rf "$REWARD" 2>/dev/null || true
        printf '%s\n' "$value" > "$REWARD" 2>/dev/null || true
    fi
}

chattr -i "$REWARD" 2>/dev/null || true
rm -f "$REWARD" 2>/dev/null || true

before=$(manifest)

cd /tests
PYTHONPATH=/tests pytest /tests/test_outputs.py --ctrf /logs/verifier/ctrf.json -rA
status=$?

after=$(manifest)
if [ "$before" != "$after" ]; then
    echo "verification material under /tests changed during the run — grading it 0" >&2
    status=1
fi

if [ "$status" -eq 0 ]; then
  write_reward 1
else
  write_reward 0
fi
exit 0
