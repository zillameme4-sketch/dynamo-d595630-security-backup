#!/bin/bash
# Runs inside the shared environment image. pytest is baked into the image, so
# nothing is installed here. Ground truth (the appuser private key, the service
# launcher) lives in tests/ and is overlaid at /tests only at verify time.
set -uo pipefail

mkdir -p /logs/verifier
chmod 700 /tests 2>/dev/null || true
chmod 600 /tests/keys/appuser_ed25519 2>/dev/null || true

cd /tests
PYTHONPATH=/tests pytest /tests/test_outputs.py --ctrf /logs/verifier/ctrf.json -rA
status=$?

if [ "$status" -eq 0 ]; then
  echo 1 > /logs/verifier/reward.txt
else
  echo 0 > /logs/verifier/reward.txt
fi
exit 0
