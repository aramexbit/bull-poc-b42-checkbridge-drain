#!/bin/bash
# Run the B-42 PoC end to end: forge test (Round23A) modelling checkBridge + send().
# Exits 0 when the bug reproduces, 1 when it does not.
set -u
cd "$(dirname "$0")/chain"
FORGE="${FORGE:-$HOME/.foundry/bin/forge}"
"$FORGE" test 2>&1 | tee /tmp/b42-forge.log
RC=${PIPESTATUS[0]}
if grep -q "19 passed" /tmp/b42-forge.log; then
  echo "B-42 reproduced: checkBridge lets a malicious bridge quote drain any token (19/19 PASS)"
  exit 0
fi
echo "B-42 NOT reproduced (forge rc=$RC)"
exit 1
