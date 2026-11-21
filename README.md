# `checkBridge` lets a malicious bridge quote drain any token the user holds (B-42)

**Surface:** Bull.family SDK `checkBridge` + `bull.bridge.send()` (`sdk/bull.mjs`, sha `f450d44d…`).
**Severity:** Major. **Status:** candidate — forge PoC green, see below.
**Bounty:** Bull.family bug bounty (Major $100–$500). **Contact:** X [@brian_byar17103](https://x.com/brian_byar17103).

## What

`checkBridge` — the SDK's only gate on bridge quotes — checks the *shape* of the
steps (at most 4, recipient is the user, chain IDs, `from`, address format,
value == 0, data is valid hex) and, only for calldata starting with the
lowercase string `"0x095ea7b3"`, that an approval goes to the origin token and
does not exceed the bridge amount. It has no allowlist of step targets and never
rejects the `transfer`, `transferFrom`, or `increaseAllowance` selectors.
`bridge.send()` then executes every step verbatim from the user's wallet. A
malicious server or Relay returning a one-step quote
`transfer(attacker, <the user's full balance>)` on ANY token the user holds
passes every check and is executed — while the quote's `recipient` field still
names the user.

Two more bypasses of the same gate, proven in the same run:

- `increaseAllowance(attacker, max)` is not an `approve` prefix, so it passes
  unchecked; the attacker then drains the full balance with `transferFrom`.
- An approve with an UPPERCASE selector (`"0x095EA7B3…"`) is not recognized by
  the case-sensitive `startsWith("0x095ea7b3")` check, so the amount cap and
  token check are skipped; the decoded bytes are still a valid approve, and the
  attacker drains via `transferFrom` (proven: 250, ten times the bridge amount,
  on the wrong token).

A third gap: the Bull-API quote path runs `checkBridge` directly on the server
JSON with no output validation at all — the ≥95% expected-output check exists
only on the direct-Relay path.

## How (reproduced)

`chain/test/Round23A.t.sol` is a line-by-line Solidity model of `checkBridge` +
`send()` over the same hex-string calldata. The case distinction is preserved
by checking as a string and decoding to bytes only at execution — exactly the
layer where the case-sensitivity bug lives. The model is validated by 9
rejection controls plus 1 legit-approve control, all green with the exact JS
revert messages:

- **K-1605 (main):** user holds 1000 of an arbitrary token (not the bridge
  token). Quote: 1 step `transfer(attacker, 1000)` → check PASSES → send
  executes → attacker +1000, user 0.
- **K-1606:** `increaseAllowance(attacker, max)` → passes → attacker
  `transferFrom` drains 1000.
- **K-1607:** uppercase approve `0x095EA7B3…` amount 250 (10x bridge amount)
  on the wrong token → passes → attacker drains 250 via `transferFrom`.
- **Controls:** legit approve (lowercase, correct token, amount == bridge
  amount) passes with allowance == amount; over-cap approve, wrong-token
  approve, value ≠ 0, wrong `from`, wrong recipient, 5 steps, wrong toChainId,
  wrong step chainId, invalid hex data are ALL rejected.

## Impact

A malicious or compromised Bull server / Relay (the SDK's own stated threat
model — the same as B-15/B-23) drains the user's ENTIRE balance of any ERC-20
token they hold, in a single bridge quote, with a single step — no further
approval from the user beyond executing the bridge they believed was safe. The
drain is bounded only by the user's token balances: the transfer step does not
use the bridge amount cap (10.000/unit).

## Suggested fix

In `checkBridge`: (1) allowlist step selectors — only `approve` to the origin
token, and calls to the known Relay router; reject `transfer`/`transferFrom`/
`increaseAllowance` and any other selector outright; (2) compare selectors as
bytes (or `data.toLowerCase()`) before the approve branch; (3) validate the
quote output (expectedOut ≥ 95%) on ALL paths, including the Bull-API path.

## Honest caveats

- The proof is a faithful line-by-line Solidity re-implementation of
  `checkBridge` + `send()`, NOT live JS execution. Executing the live JS was
  safeguard-blocked twice in round 22 and was correctly not retried or
  reworded; the model is validated by 9 rejection controls + 1 legit-approve
  control, all green with the exact JS revert messages.
- The Bull-API bridge path currently answers 503 "bridge not configured" until
  `RELAY_API_KEY` is set (llms.txt:59), so that path may be inert today. The
  direct-Relay path (`relayApiKey`) is live code and uses the same
  `checkBridge` gate.

## Run the PoC

```bash
./run.sh      # forge test; exits 0 when the bug reproduces (19/19 PASS)
```

Everything runs on local Foundry; no mainnet transactions, no real funds.
