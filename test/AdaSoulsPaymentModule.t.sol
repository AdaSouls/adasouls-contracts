// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {Safe} from "@safe/Safe.sol";
import {SafeProxyFactory} from "@safe/proxies/SafeProxyFactory.sol";
import {Enum} from "@safe/common/Enum.sol";
import {SCL_EIP6565_UTILS} from "@solidity/lib/libSCL_eddsaUtils.sol";
import {AdaSoulsPaymentModule} from "../src/AdaSoulsPaymentModule.sol";

contract TestToken {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        if (balanceOf[msg.sender] < amount) return false;
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// Against a real Safe (v1.4.1): its owners install and set up the module with Safe transactions,
/// the agent pays through it, and AdaSouls only ever signs.
contract AdaSoulsPaymentModuleTest is Test {
    AdaSoulsPaymentModule module;
    Safe safe;
    TestToken token;

    uint256 ownerKey = 0xA11CE;
    address owner = vm.addr(ownerKey);
    address agent = makeAddr("agent");
    address payee = makeAddr("payee owner's payout wallet");

    // AdaSouls' issuer key, for the test only: in production it is in KMS and signs off-chain.
    uint256 issuerSeed = uint256(keccak256("adasouls issuer, test only"));
    bytes32 issuerKey;

    uint128 constant CAP = 100e6;
    uint64 constant DAY = 1 days;

    function setUp() public {
        vm.warp(1_800_000_000);
        module = new AdaSoulsPaymentModule();
        token = new TestToken();

        Safe singleton = new Safe();
        SafeProxyFactory factory = new SafeProxyFactory();
        address[] memory owners = new address[](1);
        owners[0] = owner;
        bytes memory init =
            abi.encodeCall(Safe.setup, (owners, 1, address(0), "", address(0), address(0), 0, payable(address(0))));
        safe = Safe(payable(address(factory.createProxyWithNonce(address(singleton), init, 0))));
        token.mint(address(safe), 1_000e6);

        (uint256[5] memory extKpub,) = SCL_EIP6565_UTILS.SetKey(issuerSeed);
        issuerKey = bytes32(extKpub[4]);

        // What the owners do, each step a Safe transaction they sign.
        asOwners(address(safe), abi.encodeCall(safe.enableModule, (address(module))));
        asOwners(address(module), abi.encodeCall(module.setAgent, (agent)));
        asOwners(address(module), abi.encodeCall(module.acceptKey, (issuerKey)));
        asOwners(address(module), abi.encodeCall(module.setCap, (address(token), CAP, DAY)));
    }

    function asOwners(address to, bytes memory data) internal {
        bytes memory signature = ownerSignature(to, data);
        assertTrue(
            safe.execTransaction(to, 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), signature)
        );
    }

    function ownerSignature(address to, bytes memory data) internal view returns (bytes memory) {
        bytes32 hash =
            safe.getTransactionHash(to, 0, data, Enum.Operation.Call, 0, 0, 0, address(0), address(0), safe.nonce());
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        return abi.encodePacked(r, s, v);
    }

    function authorization(uint256 amount, bytes32 nonce)
        internal
        view
        returns (AdaSoulsPaymentModule.Authorization memory)
    {
        return AdaSoulsPaymentModule.Authorization({
            chainId: block.chainid,
            module: address(module),
            safe: address(safe),
            token: address(token),
            to: payee,
            amount: amount,
            nonce: nonce,
            expiresAt: uint64(block.timestamp + 1 hours)
        });
    }

    /// What AdaSouls does off-chain (alma-core's signPaymentAuthorization), done here with the library's RFC 8032 signer.
    function signed(AdaSoulsPaymentModule.Authorization memory a) internal view returns (bytes memory) {
        (uint256 r, uint256 s) =
            SCL_EIP6565_UTILS.SignSlow(issuerSeed, string(abi.encodePacked(module.authorizationDigest(a))));
        return abi.encodePacked(bytes32(r), bytes32(s));
    }

    function pay(AdaSoulsPaymentModule.Authorization memory a, bytes memory sig) internal {
        vm.prank(agent);
        module.pay(a, issuerKey, sig);
    }

    // ---------- What it does ----------

    function test_pays_exactly_what_was_authorized_once() public {
        AdaSoulsPaymentModule.Authorization memory a = authorization(25e6, keccak256("n1"));
        bytes memory sig = signed(a);

        vm.expectEmit(address(module));
        emit AdaSoulsPaymentModule.Paid(address(safe), a.nonce, address(token), payee, 25e6, issuerKey);
        vm.prank(agent);
        uint256 g = gasleft();
        module.pay(a, issuerKey, sig);
        console.log("pay(), whole call through a real Safe, gas:", g - gasleft());

        assertEq(token.balanceOf(payee), 25e6);
        assertEq(token.balanceOf(address(safe)), 975e6);
        assertTrue(module.nonceUsed(address(safe), a.nonce));

        vm.expectRevert(AdaSoulsPaymentModule.NonceAlreadyUsed.selector);
        pay(a, sig);
    }

    function test_owner_setup_gas() public {
        bytes32 otherKey = bytes32(uint256(issuerKey) ^ 0); // the same key again: its cost is the derivation
        uint256 g = gasleft();
        vm.prank(address(safe));
        module.acceptKey(otherKey);
        console.log("acceptKey(), once per key per Safe, gas:", g - gasleft());
    }

    // ---------- What it refuses ----------

    function test_only_the_safes_agent_can_submit() public {
        AdaSoulsPaymentModule.Authorization memory a = authorization(25e6, keccak256("n"));
        bytes memory sig = signed(a);
        for (uint256 i = 0; i < 3; i++) {
            address caller = [owner, makeAddr("stranger"), address(this)][i];
            vm.prank(caller);
            vm.expectRevert(AdaSoulsPaymentModule.NotTheAgent.selector);
            module.pay(a, issuerKey, sig);
        }
    }

    function test_a_changed_field_breaks_the_signature() public {
        AdaSoulsPaymentModule.Authorization memory a = authorization(25e6, keccak256("n"));
        bytes memory sig = signed(a);

        AdaSoulsPaymentModule.Authorization memory more = authorization(26e6, keccak256("n"));
        vm.expectRevert(AdaSoulsPaymentModule.BadSignature.selector);
        pay(more, sig);

        AdaSoulsPaymentModule.Authorization memory elsewhere = authorization(25e6, keccak256("n"));
        elsewhere.to = makeAddr("someone else");
        vm.expectRevert(AdaSoulsPaymentModule.BadSignature.selector);
        pay(elsewhere, sig);

        bytes memory forged = abi.encodePacked(sig);
        forged[63] = forged[63] ^ 0x01;
        vm.expectRevert(AdaSoulsPaymentModule.BadSignature.selector);
        pay(a, forged);

        vm.expectRevert(AdaSoulsPaymentModule.BadSignature.selector);
        pay(a, abi.encodePacked(bytes32(0)));
        assertEq(token.balanceOf(payee), 0);
    }

    function test_expired_or_for_another_chain_or_module() public {
        AdaSoulsPaymentModule.Authorization memory a = authorization(25e6, keccak256("n"));
        bytes memory sig = signed(a);

        AdaSoulsPaymentModule.Authorization memory otherChain = authorization(25e6, keccak256("n"));
        otherChain.chainId = 1;
        bytes memory otherChainSig = signed(otherChain);
        vm.expectRevert(AdaSoulsPaymentModule.WrongChainOrModule.selector);
        pay(otherChain, otherChainSig);

        AdaSoulsPaymentModule.Authorization memory otherModule = authorization(25e6, keccak256("n"));
        otherModule.module = makeAddr("another module");
        bytes memory otherModuleSig = signed(otherModule);
        vm.expectRevert(AdaSoulsPaymentModule.WrongChainOrModule.selector);
        pay(otherModule, otherModuleSig);

        vm.warp(a.expiresAt);
        vm.expectRevert(AdaSoulsPaymentModule.Expired.selector);
        pay(a, sig);
    }

    function test_only_keys_the_owners_accepted() public {
        AdaSoulsPaymentModule.Authorization memory a = authorization(25e6, keccak256("n"));
        bytes memory sig = signed(a);

        vm.prank(agent);
        vm.expectRevert(AdaSoulsPaymentModule.KeyNotAccepted.selector);
        module.pay(a, bytes32(uint256(issuerKey) + 1), sig);

        asOwners(address(module), abi.encodeCall(module.removeKey, (issuerKey)));
        assertFalse(module.isKeyAccepted(address(safe), issuerKey));
        vm.expectRevert(AdaSoulsPaymentModule.KeyNotAccepted.selector);
        pay(a, sig);
    }

    function test_the_cap_holds_per_period_and_a_token_without_one_cant_be_paid() public {
        pay(authorization(60e6, keccak256("a")), signed(authorization(60e6, keccak256("a"))));
        AdaSoulsPaymentModule.Authorization memory over = authorization(41e6, keccak256("b"));
        bytes memory overSig = signed(over);
        vm.expectRevert(abi.encodeWithSelector(AdaSoulsPaymentModule.OverCap.selector, uint256(40e6)));
        pay(over, overSig);

        // The next period starts fresh.
        vm.warp(block.timestamp + DAY);
        AdaSoulsPaymentModule.Authorization memory next = authorization(41e6, keccak256("b"));
        pay(next, signed(next));
        assertEq(token.balanceOf(payee), 101e6);

        TestToken other = new TestToken();
        other.mint(address(safe), 1e6);
        AdaSoulsPaymentModule.Authorization memory uncapped = authorization(1e6, keccak256("c"));
        uncapped.token = address(other);
        bytes memory uncappedSig = signed(uncapped);
        vm.expectRevert(AdaSoulsPaymentModule.NoCap.selector);
        pay(uncapped, uncappedSig);

        // A cap of 0 stops the token.
        asOwners(address(module), abi.encodeCall(module.setCap, (address(token), 0, 0)));
        AdaSoulsPaymentModule.Authorization memory stopped = authorization(1e6, keccak256("d"));
        bytes memory stoppedSig = signed(stopped);
        vm.expectRevert(AdaSoulsPaymentModule.NoCap.selector);
        pay(stopped, stoppedSig);
    }

    function test_a_failed_transfer_pays_nothing_and_keeps_the_nonce_unused() public {
        AdaSoulsPaymentModule.Authorization memory a = authorization(CAP, keccak256("n"));
        bytes memory sig = signed(a);
        vm.prank(address(safe));
        token.transfer(owner, 1_000e6); // the Safe is emptied
        vm.expectRevert(AdaSoulsPaymentModule.TransferFailed.selector);
        pay(a, sig);
        assertFalse(module.nonceUsed(address(safe), a.nonce));
    }

    // ---------- The owners stay in control ----------

    function test_owners_can_stop_the_agent_or_remove_the_module() public {
        AdaSoulsPaymentModule.Authorization memory a = authorization(25e6, keccak256("n"));
        bytes memory sig = signed(a);

        asOwners(address(module), abi.encodeCall(module.setAgent, (address(0))));
        vm.expectRevert(AdaSoulsPaymentModule.NotTheAgent.selector);
        pay(a, sig);

        asOwners(address(module), abi.encodeCall(module.setAgent, (agent)));
        // Removing the module (the Safe's module list: SENTINEL -> module).
        asOwners(address(safe), abi.encodeCall(safe.disableModule, (address(0x1), address(module))));
        vm.expectRevert(bytes("GS104")); // the Safe's own "not an enabled module"
        pay(a, sig);

        // And they can always move funds themselves, with no AdaSouls involvement.
        asOwners(address(token), abi.encodeCall(TestToken.transfer, (owner, 10e6)));
        assertEq(token.balanceOf(owner), 10e6);
    }

    function test_settings_are_each_safes_own() public {
        address stranger = makeAddr("stranger");
        vm.prank(stranger);
        module.setAgent(stranger);
        vm.prank(stranger);
        module.setCap(address(token), type(uint128).max, 1);
        assertEq(module.agentOf(address(safe)), agent);
        (uint128 cap,,,) = module.allowanceOf(address(safe), address(token));
        assertEq(cap, CAP);
    }
}
