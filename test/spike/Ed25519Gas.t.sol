// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test, console} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {SCL_EIP6565_UTILS} from "@solidity/lib/libSCL_eddsaUtils.sol";
import {SclEd25519Verifier} from "../../src/spike/SclEd25519Verifier.sol";
import {Eip712Verifier} from "../../src/spike/Eip712Verifier.sol";

/// The gas spike (README.md, "Gas spike"): what one payment authorization costs to check on-chain.
/// Vectors come from spike/gen-vectors.mjs. Each gas figure is the whole external call (about 2.6k is the call itself).
contract Ed25519GasTest is Test {
    using stdJson for string;

    string json;
    SclEd25519Verifier ed;
    Eip712Verifier eip712;
    uint256[5] extKpub;

    function setUp() public {
        json = vm.readFile("spike/vectors.json");
        ed = new SclEd25519Verifier();
        eip712 = new Eip712Verifier(json.readAddress(".ecdsa.module"));
        extKpub = ed.keyFromPublic(json.readBytes32(".pub"));
    }

    function halves(bytes memory sig) internal pure returns (uint256 r, uint256 s) {
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
        }
    }

    function flip(bytes memory b) internal pure returns (bytes memory c) {
        c = bytes.concat(b);
        c[c.length - 1] = c[c.length - 1] ^ 0x01;
    }

    function check(bytes memory m, bytes memory sig) internal view returns (uint256 used, bool ok) {
        (uint256 r, uint256 s) = halves(sig);
        uint256 g = gasleft();
        ok = ed.verify(m, r, s, extKpub);
        used = g - gasleft();
    }

    function test_digest_signature_verifies_and_costs() public view {
        (uint256 used, bool ok) = check(json.readBytes(".digest"), json.readBytes(".digestSig"));
        assertTrue(ok);
        console.log("Ed25519 over a 32-byte digest, gas:", used);
    }

    function test_full_message_costs_about_twice_as_much() public view {
        (uint256 used, bool ok) = check(json.readBytes(".packed"), json.readBytes(".packedSig"));
        assertTrue(ok);
        console.log("Ed25519 over the 244-byte authorization, gas:", used);
    }

    function test_rejects_a_changed_message_or_signature() public view {
        bytes memory m = json.readBytes(".digest");
        bytes memory sig = json.readBytes(".digestSig");
        (, bool changedMessage) = check(flip(m), sig);
        (, bool changedSignature) = check(m, flip(sig));
        (, bool otherMessagesSignature) = check(m, json.readBytes(".packedSig"));
        assertFalse(changedMessage);
        assertFalse(changedSignature);
        assertFalse(otherMessagesSignature);
    }

    /// The key built from the public key alone is the one the library builds from the seed.
    function test_key_from_public_key_matches_the_library() public {
        (uint256[5] memory fromSeed,) = SCL_EIP6565_UTILS.SetKey(uint256(json.readBytes32(".seed")));
        uint256 g = gasleft();
        uint256[5] memory fromPub = ed.keyFromPublic(json.readBytes32(".pub"));
        uint256 used = g - gasleft();
        for (uint256 i = 0; i < 5; i++) {
            assertEq(fromPub[i], fromSeed[i]);
        }
        console.log("Key setup from the public key (once per key), gas:", used);
    }

    function test_key_from_public_key_refuses_a_non_point() public {
        // y = 2 is not on the curve: x^2 has no root, and the library says so (_NotQuadraticResidueError).
        vm.expectRevert(abi.encode(uint256(0x7FC)));
        ed.keyFromPublic(bytes32(uint256(2) << 248));
    }

    function test_eip712_fallback() public view {
        Eip712Verifier.PaymentAuthorization memory a = Eip712Verifier.PaymentAuthorization({
            action: json.readBytes32(".ecdsa.action"),
            safe: json.readAddress(".ecdsa.safe"),
            token: json.readAddress(".ecdsa.token"),
            to: json.readAddress(".ecdsa.to"),
            amount: json.readUint(".ecdsa.amount"),
            nonce: json.readBytes32(".ecdsa.nonce"),
            expiresAt: uint64(json.readUint(".ecdsa.expiresAt"))
        });
        bytes memory sig = json.readBytes(".ecdsa.sig");
        uint256 g = gasleft();
        address signer = eip712.recover(a, sig);
        uint256 used = g - gasleft();
        assertEq(signer, json.readAddress(".ecdsa.signer"));
        a.amount += 1;
        assertTrue(eip712.recover(a, sig) != signer);
        console.log("secp256k1 EIP-712 fallback, gas:", used);
    }
}
