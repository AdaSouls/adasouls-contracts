// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {AdaSoulsPaymentModule} from "../src/AdaSoulsPaymentModule.sol";
import {Ed25519Key} from "../src/Ed25519Key.sol";

/// The module and alma-core agree byte for byte: same digest, and the module accepts
/// what alma-core's signPaymentAuthorization signs (test/vectors/alma-core-authorization.json,
/// from spike/gen-alma-core-vector.mjs).
contract AlmaCoreInteropTest is Test {
    using stdJson for string;

    AdaSoulsPaymentModule module = new AdaSoulsPaymentModule();
    string json = vm.readFile("test/vectors/alma-core-authorization.json");

    function authorization() internal view returns (AdaSoulsPaymentModule.Authorization memory) {
        return AdaSoulsPaymentModule.Authorization({
            chainId: json.readUint(".chainId"),
            module: json.readAddress(".module"),
            safe: json.readAddress(".safe"),
            token: json.readAddress(".token"),
            to: json.readAddress(".to"),
            amount: vm.parseUint(json.readString(".amount")),
            nonce: json.readBytes32(".nonce"),
            expiresAt: uint64(json.readUint(".expiresAt"))
        });
    }

    function test_digest_is_alma_cores() public view {
        bytes32 digest = module.authorizationDigest(authorization());
        assertEq(digest, json.readBytes32(".digest"));
        // The known answer alma-core's own test pins, computed apart with Python's hashlib.
        assertEq(digest, 0xc8058e0d4c6724a791fcb5177e6ddd7d0e34cf39552ad54b77f55396c9f4b875);
    }

    function test_accepts_alma_cores_signature_and_nothing_else() public {
        uint256[5] memory key = Ed25519Key.fromPublic(json.readBytes32(".publicKey"));
        bytes memory sig = json.readBytes(".sig");
        AdaSoulsPaymentModule.Authorization memory a = authorization();
        assertTrue(module.signatureValid(a, key, sig));

        a.amount += 1;
        assertFalse(module.signatureValid(a, key, sig));
        a.amount -= 1;
        a.to = address(0x3334);
        assertFalse(module.signatureValid(a, key, sig));
    }
}
