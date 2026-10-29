// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {SCL_EIP6565} from "@solidity/lib/libSCL_EIP6565.sol";
import {Ed25519Key} from "../Ed25519Key.sol";

/// @notice SPIKE, not for deployment. Checks an Ed25519 (RFC 8032) signature with
/// Smooth Crypto Lib, as the payment module would check an AdaSouls payment
/// authorization signed by the issuer key (AWS KMS, ED25519_SHA_512).
/// See README.md, "Gas spike".
contract SclEd25519Verifier {
    /// @param m The signed message. Keep it to a 32-byte digest: SHA-512 runs in Solidity, so cost grows with length.
    /// @param r The signature's first 32 bytes, as they come.
    /// @param s The signature's last 32 bytes, as they come.
    /// @param extKpub The public key as keyFromPublic precomputes it.
    function verify(bytes calldata m, uint256 r, uint256 s, uint256[5] calldata extKpub) external view returns (bool) {
        return SCL_EIP6565.Verify_LE(string(m), r, s, extKpub);
    }

    /// @notice The precomputed key from the 32-byte RFC 8032 public key alone (see Ed25519Key).
    function keyFromPublic(bytes32 pub) external returns (uint256[5] memory) {
        return Ed25519Key.fromPublic(pub);
    }
}
