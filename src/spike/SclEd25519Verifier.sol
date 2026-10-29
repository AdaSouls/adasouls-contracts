// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {SCL_EIP6565} from "@solidity/lib/libSCL_EIP6565.sol";
import {SCL_sha512} from "@solidity/hash/SCL_sha512.sol";
import {ModInv} from "@solidity/modular/SCL_modular.sol";
import {SqrtMod} from "@solidity/modular/SCL_sqrtMod_5mod8.sol";
import {p, d, pMINUS_1} from "@solidity/fields/SCL_wei25519.sol";

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

    /// @notice The precomputed key from the 32-byte RFC 8032 public key alone: a KMS key never
    /// gives its seed, and Smooth Crypto Lib's own SetKey needs it. Done once, when the module is
    /// set up with AdaSouls' key. Adapted from the library's test helper edDecompressX.
    /// Not part of the audited library: it must be in this repo's audit.
    function keyFromPublic(bytes32 pub) external returns (uint256[5] memory extKpub) {
        uint256 c = SCL_sha512.Swap256(uint256(pub));
        uint256 sign = (c >> 255) & 1;
        uint256 y = c & 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
        uint256 y2 = mulmod(y, y, p);
        uint256 x2 = mulmod(addmod(y2, pMINUS_1, p), ModInv(addmod(mulmod(d, y2, p), 1, p), p), p);
        // Reverts with the library's _NotQuadraticResidueError (0x7FC) when pub is not a curve point.
        uint256 x = SqrtMod(x2);
        if ((x & 1) != sign) x = p - x;
        extKpub[4] = uint256(pub);
        (extKpub[0], extKpub[1]) = SCL_EIP6565.Edwards2WeierStrass(x, y);
        (extKpub[2], extKpub[3]) = SCL_EIP6565.ecPow128(extKpub[0], extKpub[1], 1, 1);
    }
}
