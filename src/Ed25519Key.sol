// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {SCL_EIP6565} from "@solidity/lib/libSCL_EIP6565.sol";
import {SCL_sha512} from "@solidity/hash/SCL_sha512.sol";
import {ModInv} from "@solidity/modular/SCL_modular.sol";
import {SqrtMod} from "@solidity/modular/SCL_sqrtMod_5mod8.sol";
import {p, d, pMINUS_1} from "@solidity/fields/SCL_wei25519.sol";

/// @notice An Ed25519 public key in the form Smooth Crypto Lib verifies against.
/// @dev Our code, not the audited library's: it goes in this repo's audit. Smooth Crypto Lib's
/// own SetKey derives the key from the private seed, which a KMS key never gives; this does it
/// from the 32-byte RFC 8032 public key alone. Adapted from the library's test helper
/// edDecompressX, and checked against SetKey in test/spike.
library Ed25519Key {
    /// @return extKpub What SCL_EIP6565.Verify_LE takes. Reverts with Smooth Crypto Lib's
    /// _NotQuadraticResidueError (0x7FC) when `pub` is not a point on the curve.
    function fromPublic(bytes32 pub) internal returns (uint256[5] memory extKpub) {
        uint256 c = SCL_sha512.Swap256(uint256(pub));
        uint256 sign = (c >> 255) & 1;
        uint256 y = c & 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
        uint256 y2 = mulmod(y, y, p);
        uint256 x2 = mulmod(addmod(y2, pMINUS_1, p), ModInv(addmod(mulmod(d, y2, p), 1, p), p), p);
        uint256 x = SqrtMod(x2);
        if ((x & 1) != sign) x = p - x;
        extKpub[4] = uint256(pub);
        (extKpub[0], extKpub[1]) = SCL_EIP6565.Edwards2WeierStrass(x, y);
        (extKpub[2], extKpub[3]) = SCL_EIP6565.ecPow128(extKpub[0], extKpub[1], 1, 1);
    }
}
