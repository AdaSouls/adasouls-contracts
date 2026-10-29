// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @notice SPIKE, not for deployment. The fallback if the issuer key is ever replaced
/// for authorizations: a secp256k1 key signing an EIP-712 struct, checked with ecrecover.
contract Eip712Verifier {
    struct PaymentAuthorization {
        bytes32 action;
        address safe;
        address token;
        address to;
        uint256 amount;
        bytes32 nonce;
        uint64 expiresAt;
    }

    bytes32 constant TYPEHASH = keccak256(
        "PaymentAuthorization(bytes32 action,address safe,address token,address to,uint256 amount,bytes32 nonce,uint64 expiresAt)"
    );
    bytes32 immutable DOMAIN;

    constructor(address module) {
        DOMAIN = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("AdaSouls"),
                keccak256("1"),
                8453,
                module
            )
        );
    }

    function recover(PaymentAuthorization calldata a, bytes calldata sig) external view returns (address) {
        bytes32 structHash =
            keccak256(abi.encode(TYPEHASH, a.action, a.safe, a.token, a.to, a.amount, a.nonce, a.expiresAt));
        bytes32 digest = keccak256(abi.encodePacked(hex"1901", DOMAIN, structHash));
        (bytes32 r, bytes32 s) = abi.decode(sig[:64], (bytes32, bytes32));
        return ecrecover(digest, uint8(sig[64]), r, s);
    }
}
