// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {SCL_EIP6565} from "@solidity/lib/libSCL_EIP6565.sol";
import {Ed25519Key} from "./Ed25519Key.sol";

interface ISafe {
    function execTransactionFromModuleReturnData(address to, uint256 value, bytes calldata data, uint8 operation)
        external
        returns (bool success, bytes memory returnData);
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title AdaSouls payment module
/// @notice A Safe module through which an agent pays out of its Safe only what AdaSouls
/// authorized: this token, this amount, to this address, once, before this time.
///
/// Who can do what:
/// - The Safe's owners hold its keys and keep full control. They install the module, name
///   the agent, choose which AdaSouls keys they accept, and cap what can leave per token and
///   period. They can change any of it, or remove the module, with an ordinary Safe transaction.
/// - The agent's key is not an owner. Through this module it can only submit a payment that
///   AdaSouls signed.
/// - AdaSouls signs authorizations (alma-payment-authorization/1, from the alma-core package) with
///   its issuer key and holds no key that moves money: a signature pays nothing unless the
///   agent submits it, and pays only the payee it names.
///
/// There is no admin, no upgrade and no owner of this contract. One deployment serves every
/// Safe; each Safe's settings are written by that Safe itself (msg.sender).
contract AdaSoulsPaymentModule {
    /// @notice What AdaSouls signs, as alma-core's paymentAuthorizationDigest packs it.
    struct Authorization {
        uint256 chainId;
        address module;
        address safe;
        address token;
        address to;
        uint256 amount;
        bytes32 nonce;
        uint64 expiresAt;
    }

    /// @notice How much of a token can leave a Safe through this module per period.
    struct Allowance {
        uint128 cap;
        uint128 spent;
        uint64 period;
        uint64 periodStart;
    }

    string public constant AUTHORIZATION_TYPE = "alma-payment-authorization/1";

    mapping(address safe => address) public agentOf;
    /// @dev An accepted key in the form the verifier takes; extKpub[4] is the key itself, never 0.
    mapping(address safe => mapping(bytes32 publicKey => uint256[5] extKpub)) internal acceptedKeys;
    mapping(address safe => mapping(address token => Allowance)) public allowanceOf;
    mapping(address safe => mapping(bytes32 nonce => bool)) public nonceUsed;

    event AgentSet(address indexed safe, address agent);
    event KeyAccepted(address indexed safe, bytes32 publicKey);
    event KeyRemoved(address indexed safe, bytes32 publicKey);
    event CapSet(address indexed safe, address indexed token, uint128 cap, uint64 period);
    event Paid(
        address indexed safe,
        bytes32 indexed nonce,
        address indexed token,
        address to,
        uint256 amount,
        bytes32 publicKey
    );

    error NotTheAgent();
    error WrongChainOrModule();
    error Expired();
    error NonceAlreadyUsed();
    error KeyNotAccepted();
    error BadSignature();
    error NoCap();
    error OverCap(uint256 available);
    error TransferFailed();
    error InvalidSetting();

    // ---------- Settings: each written by the Safe itself, in a transaction its owners sign ----------

    /// @notice The one address that may submit payments for the calling Safe. address(0) stops all payments.
    function setAgent(address agent) external {
        agentOf[msg.sender] = agent;
        emit AgentSet(msg.sender, agent);
    }

    /// @notice Accepts an AdaSouls issuer key (raw 32-byte Ed25519) for the calling Safe.
    /// @dev AdaSouls announces a new key 30 days before it signs with it, so owners can accept it in time.
    function acceptKey(bytes32 publicKey) external {
        if (publicKey == bytes32(0)) revert InvalidSetting();
        acceptedKeys[msg.sender][publicKey] = Ed25519Key.fromPublic(publicKey);
        emit KeyAccepted(msg.sender, publicKey);
    }

    function removeKey(bytes32 publicKey) external {
        delete acceptedKeys[msg.sender][publicKey];
        emit KeyRemoved(msg.sender, publicKey);
    }

    /// @notice At most `cap` of `token` leaves the calling Safe through this module per `period`
    /// seconds. A token without a cap can't be paid at all. A cap of 0 stops that token.
    /// Setting it starts a new period.
    function setCap(address token, uint128 cap, uint64 period) external {
        if (token == address(0) || (cap != 0 && period == 0)) revert InvalidSetting();
        allowanceOf[msg.sender][token] =
            Allowance({cap: cap, spent: 0, period: period, periodStart: uint64(block.timestamp)});
        emit CapSet(msg.sender, token, cap, period);
    }

    function isKeyAccepted(address safe, bytes32 publicKey) external view returns (bool) {
        return acceptedKeys[safe][publicKey][4] != 0;
    }

    // ---------- Paying ----------

    /// @notice Pays one authorization out of `a.safe`. Only that Safe's agent may call it.
    /// @param publicKey The AdaSouls key that signed (the Safe must have accepted it).
    /// @param signature Ed25519 over authorizationDigest(a), 64 bytes as RFC 8032 lays them out.
    function pay(Authorization calldata a, bytes32 publicKey, bytes calldata signature) external {
        if (msg.sender != agentOf[a.safe]) revert NotTheAgent();
        if (a.chainId != block.chainid || a.module != address(this)) revert WrongChainOrModule();
        if (block.timestamp >= a.expiresAt) revert Expired();
        if (nonceUsed[a.safe][a.nonce]) revert NonceAlreadyUsed();
        uint256[5] memory key = acceptedKeys[a.safe][publicKey];
        if (key[4] == 0) revert KeyNotAccepted();
        if (!signatureValid(a, key, signature)) revert BadSignature();

        // Recorded before the Safe is called: a reentrant call finds the nonce used and the cap spent.
        nonceUsed[a.safe][a.nonce] = true;
        spend(a.safe, a.token, a.amount);
        emit Paid(a.safe, a.nonce, a.token, a.to, a.amount, publicKey);

        (bool ok, bytes memory ret) = ISafe(a.safe)
            .execTransactionFromModuleReturnData(a.token, 0, abi.encodeCall(IERC20.transfer, (a.to, a.amount)), 0);
        // Tokens that return nothing on success are accepted; one that returns false is not.
        if (!ok || (ret.length != 0 && !abi.decode(ret, (bool)))) revert TransferFailed();
    }

    /// @notice The 32 bytes AdaSouls signs. Must equal alma-core's paymentAuthorizationDigest.
    function authorizationDigest(Authorization calldata a) public pure returns (bytes32) {
        return sha256(
            abi.encodePacked(
                AUTHORIZATION_TYPE, a.chainId, a.module, a.safe, a.token, a.to, a.amount, a.nonce, a.expiresAt
            )
        );
    }

    /// @notice Whether `signature` is `key`'s over this authorization. Checks nothing else: not the
    /// chain, the module, expiry, the nonce or the cap. For tooling; pay() does all of it.
    function signatureValid(Authorization calldata a, uint256[5] memory key, bytes calldata signature)
        public
        view
        returns (bool)
    {
        if (signature.length != 64) return false;
        return SCL_EIP6565.Verify_LE(
            string(abi.encodePacked(authorizationDigest(a))),
            uint256(bytes32(signature[:32])),
            uint256(bytes32(signature[32:])),
            key
        );
    }

    function spend(address safe, address token, uint256 amount) private {
        Allowance storage allowance = allowanceOf[safe][token];
        if (allowance.cap == 0) revert NoCap();
        if (block.timestamp >= uint256(allowance.periodStart) + allowance.period) {
            allowance.periodStart = uint64(block.timestamp);
            allowance.spent = 0;
        }
        uint256 available = allowance.cap - allowance.spent;
        if (amount > available) revert OverCap(available);
        allowance.spent += uint128(amount);
    }
}
