// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {AdaSoulsPaymentModule} from "../src/AdaSoulsPaymentModule.sol";

/// @notice Deploys the payment module at the same address on every chain, from any account:
/// AdaSouls holds no deployer key, and nobody needs one in particular (README, "Deploying").
///
/// Both deployments go through the CREATE2 factory that already exists at the same address on
/// Base and most EVM chains, so each address depends only on the bytecode and a salt:
/// - Smooth Crypto Lib's SCL_EIP6565, which the module links to: Foundry deploys it this way
///   itself, with `create2_library_salt` (foundry.toml).
/// - The module, with SALT below.
/// Running it again where it is already deployed changes nothing.
contract Deploy is Script {
    /// The deterministic deployment proxy (github.com/Arachnid/deterministic-deployment-proxy).
    address constant FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    /// A new version of the module gets a new salt, and so a new address: nothing is ever upgraded in place.
    bytes32 public constant SALT = keccak256("adasouls-payment-module/1");

    /// Where the module is, or will be, on any chain.
    function predicted() public view returns (address) {
        return vm.computeCreate2Address(SALT, keccak256(type(AdaSoulsPaymentModule).creationCode), FACTORY);
    }

    function run() external returns (address module) {
        module = predicted();
        console.log("AdaSoulsPaymentModule:", module);
        if (module.code.length > 0) {
            console.log("already deployed on chain", block.chainid);
            return module;
        }
        require(FACTORY.code.length > 0, "this chain has no CREATE2 factory at 0x4e59...956C");

        vm.startBroadcast();
        AdaSoulsPaymentModule deployed = new AdaSoulsPaymentModule{salt: SALT}();
        vm.stopBroadcast();

        require(address(deployed) == module, "deployed at an unexpected address: check the compiler settings");
        require(
            keccak256(bytes(deployed.AUTHORIZATION_TYPE())) == keccak256("alma-payment-authorization/1"),
            "unexpected module"
        );
        console.log("deployed on chain", block.chainid);
    }
}
