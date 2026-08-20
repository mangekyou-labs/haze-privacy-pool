// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {ApplicationRegistry} from "../src/ApplicationRegistry.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";

/// @notice Activates the development application and policy after the 1-second minDelay.
contract ActivateFujiLive is Script {
    bytes32 internal constant APP_ID = bytes32(uint256(0xA11));

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address apps = vm.envAddress("HAZE_APPLICATION_REGISTRY");
        address policies = vm.envAddress("HAZE_POLICY_REGISTRY");
        require(block.chainid == 43113, "VERSION_UNSUPPORTED");

        vm.startBroadcast(pk);
        ApplicationRegistry(apps).activateRegister(APP_ID);
        PolicyRegistry(policies).activatePolicy(1);
        vm.stopBroadcast();

        console2.log("activated application", uint256(APP_ID));
        console2.log("activated policy", uint256(1));
    }
}
