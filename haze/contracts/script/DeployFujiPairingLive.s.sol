// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {DevelopmentEqualityVerifier} from "haze-dev/DevelopmentEqualityVerifier.sol";
import {Groth16Verifier} from "haze-operator/HazeGroth16Verifier.generated.sol";
import {ApplicationRegistry} from "../src/ApplicationRegistry.sol";
import {EmergencyExit} from "../src/EmergencyExit.sol";
import {HazeAccess} from "../src/HazeAccess.sol";
import {IHazeGroth16Verifier} from "../src/HazeGroth16Verifier.sol";
import {HazePool} from "../src/HazePool.sol";
import {HazeSpendVerifierPairing} from "../src/HazeSpendVerifierPairing.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {SwapAndShieldRouter} from "../src/SwapAndShieldRouter.sol";
import {VersionRegistry} from "../src/VersionRegistry.sol";

/// @notice Adapter so the generated snarkjs verifier satisfies IHazeGroth16Verifier.
/// @dev Operator-owned. Not an SC-09 production ceremony.
contract HazeOperatorGroth16Adapter is IHazeGroth16Verifier {
    bool public constant NOT_FOR_PRODUCTION = true;
    Groth16Verifier public immutable impl;

    constructor(Groth16Verifier impl_) {
        require(address(impl_) != address(0), "ENCODING_INVALID");
        impl = impl_;
    }

    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[29] calldata input
    ) external view returns (bool) {
        return impl.verifyProof(a, b, c, input);
    }
}

/// @notice Broadcasts a new immutable Fuji set with the operator-owned pairing verifier.
/// @dev Does not write production keys, flip SC-09, or upgrade the previous digest set.
contract DeployFujiPairingLive is Script {
    address internal constant USDC = 0x5425890298aed601595a70AB815c96711a31Bc65;
    uint48 internal constant MIN_DELAY = 1;
    uint256 internal constant ROOT_HISTORY = 4;
    bytes32 internal constant POOL_VERSION = bytes32(uint256(0xB001));
    bytes32 internal constant APP_ID = bytes32(uint256(0xA11));
    bytes32 internal constant MEMBER_ROOT = bytes32(uint256(0x11));
    bytes32 internal constant BLOCK_ROOT = bytes32(uint256(0x44));
    bytes32 internal constant POLICY_ARTIFACT = bytes32(uint256(0x55));

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(pk);
        require(block.chainid == 43113, "VERSION_UNSUPPORTED");

        vm.startBroadcast(pk);
        HazeAccess access = new HazeAccess(deployer, deployer, MIN_DELAY);
        ApplicationRegistry apps = new ApplicationRegistry(access);
        PolicyRegistry policies = new PolicyRegistry(access);
        VersionRegistry versions = new VersionRegistry(access);
        DevelopmentEqualityVerifier backend = new DevelopmentEqualityVerifier();
        Groth16Verifier generated = new Groth16Verifier();
        HazeOperatorGroth16Adapter adapter = new HazeOperatorGroth16Adapter(generated);
        HazeSpendVerifierPairing verifier = new HazeSpendVerifierPairing(backend, adapter);

        uint64 nonce = uint64(vm.getNonce(deployer));
        address predictedRouter = vm.computeCreateAddress(deployer, nonce + 1);
        address predictedExit = vm.computeCreateAddress(deployer, nonce + 2);
        HazePool pool = new HazePool(
            access,
            apps,
            policies,
            verifier,
            USDC,
            predictedRouter,
            predictedExit,
            POOL_VERSION,
            ROOT_HISTORY
        );
        address[] memory tokens = new address[](0);
        address[] memory adapters = new address[](0);
        SwapAndShieldRouter router = new SwapAndShieldRouter(access, pool, USDC, tokens, adapters);
        EmergencyExit exitContract = new EmergencyExit(access, pool, versions, policies);
        require(address(router) == predictedRouter, "router");
        require(address(exitContract) == predictedExit, "exit");

        apps.scheduleRegister(
            ApplicationRegistry.RegisterParams({
                applicationId: APP_ID,
                admin: deployer,
                gatekeeperSigner: deployer,
                policyAuthority: deployer,
                membershipRoot: MEMBER_ROOT,
                auditPublicKey: hex"11",
                manifestUri: "ipfs://haze-fuji-pairing-live",
                manifestHash: bytes32(uint256(0x22)),
                policyProfile: bytes32(uint256(0x33))
            })
        );
        policies.schedulePolicy(1, BLOCK_ROOT, POLICY_ARTIFACT);
        vm.stopBroadcast();

        console2.log(string.concat("HazeAccess ", vm.toString(address(access))));
        console2.log(string.concat("ApplicationRegistry ", vm.toString(address(apps))));
        console2.log(string.concat("PolicyRegistry ", vm.toString(address(policies))));
        console2.log(string.concat("VersionRegistry ", vm.toString(address(versions))));
        console2.log(string.concat("DevelopmentEqualityVerifier ", vm.toString(address(backend))));
        console2.log(string.concat("Groth16Verifier ", vm.toString(address(generated))));
        console2.log(string.concat("HazeOperatorGroth16Adapter ", vm.toString(address(adapter))));
        console2.log(string.concat("HazeSpendVerifierPairing ", vm.toString(address(verifier))));
        console2.log(string.concat("HazePool ", vm.toString(address(pool))));
        console2.log(string.concat("SwapAndShieldRouter ", vm.toString(address(router))));
        console2.log(string.concat("EmergencyExit ", vm.toString(address(exitContract))));
        console2.log(string.concat("deployer ", vm.toString(deployer)));
    }
}
