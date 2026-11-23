// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {ApplicationRegistry} from "../src/ApplicationRegistry.sol";
import {HazeAccess} from "../src/HazeAccess.sol";
import {IHazeGroth16Verifier} from "../src/HazeGroth16Verifier.sol";
import {HazePoolPoseidon} from "../src/HazePoolPoseidon.sol";
import {HazeSpendVerifierGroth16} from "../src/HazeSpendVerifierGroth16.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {SwapAndShieldRouter} from "../src/SwapAndShieldRouter.sol";
import {VersionRegistry} from "../src/VersionRegistry.sol";

interface IHazeOperatorGroth16Adapter {
    function impl() external view returns (address);
}

/// @notice Fuji v2 set: Poseidon2 pool wired to the Groth16-only spend verifier with the
///         emergency exit disabled.
/// @dev Differences from `DeployFujiPoseidonLive`:
///      - `HazeSpendVerifierGroth16` replaces `HazeSpendVerifierPairing`; the 32-byte keccak
///        digest "proof" path no longer exists.
///      - No `EmergencyExit` is deployed and the pool is constructed with `approvedExit =
///        address(0)`, so `HazePool.exitFromEmergency` always reverts `UNAUTHORIZED`.
///      - No `DevelopmentEqualityVerifier` is deployed (nothing uses it).
///      - The already-deployed operator `Groth16Verifier` and its adapter are reused by address,
///        so this script does not import the gitignored `haze-operator/` generated source.
///      Env: PRIVATE_KEY, HAZE_GROTH16_VERIFIER, HAZE_GROTH16_ADAPTER.
///      After broadcast, wait minDelay (1s) and run `ActivateFujiLive` with the new registries.
contract DeployFujiPoseidonV2 is Script {
    address internal constant USDC = 0x5425890298aed601595a70AB815c96711a31Bc65;
    uint48 internal constant MIN_DELAY = 1;
    uint256 internal constant ROOT_HISTORY = 4;
    /// @dev Same version tag as v1 so existing prover tooling keeps working. Cross-pool replay is
    ///      still bound by public input 2 (pool address) and the EIP-712 domain.
    bytes32 internal constant POOL_VERSION = bytes32(uint256(0xB001));
    bytes32 internal constant APP_ID = bytes32(uint256(0xA11));
    bytes32 internal constant MEMBER_ROOT =
        0x15d312c3937a289d3fd541c50355ac3a2122c88498db924c011ac0a619f352c4;
    bytes32 internal constant BLOCK_ROOT =
        0x2f9120bf4979f6f079577e2eaeb96fd996129dbd24a0855fbd0fe7e30669716d;
    bytes32 internal constant POLICY_ARTIFACT = bytes32(uint256(0x55));

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address groth16 = vm.envAddress("HAZE_GROTH16_VERIFIER");
        address adapterAddr = vm.envAddress("HAZE_GROTH16_ADAPTER");
        address deployer = vm.addr(pk);
        require(block.chainid == 43113, "VERSION_UNSUPPORTED");
        require(groth16.code.length != 0 && adapterAddr.code.length != 0, "ENCODING_INVALID");
        require(IHazeOperatorGroth16Adapter(adapterAddr).impl() == groth16, "ADAPTER_MISMATCH");
        IHazeGroth16Verifier adapter = IHazeGroth16Verifier(adapterAddr);

        vm.startBroadcast(pk);
        HazeAccess access = new HazeAccess(deployer, deployer, MIN_DELAY);
        ApplicationRegistry apps = new ApplicationRegistry(access);
        PolicyRegistry policies = new PolicyRegistry(access);
        VersionRegistry versions = new VersionRegistry(access);
        HazeSpendVerifierGroth16 verifier = new HazeSpendVerifierGroth16(adapter);

        uint64 nonce = uint64(vm.getNonce(deployer));
        address predictedRouter = vm.computeCreateAddress(deployer, nonce + 1);
        HazePoolPoseidon pool = new HazePoolPoseidon(
            access,
            apps,
            policies,
            verifier,
            USDC,
            predictedRouter,
            address(0),
            POOL_VERSION,
            ROOT_HISTORY
        );
        address[] memory tokens = new address[](0);
        address[] memory adapters = new address[](0);
        SwapAndShieldRouter router = new SwapAndShieldRouter(access, pool, USDC, tokens, adapters);
        require(address(router) == predictedRouter, "router");

        apps.scheduleRegister(
            ApplicationRegistry.RegisterParams({
                applicationId: APP_ID,
                admin: deployer,
                gatekeeperSigner: deployer,
                policyAuthority: deployer,
                membershipRoot: MEMBER_ROOT,
                auditPublicKey: hex"11",
                manifestUri: "ipfs://haze-fuji-poseidon-v2",
                manifestHash: bytes32(uint256(0x22)),
                policyProfile: bytes32(uint256(0x33))
            })
        );
        policies.schedulePolicy(1, BLOCK_ROOT, POLICY_ARTIFACT);
        vm.stopBroadcast();

        _selfCheck(pool, verifier, router);

        console2.log(string.concat("HazeAccess ", vm.toString(address(access))));
        console2.log(string.concat("ApplicationRegistry ", vm.toString(address(apps))));
        console2.log(string.concat("PolicyRegistry ", vm.toString(address(policies))));
        console2.log(string.concat("VersionRegistry ", vm.toString(address(versions))));
        console2.log(string.concat("Groth16Verifier ", vm.toString(groth16)));
        console2.log(string.concat("HazeOperatorGroth16Adapter ", vm.toString(adapterAddr)));
        console2.log(string.concat("HazeSpendVerifierGroth16 ", vm.toString(address(verifier))));
        console2.log(string.concat("HazePoolPoseidon ", vm.toString(address(pool))));
        console2.log(string.concat("SwapAndShieldRouter ", vm.toString(address(router))));
        console2.log("EmergencyExit disabled (approvedExit = 0x0)");
        console2.log(string.concat("deployer ", vm.toString(deployer)));
    }

    /// @dev Read-only post-deploy assertions; runs in simulation before any broadcast is sent.
    function _selfCheck(HazePoolPoseidon pool, HazeSpendVerifierGroth16 verifier, SwapAndShieldRouter router)
        internal
        view
    {
        require(pool.approvedExit() == address(0), "EXIT_WIRED");
        require(pool.approvedRouter() == address(router), "ROUTER_WIRED");
        require(address(pool.verifier()) == address(verifier), "VERIFIER_WIRED");
        uint256[29] memory inputs;
        inputs[0] = uint256(verifier.PROTOCOL_VERSION_TAG());
        bytes memory digest = abi.encodePacked(keccak256(abi.encodePacked(inputs)));
        bytes32 artifactHash = verifier.SPEND_ARTIFACT_HASH();
        try verifier.verify(inputs, digest, artifactHash, false) returns (bool) {
            revert("DIGEST_ACCEPTED");
        } catch {}
    }
}
