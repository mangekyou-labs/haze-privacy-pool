// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {HazePool} from "../src/HazePool.sol";
import {HazeProtocolVectors} from "../src/HazeProtocolVectors.sol";

interface IERC20Live {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @notice Broadcasts one operator-owned Groth16 deposit or withdraw on the Poseidon Fuji pool.
/// @dev Not T7.4. Does not flip fuji-v1.json or invent production keys.
contract TransactFujiPoseidonLive is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address user = vm.addr(pk);
        HazePool pool = HazePool(vm.envAddress("HAZE_POOL"));
        string memory json = vm.readFile(vm.envString("HAZE_TRANSACT_JSON"));
        require(block.chainid == 43113, "VERSION_UNSUPPORTED");
        require(pool.NOT_FOR_PRODUCTION(), "VERSION_UNSUPPORTED");
        require(address(pool) == vm.parseJsonAddress(json, ".pool"), "POOL");

        HazePool.TransactArgs memory args;
        args.intent.applicationId = bytes32(vm.parseJsonUint(json, ".applicationId"));
        args.intent.user = user;
        args.intent.pool = address(pool);
        args.intent.poolVersion = pool.poolVersion();
        args.intent.action = uint8(vm.parseJsonUint(json, ".action"));
        args.intent.noteTreeRoot = vm.parseJsonUint(json, ".noteTreeRoot");
        args.intent.applicationPolicyVersion = uint64(vm.parseJsonUint(json, ".applicationPolicyVersion"));
        args.intent.hazePolicyVersion = uint64(vm.parseJsonUint(json, ".hazePolicyVersion"));
        args.intent.applicationMembershipRoot = vm.parseJsonUint(json, ".applicationMembershipRoot");
        args.intent.hazeBlocklistRoot = vm.parseJsonUint(json, ".hazeBlocklistRoot");
        args.intent.inputNullifier0 = vm.parseJsonUint(json, ".inputNullifier0");
        args.intent.inputNullifier1 = vm.parseJsonUint(json, ".inputNullifier1");
        args.intent.outputCommitment0 = vm.parseJsonUint(json, ".outputCommitment0");
        args.intent.outputCommitment1 = vm.parseJsonUint(json, ".outputCommitment1");
        args.intent.publicAmount = uint64(vm.parseJsonUint(json, ".publicAmount"));
        args.intent.publicRecipient = vm.parseJsonAddress(json, ".publicRecipient");
        args.intent.recipientCiphertextHash0 = bytes32(vm.parseJsonUint(json, ".recipientCiphertextHash0"));
        args.intent.recipientCiphertextHash1 = bytes32(vm.parseJsonUint(json, ".recipientCiphertextHash1"));
        args.intent.auditDataCommitment = vm.parseJsonUint(json, ".auditDataCommitment");
        args.intent.auditCiphertextHash = bytes32(vm.parseJsonUint(json, ".auditCiphertextHash"));

        args.recipientCiphertext0 = vm.parseBytes(vm.parseJsonString(json, ".recipientCiphertext0"));
        args.recipientCiphertext1 = vm.parseBytes(vm.parseJsonString(json, ".recipientCiphertext1"));
        args.auditCiphertext = vm.parseBytes(vm.parseJsonString(json, ".auditCiphertext"));
        args.proof = vm.parseBytes(vm.parseJsonString(json, ".proofBytes"));
        require(args.proof.length == 256, "ENCODING_INVALID");

        uint256[29] memory inputs = pool.publicInputs(args.intent);
        for (uint256 i = 0; i < 29; ++i) {
            uint256 expected = vm.parseJsonUint(json, string.concat(".publicSignals[", vm.toString(i), "]"));
            require(inputs[i] == expected, "PUBLIC_INPUT_MISMATCH");
        }

        args.authorization.applicationId = args.intent.applicationId;
        args.authorization.user = args.intent.user;
        args.authorization.pool = args.intent.pool;
        args.authorization.poolVersion = args.intent.poolVersion;
        args.authorization.action = args.intent.action;
        args.authorization.intentHash = HazeProtocolVectors.intentStructHash(args.intent);
        args.authorization.applicationPolicyVersion = args.intent.applicationPolicyVersion;
        args.authorization.hazePolicyVersion = args.intent.hazePolicyVersion;
        args.authorization.auditDataCommitment = args.intent.auditDataCommitment;
        args.authorization.auditCiphertextHash = args.intent.auditCiphertextHash;
        args.authorization.nonce = keccak256(abi.encodePacked("haze-fuji-poseidon", user, args.intent.action, block.timestamp));
        args.authorization.validAfter = uint48(block.timestamp - 1);
        args.authorization.validUntil = uint48(block.timestamp + 1 hours);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            pk,
            HazeProtocolVectors.typedDataDigest(
                HazeProtocolVectors.domainSeparator(
                    pool.DOMAIN_NAME(), pool.DOMAIN_VERSION(), block.chainid, address(pool)
                ),
                HazeProtocolVectors.authorizationStructHash(args.authorization)
            )
        );
        args.authorizationSignature = abi.encodePacked(r, s, v);

        vm.startBroadcast(pk);
        if (args.intent.action == 1) {
            require(IERC20Live(address(pool.usdc())).balanceOf(user) >= args.intent.publicAmount, "USDC_BALANCE");
            require(IERC20Live(address(pool.usdc())).approve(address(pool), args.intent.publicAmount), "approve");
            pool.deposit(args);
        } else {
            require(args.intent.action == 2 || args.intent.action == 3, "ENCODING_INVALID");
            pool.transact(args);
        }
        vm.stopBroadcast();

        console2.log("transact pool", address(pool));
        console2.log("transact user", user);
        console2.log("transact action", args.intent.action);
        console2.log("transact amount", args.intent.publicAmount);
    }
}
