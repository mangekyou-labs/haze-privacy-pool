// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {IHazeSpendVerifier} from "../src/HazeSpendVerifier.sol";

/// @notice Constructor receipt that pairing-verifies an operator-owned 256-byte Groth16 proof.
/// @dev Not an SC-09 production approval.
contract HazeOperatorPairingReceipt {
    bool public constant NOT_FOR_PRODUCTION = true;

    event PairingVerified(address verifier, bytes32 artifactHash, bool production);

    constructor(
        IHazeSpendVerifier verifier,
        uint256[29] memory publicInputs,
        bytes memory proof,
        bytes32 artifactHash,
        bool production
    ) {
        require(proof.length == 256, "ENCODING_INVALID");
        require(verifier.verify(publicInputs, proof, artifactHash, production), "PROOF_INVALID");
        emit PairingVerified(address(verifier), artifactHash, production);
    }
}

/// @notice Broadcasts a Fuji receipt that requires pairing-verify == true.
/// @dev Does not flip committed fuji-v1, SC-09, or spend_prove.
contract VerifyFujiPairingLive is Script {
    bytes32 internal constant SPEND_ARTIFACT_HASH =
        0xac2082ecb2129c571d2ddeb170f261a0da074491773102fa4f1544e97eb19281;

    function run() external {
        require(block.chainid == 43113, "VERSION_UNSUPPORTED");
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address pairing = vm.envAddress("HAZE_PAIRING");
        string memory json = vm.readFile(vm.envString("HAZE_OPERATOR_PROVE_JSON"));
        bytes memory proof = vm.parseBytes(vm.parseJsonString(json, ".proofBytes"));
        uint256[29] memory inputs;
        for (uint256 i = 0; i < 29; ++i) {
            inputs[i] = vm.parseJsonUint(json, string.concat(".publicSignals[", vm.toString(i), "]"));
        }
        vm.startBroadcast(pk);
        HazeOperatorPairingReceipt receipt = new HazeOperatorPairingReceipt(
            IHazeSpendVerifier(pairing),
            inputs,
            proof,
            SPEND_ARTIFACT_HASH,
            true
        );
        console2.log("HazeOperatorPairingReceipt", address(receipt));
        vm.stopBroadcast();
    }
}
