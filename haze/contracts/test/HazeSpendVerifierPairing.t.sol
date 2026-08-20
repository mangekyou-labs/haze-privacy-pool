// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {DevelopmentEqualityVerifier} from "haze-dev/DevelopmentEqualityVerifier.sol";
import {HazeGroth16Verifier} from "../src/HazeGroth16Verifier.sol";
import {HazeSpendVerifierPairing} from "../src/HazeSpendVerifierPairing.sol";

contract HazeSpendVerifierPairingTest is Test {
    HazeSpendVerifierPairing internal verifier;
    HazeGroth16Verifier internal pairing;

    function setUp() public {
        pairing = new HazeGroth16Verifier();
        verifier = new HazeSpendVerifierPairing(new DevelopmentEqualityVerifier(), pairing);
    }

    function testProductionPairingIsKeysMissing() public {
        uint256[29] memory inputs;
        inputs[0] = uint256(verifier.PROTOCOL_VERSION_TAG());
        bytes32 artifactHash = verifier.SPEND_ARTIFACT_HASH();
        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        vm.expectRevert(bytes("KEYS_MISSING"));
        verifier.verify(inputs, abi.encode(a, b, c), artifactHash, true);
    }

    function testPairingBackendProofRevertsKeysMissing() public {
        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        uint256[29] memory input;
        vm.expectRevert(bytes("KEYS_MISSING"));
        pairing.verifyProof(a, b, c, input);
    }

    function testOperatorOwnedGroth16ProofHitsPairingBackend() public {
        uint256[29] memory inputs;
        inputs[0] = uint256(verifier.PROTOCOL_VERSION_TAG());
        inputs[16] = 1;
        bytes32 artifactHash = verifier.SPEND_ARTIFACT_HASH();
        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        bytes memory proof = abi.encode(a, b, c);
        vm.expectRevert(bytes("KEYS_MISSING"));
        verifier.verify(inputs, proof, artifactHash, false);
    }
}
