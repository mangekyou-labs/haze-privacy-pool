// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {DevelopmentEqualityVerifier} from "haze-dev/DevelopmentEqualityVerifier.sol";
import {HazeSpendVerifier} from "../src/HazeSpendVerifier.sol";

abstract contract HazeSpendVerifierFixture is Test {
    using stdJson for string;

    bytes32 internal constant SPEND_ARTIFACT_HASH =
        0xac2082ecb2129c571d2ddeb170f261a0da074491773102fa4f1544e97eb19281;
    bytes32 internal constant BUILD_HASH =
        0x533f1d9d172c8395b4849bd7b90901b5314b7fc4735b878385e22b5a19d3cd41;
    bytes32 internal constant PROTOCOL_VERSION_TAG =
        0x2afe8a5679df289719eae23ad89b300434b9dfbb8194dad0b50dee97f91a3868;
    uint256 internal constant SNARK_SCALAR_FIELD =
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    HazeSpendVerifier internal verifier;
    DevelopmentEqualityVerifier internal pairing;
    string internal spendFixture;

    function setUp() public {
        pairing = new DevelopmentEqualityVerifier();
        verifier = new HazeSpendVerifier(pairing);
        spendFixture = vm.readFile(string.concat(vm.projectRoot(), "/../circuits/vectors/v1/haze-spend-v1.json"));
    }

    function publicKeys() internal pure returns (string[29] memory keys) {
        keys = [
            string("protocolVersionTag"),
            "chainId",
            "poolAddress",
            "poolVersionHi",
            "poolVersionLo",
            "applicationIdHi",
            "applicationIdLo",
            "noteTreeRoot",
            "applicationPolicyVersion",
            "hazePolicyVersion",
            "applicationMembershipRoot",
            "hazeBlocklistRoot",
            "inputNullifier0",
            "inputNullifier1",
            "outputCommitment0",
            "outputCommitment1",
            "action",
            "publicAmount",
            "publicRecipient",
            "authorizedUser",
            "intentHashHi",
            "intentHashLo",
            "recipientCiphertextHash0Hi",
            "recipientCiphertextHash0Lo",
            "recipientCiphertextHash1Hi",
            "recipientCiphertextHash1Lo",
            "auditDataCommitment",
            "auditCiphertextHashHi",
            "auditCiphertextHashLo"
        ];
    }

    function loadCase(uint256 index) internal view returns (uint256[29] memory inputs) {
        string[29] memory keys = publicKeys();
        for (uint256 i = 0; i < 29; ++i) {
            inputs[i] = spendFixture.readUint(
                string.concat(".cases[", vm.toString(index), "].circom.", keys[i])
            );
        }
    }

    function developmentProof(uint256[29] memory inputs) internal pure returns (bytes memory) {
        return abi.encodePacked(keccak256(abi.encodePacked(inputs)));
    }
}

contract HazeSpendVerifierTest is HazeSpendVerifierFixture {
    function testPinsTwentyNinePublicInputsAndFrozenHashes() public view {
        assertEq(verifier.PUBLIC_INPUT_COUNT(), 29);
        assertEq(verifier.SPEND_ARTIFACT_HASH(), SPEND_ARTIFACT_HASH);
        assertEq(verifier.CIRCUIT_BUILD_HASH(), BUILD_HASH);
        assertEq(verifier.PROTOCOL_VERSION_TAG(), PROTOCOL_VERSION_TAG);
        assertEq(verifier.SNARK_SCALAR_FIELD(), SNARK_SCALAR_FIELD);
        assertTrue(verifier.NOT_FOR_PRODUCTION());
        string[29] memory names = verifier.publicInputNames();
        string[29] memory expected = [
            string("protocol_version_tag"),
            "chain_id",
            "pool_address",
            "pool_version_hi",
            "pool_version_lo",
            "application_id_hi",
            "application_id_lo",
            "note_tree_root",
            "application_policy_version",
            "haze_policy_version",
            "application_membership_root",
            "haze_blocklist_root",
            "input_nullifier_0",
            "input_nullifier_1",
            "output_commitment_0",
            "output_commitment_1",
            "action",
            "public_amount",
            "public_recipient",
            "authorized_user",
            "intent_hash_hi",
            "intent_hash_lo",
            "recipient_ciphertext_hash_0_hi",
            "recipient_ciphertext_hash_0_lo",
            "recipient_ciphertext_hash_1_hi",
            "recipient_ciphertext_hash_1_lo",
            "audit_data_commitment",
            "audit_ciphertext_hash_hi",
            "audit_ciphertext_hash_lo"
        ];
        for (uint256 i = 0; i < 29; ++i) {
            assertEq(keccak256(bytes(names[i])), keccak256(bytes(expected[i])));
        }
    }

    function testDepositFixtureVerifiesWithMatchingArtifactAndDevelopmentProof() public view {
        uint256[29] memory inputs = loadCase(0);
        assertEq(inputs[0], uint256(PROTOCOL_VERSION_TAG));
        assertEq(inputs[7], 0);
        assertEq(inputs[12], 0);
        assertEq(inputs[13], 0);
        assertEq(inputs[16], 1);
        assertTrue(verifier.verify(inputs, developmentProof(inputs), SPEND_ARTIFACT_HASH, false));
    }

    function testTransferAndWithdrawFixturesVerify() public view {
        uint256[29] memory transferInputs = loadCase(1);
        uint256[29] memory withdrawInputs = loadCase(2);
        assertEq(transferInputs[16], 2);
        assertTrue(transferInputs[7] != 0);
        assertTrue(
            verifier.verify(
                transferInputs, developmentProof(transferInputs), SPEND_ARTIFACT_HASH, false
            )
        );
        assertEq(withdrawInputs[16], 3);
        assertTrue(
            verifier.verify(
                withdrawInputs, developmentProof(withdrawInputs), SPEND_ARTIFACT_HASH, false
            )
        );
    }

    function testWrongArtifactHashReverts() public {
        uint256[29] memory inputs = loadCase(0);
        vm.expectRevert(bytes("ARTIFACT"));
        verifier.verify(inputs, developmentProof(inputs), bytes32(uint256(1)), false);
    }

    function testFieldOutOfRangeReverts() public {
        uint256[29] memory inputs = loadCase(0);
        inputs[17] = SNARK_SCALAR_FIELD;
        vm.expectRevert(bytes("FIELD_OUT_OF_RANGE"));
        verifier.verify(inputs, developmentProof(inputs), SPEND_ARTIFACT_HASH, false);
    }

    function testDepositRequiresZeroNoteRootAndNullifiers() public {
        uint256[29] memory inputs = loadCase(0);
        inputs[7] = 1;
        vm.expectRevert(bytes("ENCODING_INVALID"));
        verifier.verify(inputs, developmentProof(inputs), SPEND_ARTIFACT_HASH, false);
    }

    function testUnknownActionReverts() public {
        uint256[29] memory inputs = loadCase(0);
        inputs[16] = 6;
        vm.expectRevert(bytes("ENCODING_INVALID"));
        verifier.verify(inputs, developmentProof(inputs), SPEND_ARTIFACT_HASH, false);
    }

    function testWrongProtocolVersionTagReverts() public {
        uint256[29] memory inputs = loadCase(0);
        inputs[0] = 1;
        vm.expectRevert(bytes("VERSION_UNSUPPORTED"));
        verifier.verify(inputs, developmentProof(inputs), SPEND_ARTIFACT_HASH, false);
    }

    function testMalformedAndMismatchedProofsFail() public {
        uint256[29] memory inputs = loadCase(0);
        vm.expectRevert(bytes("ENCODING_INVALID"));
        verifier.verify(inputs, hex"01", SPEND_ARTIFACT_HASH, false);

        bytes memory wrong = abi.encodePacked(bytes32(uint256(2)));
        vm.expectRevert(bytes("ENCODING_INVALID"));
        verifier.verify(inputs, wrong, SPEND_ARTIFACT_HASH, false);
    }

    function testProductionSelectionIsKeysMissing() public {
        uint256[29] memory inputs = loadCase(0);
        vm.expectRevert(bytes("KEYS_MISSING"));
        verifier.verify(inputs, developmentProof(inputs), SPEND_ARTIFACT_HASH, true);
    }

    function testNoProxyAdminOrMutationPath() public {
        bytes4[6] memory forbidden = [
            bytes4(keccak256("owner()")),
            bytes4(keccak256("admin()")),
            bytes4(keccak256("upgradeTo(address)")),
            bytes4(keccak256("upgradeToAndCall(address,bytes)")),
            bytes4(keccak256("initialize(address)")),
            bytes4(keccak256("setPairingBackend(address)"))
        ];
        for (uint256 i = 0; i < forbidden.length; ++i) {
            (bool ok,) = address(verifier).call(abi.encodePacked(forbidden[i]));
            assertFalse(ok);
        }
        assertEq(address(verifier.pairingBackend()), address(pairing));
    }

    function testVerifyDepositGasSnapshot() public {
        uint256[29] memory inputs = loadCase(0);
        bytes memory proof = developmentProof(inputs);
        uint256 start = gasleft();
        bool ok = verifier.verify(inputs, proof, SPEND_ARTIFACT_HASH, false);
        uint256 used = start - gasleft();
        assertTrue(ok);
        assertEq(used, 15214);
        emit log_named_uint("verify_deposit_gas", used);
    }
}

contract HazeSpendVerifierPublicInputBindingTest is HazeSpendVerifierFixture {
    function testRejectsProofWhenActionPublicInputsDiffer() public {
        uint256[29] memory inputs = loadCase(0);
        bytes memory proof = developmentProof(inputs);
        uint256[5] memory indexes = [uint256(3), 17, 18, 20, 27];
        for (uint256 i = 0; i < indexes.length; ++i) {
            uint256[29] memory mutated = inputs;
            mutated[indexes[i]] = mutated[indexes[i]] + 1;
            vm.expectRevert(bytes("ENCODING_INVALID"));
            verifier.verify(mutated, proof, SPEND_ARTIFACT_HASH, false);
        }
    }
}
