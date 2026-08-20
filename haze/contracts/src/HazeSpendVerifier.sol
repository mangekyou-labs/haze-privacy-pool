// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {DevelopmentEqualityVerifier} from "haze-dev/DevelopmentEqualityVerifier.sol";

interface IHazeSpendVerifier {
    function verify(
        uint256[29] calldata publicInputs,
        bytes calldata proof,
        bytes32 artifactHash,
        bool production
    ) external view returns (bool);
}

/// @title HazeSpendVerifier
/// @notice Versioned immutable wrapper around spend public-input checks.
/// @dev Production Groth16 pairing from a ceremony-bound verifying key is T7.4.
///      This wrapper has no owner, proxy, or admin mutation path.
contract HazeSpendVerifier is IHazeSpendVerifier {
    bool public constant NOT_FOR_PRODUCTION = true;
    uint256 public constant PUBLIC_INPUT_COUNT = 29;
    uint256 public constant SNARK_SCALAR_FIELD =
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    bytes32 public constant PROTOCOL_VERSION_TAG =
        0x2afe8a5679df289719eae23ad89b300434b9dfbb8194dad0b50dee97f91a3868;
    bytes32 public constant SPEND_ARTIFACT_HASH =
        0xac2082ecb2129c571d2ddeb170f261a0da074491773102fa4f1544e97eb19281;
    bytes32 public constant CIRCUIT_BUILD_HASH =
        0x533f1d9d172c8395b4849bd7b90901b5314b7fc4735b878385e22b5a19d3cd41;

    DevelopmentEqualityVerifier public immutable pairingBackend;

    constructor(DevelopmentEqualityVerifier backend) {
        require(address(backend) != address(0), "ENCODING_INVALID");
        require(backend.NOT_FOR_PRODUCTION(), "VERSION_UNSUPPORTED");
        pairingBackend = backend;
    }

    function publicInputNames() external pure returns (string[29] memory names) {
        names = [
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
    }

    /// @notice Check 29 public inputs and the development proof digest.
    /// @param production When true, reverts `KEYS_MISSING` until T7.4.
    function verify(
        uint256[29] calldata publicInputs,
        bytes calldata proof,
        bytes32 artifactHash,
        bool production
    ) external view returns (bool) {
        if (production) {
            revert("KEYS_MISSING");
        }
        require(artifactHash == SPEND_ARTIFACT_HASH, "ARTIFACT");
        _checkPublicInputs(publicInputs);
        bytes32 digest = keccak256(abi.encodePacked(publicInputs));
        require(proof.length == 32, "ENCODING_INVALID");
        require(bytes32(proof) == digest, "ENCODING_INVALID");
        uint256 fieldDigest = uint256(digest) % SNARK_SCALAR_FIELD;
        return pairingBackend.verify(fieldDigest, fieldDigest, pairingBackend.ARTIFACT_HASH());
    }

    function _checkPublicInputs(uint256[29] calldata publicInputs) internal pure {
        for (uint256 i = 0; i < 29; ++i) {
            require(publicInputs[i] < SNARK_SCALAR_FIELD, "FIELD_OUT_OF_RANGE");
        }
        require(publicInputs[0] == uint256(PROTOCOL_VERSION_TAG), "VERSION_UNSUPPORTED");
        uint256 action = publicInputs[16];
        require(action >= 1 && action <= 5, "ENCODING_INVALID");
        if (action == 1) {
            require(
                publicInputs[7] == 0 && publicInputs[12] == 0 && publicInputs[13] == 0,
                "ENCODING_INVALID"
            );
        }
    }
}
