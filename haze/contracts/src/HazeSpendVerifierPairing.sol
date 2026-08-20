// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IHazeGroth16Verifier} from "./HazeGroth16Verifier.sol";
import {IHazeSpendVerifier} from "./HazeSpendVerifier.sol";
import {DevelopmentEqualityVerifier} from "haze-dev/DevelopmentEqualityVerifier.sol";

/// @title HazeSpendVerifierPairing
/// @notice Sibling wrap for an operator-owned pairing backend. Not an upgrade of the live Fuji verifier.
/// @dev `production=true` or a 256-byte Groth16 proof calls `verifyProof`. The committed
///      placeholder backend still reverts `KEYS_MISSING`. Digest path stays 32-byte keccak.
contract HazeSpendVerifierPairing is IHazeSpendVerifier {
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

    DevelopmentEqualityVerifier public immutable developmentBackend;
    IHazeGroth16Verifier public immutable pairingBackend;

    constructor(DevelopmentEqualityVerifier development, IHazeGroth16Verifier pairing) {
        require(address(development) != address(0), "ENCODING_INVALID");
        require(address(pairing) != address(0), "ENCODING_INVALID");
        require(development.NOT_FOR_PRODUCTION(), "VERSION_UNSUPPORTED");
        require(pairing.NOT_FOR_PRODUCTION(), "VERSION_UNSUPPORTED");
        developmentBackend = development;
        pairingBackend = pairing;
    }

    /// @param production When true, uses pairing. Operator-owned; not SC-09 production.
    function verify(
        uint256[29] calldata publicInputs,
        bytes calldata proof,
        bytes32 artifactHash,
        bool production
    ) external view returns (bool) {
        require(artifactHash == SPEND_ARTIFACT_HASH, "ARTIFACT");
        for (uint256 i = 0; i < 29; ++i) {
            require(publicInputs[i] < SNARK_SCALAR_FIELD, "FIELD_OUT_OF_RANGE");
        }
        require(publicInputs[0] == uint256(PROTOCOL_VERSION_TAG), "VERSION_UNSUPPORTED");
        if (production || proof.length != 32) {
            require(proof.length == 256, "ENCODING_INVALID");
            (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) =
                abi.decode(proof, (uint256[2], uint256[2][2], uint256[2]));
            return pairingBackend.verifyProof(a, b, c, publicInputs);
        }
        bytes32 digest = keccak256(abi.encodePacked(publicInputs));
        require(bytes32(proof) == digest, "ENCODING_INVALID");
        uint256 fieldDigest = uint256(digest) % SNARK_SCALAR_FIELD;
        return developmentBackend.verify(fieldDigest, fieldDigest, developmentBackend.ARTIFACT_HASH());
    }
}
