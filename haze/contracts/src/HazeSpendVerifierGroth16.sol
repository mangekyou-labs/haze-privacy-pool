// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IHazeGroth16Verifier} from "./HazeGroth16Verifier.sol";
import {IHazeSpendVerifier} from "./HazeSpendVerifier.sol";

/// @title HazeSpendVerifierGroth16
/// @notice Pairing-only spend verifier. Every accepted proof is a 256-byte Groth16 proof
///         checked by `IHazeGroth16Verifier.verifyProof`.
/// @dev Replaces `HazeSpendVerifierPairing` for the Fuji v2 set. The 32-byte
///      `keccak256(publicInputs)` development digest path is removed: the digest is computable by
///      anyone from public data, so it authenticates nothing. The `production` flag is ignored;
///      both values take the same pairing path. Artifact-hash, field-range and version-tag checks
///      are unchanged. No owner, proxy, or upgrade path. The pairing backend is operator-owned and
///      not an SC-09 production ceremony, so this contract stays `NOT_FOR_PRODUCTION`.
contract HazeSpendVerifierGroth16 is IHazeSpendVerifier {
    bool public constant NOT_FOR_PRODUCTION = true;
    uint256 public constant PUBLIC_INPUT_COUNT = 29;
    uint256 public constant PROOF_LENGTH = 256;
    uint256 public constant SNARK_SCALAR_FIELD =
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    bytes32 public constant PROTOCOL_VERSION_TAG =
        0x2afe8a5679df289719eae23ad89b300434b9dfbb8194dad0b50dee97f91a3868;
    bytes32 public constant SPEND_ARTIFACT_HASH =
        0xac2082ecb2129c571d2ddeb170f261a0da074491773102fa4f1544e97eb19281;
    bytes32 public constant CIRCUIT_BUILD_HASH =
        0x533f1d9d172c8395b4849bd7b90901b5314b7fc4735b878385e22b5a19d3cd41;

    IHazeGroth16Verifier public immutable pairingBackend;

    constructor(IHazeGroth16Verifier pairing) {
        require(address(pairing).code.length != 0, "ENCODING_INVALID");
        require(pairing.NOT_FOR_PRODUCTION(), "VERSION_UNSUPPORTED");
        pairingBackend = pairing;
    }

    /// @param production Ignored. Kept for `IHazeSpendVerifier` compatibility; there is no
    ///        non-pairing path.
    function verify(
        uint256[29] calldata publicInputs,
        bytes calldata proof,
        bytes32 artifactHash,
        bool production
    ) external view returns (bool) {
        production;
        require(artifactHash == SPEND_ARTIFACT_HASH, "ARTIFACT");
        for (uint256 i = 0; i < 29; ++i) {
            require(publicInputs[i] < SNARK_SCALAR_FIELD, "FIELD_OUT_OF_RANGE");
        }
        require(publicInputs[0] == uint256(PROTOCOL_VERSION_TAG), "VERSION_UNSUPPORTED");
        require(proof.length == PROOF_LENGTH, "ENCODING_INVALID");
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) =
            abi.decode(proof, (uint256[2], uint256[2][2], uint256[2]));
        return pairingBackend.verifyProof(a, b, c, publicInputs);
    }
}
