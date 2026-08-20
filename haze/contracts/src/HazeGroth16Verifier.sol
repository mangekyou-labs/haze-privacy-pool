// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IHazeGroth16Verifier {
    function NOT_FOR_PRODUCTION() external view returns (bool);

    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[29] calldata input
    ) external view returns (bool);
}

/// @title HazeGroth16Verifier
/// @notice Placeholder pairing backend. Does not contain a verifying key.
/// @dev A one-laptop snarkjs export is not committed here. `verifyProof` stays
///      `KEYS_MISSING` until an operator-exported verifier is reviewed and a
///      later SC-09 flip authorizes wiring it.
contract HazeGroth16Verifier is IHazeGroth16Verifier {
    bool public constant NOT_FOR_PRODUCTION = true;

    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[29] calldata
    ) external pure returns (bool) {
        revert("KEYS_MISSING");
    }
}
