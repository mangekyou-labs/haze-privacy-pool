// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ApplicationRegistry} from "./ApplicationRegistry.sol";
import {HazeAccess} from "./HazeAccess.sol";
import {HazePool} from "./HazePool.sol";
import {HazePoseidon2} from "./HazePoseidon2.sol";
import {IHazeSpendVerifier} from "./HazeSpendVerifier.sol";
import {PolicyRegistry} from "./PolicyRegistry.sol";

/// @title HazePoolPoseidon
/// @notice Sibling incremental tree using Poseidon2 haze/avalanche/v1/note-tree-node parents.
/// @dev Operator-owned demo. Not an upgrade of the keccak HazePool. No owner or proxy.
contract HazePoolPoseidon is HazePool {
    constructor(
        HazeAccess access_,
        ApplicationRegistry applications_,
        PolicyRegistry policies_,
        IHazeSpendVerifier verifier_,
        address usdc_,
        address approvedRouter_,
        address approvedExit_,
        bytes32 poolVersion_,
        uint256 rootHistorySize_
    )
        HazePool(
            access_,
            applications_,
            policies_,
            verifier_,
            usdc_,
            approvedRouter_,
            approvedExit_,
            poolVersion_,
            rootHistorySize_
        )
    {}

    function _hashPairAt(uint256 level, uint256 left, uint256 right)
        internal
        view
        virtual
        override
        returns (uint256)
    {
        return HazePoseidon2.parentNode(
            HazePoseidon2.domainField(HazePoseidon2.NOTE_TREE), level, left, right
        );
    }
}
