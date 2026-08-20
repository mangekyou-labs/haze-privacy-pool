// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title HazeAccess
/// @notice Separate governance, pause, and super-auditor capabilities.
/// @dev Super-auditor grants are timelocked and confer no registry mutation.
contract HazeAccess {
    address public immutable governance;
    address public immutable pauseRole;
    uint48 public immutable minDelay;

    bool public paused;
    mapping(address => bool) public isSuperAuditor;

    address public pendingSuperAuditor;
    bool public pendingSuperAuditorGrant;
    uint48 public pendingSuperAuditorEta;
    bool public superAuditorScheduled;

    event Paused(address indexed caller);
    event Unpaused(address indexed caller);
    event SuperAuditorScheduled(address indexed account, bool grant, uint48 activateAt);
    event SuperAuditorUpdated(address indexed account, bool grant);

    constructor(address governance_, address pauseRole_, uint48 minDelay_) {
        require(governance_ != address(0) && pauseRole_ != address(0), "ENCODING_INVALID");
        require(minDelay_ != 0, "ENCODING_INVALID");
        governance = governance_;
        pauseRole = pauseRole_;
        minDelay = minDelay_;
    }

    function pause() external {
        require(msg.sender == pauseRole, "UNAUTHORIZED");
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external {
        require(msg.sender == pauseRole, "UNAUTHORIZED");
        paused = false;
        emit Unpaused(msg.sender);
    }

    function scheduleSuperAuditor(address account, bool grant) external {
        require(!paused, "PAUSED");
        require(msg.sender == governance, "UNAUTHORIZED");
        require(account != address(0), "ENCODING_INVALID");
        pendingSuperAuditor = account;
        pendingSuperAuditorGrant = grant;
        pendingSuperAuditorEta = uint48(block.timestamp) + minDelay;
        superAuditorScheduled = true;
        emit SuperAuditorScheduled(account, grant, pendingSuperAuditorEta);
    }

    function activateSuperAuditor() external {
        require(!paused, "PAUSED");
        require(superAuditorScheduled && block.timestamp >= pendingSuperAuditorEta, "TIMELOCK");
        isSuperAuditor[pendingSuperAuditor] = pendingSuperAuditorGrant;
        emit SuperAuditorUpdated(pendingSuperAuditor, pendingSuperAuditorGrant);
        superAuditorScheduled = false;
        pendingSuperAuditor = address(0);
        pendingSuperAuditorEta = 0;
    }
}
