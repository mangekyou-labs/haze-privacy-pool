// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {HazeAccess} from "./HazeAccess.sol";

/// @title PolicyRegistry
/// @notice Timelocked Haze global blocklist roots with no post-activation grace period.
contract PolicyRegistry {
    enum Status {
        Unspecified,
        Scheduled,
        Active,
        Retired
    }

    struct PolicyVersion {
        uint64 version;
        bytes32 globalBlocklistRoot;
        uint48 activateAt;
        bytes32 artifactHash;
        Status status;
    }

    HazeAccess public immutable access;
    uint64 public lastScheduledVersion;
    uint64 public activeVersion;
    bytes32 public activeRoot;

    mapping(uint64 => PolicyVersion) private versions;

    event PolicyScheduled(uint64 indexed version, bytes32 globalBlocklistRoot, uint48 activateAt, bytes32 artifactHash);
    event PolicyActivated(uint64 indexed version, uint64 retiredVersion, bytes32 globalBlocklistRoot);

    constructor(HazeAccess access_) {
        require(address(access_) != address(0), "ENCODING_INVALID");
        access = access_;
    }

    function schedulePolicy(uint64 version, bytes32 globalBlocklistRoot, bytes32 artifactHash) external {
        require(!access.paused(), "PAUSED");
        require(msg.sender == access.governance(), "UNAUTHORIZED");
        require(version == lastScheduledVersion + 1, "VERSION_UNSUPPORTED");
        require(globalBlocklistRoot != bytes32(0) && artifactHash != bytes32(0), "ENCODING_INVALID");
        uint48 activateAt = uint48(block.timestamp) + access.minDelay();
        versions[version] = PolicyVersion({
            version: version,
            globalBlocklistRoot: globalBlocklistRoot,
            activateAt: activateAt,
            artifactHash: artifactHash,
            status: Status.Scheduled
        });
        lastScheduledVersion = version;
        emit PolicyScheduled(version, globalBlocklistRoot, activateAt, artifactHash);
    }

    function activatePolicy(uint64 version) external {
        require(!access.paused(), "PAUSED");
        PolicyVersion storage scheduled = versions[version];
        require(scheduled.status == Status.Scheduled, "STATUS_INVALID");
        require(block.timestamp >= scheduled.activateAt, "TIMELOCK");
        uint64 retiredVersion = activeVersion;
        if (retiredVersion != 0) {
            versions[retiredVersion].status = Status.Retired;
        }
        scheduled.status = Status.Active;
        activeVersion = version;
        activeRoot = scheduled.globalBlocklistRoot;
        emit PolicyActivated(version, retiredVersion, scheduled.globalBlocklistRoot);
    }

    function policy(uint64 version) external view returns (PolicyVersion memory) {
        return versions[version];
    }

    function isActivePolicy(uint64 version, bytes32 globalBlocklistRoot) external view returns (bool) {
        return version != 0 && version == activeVersion && globalBlocklistRoot == activeRoot;
    }
}
