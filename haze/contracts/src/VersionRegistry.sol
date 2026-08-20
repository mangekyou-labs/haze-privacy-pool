// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {HazeAccess} from "./HazeAccess.sol";

/// @title VersionRegistry
/// @notice Publishes immutable release metadata and artifact hashes.
/// @dev This contract does not upgrade deployed code.
contract VersionRegistry {
    enum Status {
        Unspecified,
        Scheduled,
        Active,
        Retired
    }

    struct Release {
        bytes32 versionTag;
        bytes32 artifactHash;
        string metadataUri;
        uint48 activateAt;
        uint48 supportUntil;
        Status status;
    }

    HazeAccess public immutable access;
    bytes32 public activeTag;

    mapping(bytes32 => Release) private releases;

    event ReleaseScheduled(bytes32 indexed versionTag, bytes32 artifactHash, uint48 activateAt);
    event ReleaseActivated(bytes32 indexed versionTag, bytes32 artifactHash);

    constructor(HazeAccess access_) {
        require(address(access_) != address(0), "ENCODING_INVALID");
        access = access_;
    }

    function scheduleRelease(bytes32 versionTag, bytes32 artifactHash, string calldata metadataUri) external {
        _scheduleRelease(versionTag, artifactHash, metadataUri, 0);
    }

    function scheduleRelease(
        bytes32 versionTag,
        bytes32 artifactHash,
        string calldata metadataUri,
        uint48 supportUntil
    ) external {
        _scheduleRelease(versionTag, artifactHash, metadataUri, supportUntil);
    }

    function isExitCapable(bytes32 versionTag) external view returns (bool) {
        Status status = releases[versionTag].status;
        if (status == Status.Unspecified) {
            return true;
        }
        if (status == Status.Scheduled) {
            return false;
        }
        if (status == Status.Active) {
            return true;
        }
        return block.timestamp <= releases[versionTag].supportUntil;
    }

    function _scheduleRelease(
        bytes32 versionTag,
        bytes32 artifactHash,
        string calldata metadataUri,
        uint48 supportUntil
    ) internal {
        require(!access.paused(), "PAUSED");
        require(msg.sender == access.governance(), "UNAUTHORIZED");
        require(versionTag != bytes32(0) && artifactHash != bytes32(0), "ENCODING_INVALID");
        require(releases[versionTag].status == Status.Unspecified, "STATUS_INVALID");
        uint48 activateAt = uint48(block.timestamp) + access.minDelay();
        require(supportUntil == 0 || supportUntil > activateAt, "ENCODING_INVALID");
        releases[versionTag] = Release({
            versionTag: versionTag,
            artifactHash: artifactHash,
            metadataUri: metadataUri,
            activateAt: activateAt,
            supportUntil: supportUntil,
            status: Status.Scheduled
        });
        emit ReleaseScheduled(versionTag, artifactHash, activateAt);
    }

    function activateRelease(bytes32 versionTag) external {
        require(!access.paused(), "PAUSED");
        Release storage scheduled = releases[versionTag];
        require(scheduled.status == Status.Scheduled, "STATUS_INVALID");
        require(block.timestamp >= scheduled.activateAt, "TIMELOCK");
        if (activeTag != bytes32(0)) {
            releases[activeTag].status = Status.Retired;
        }
        scheduled.status = Status.Active;
        activeTag = versionTag;
        emit ReleaseActivated(versionTag, scheduled.artifactHash);
    }

    function release(bytes32 versionTag) external view returns (Release memory) {
        return releases[versionTag];
    }

    function activeRelease() external view returns (Release memory) {
        return releases[activeTag];
    }

    function isActiveRelease(bytes32 versionTag, bytes32 artifactHash) external view returns (bool) {
        return versionTag != bytes32(0) && versionTag == activeTag && artifactHash == releases[versionTag].artifactHash;
    }
}
