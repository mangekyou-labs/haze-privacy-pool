// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {HazeAccess} from "./HazeAccess.sol";

/// @title ApplicationRegistry
/// @notice Application identity, manifest hash, gatekeeper, and KYC membership root.
/// @dev Haze governance is not the KYC authority. Membership roots are app-controlled.
contract ApplicationRegistry {
    enum Status {
        Unspecified,
        Pending,
        Active,
        Suspended,
        Retired
    }

    struct ApplicationRecord {
        bytes32 applicationId;
        address admin;
        address gatekeeperSigner;
        address policyAuthority;
        bytes32 membershipRoot;
        uint64 membershipVersion;
        bytes auditPublicKey;
        uint64 auditKeyVersion;
        string manifestUri;
        bytes32 manifestHash;
        bytes32 policyProfile;
        Status status;
    }

    struct RegisterParams {
        bytes32 applicationId;
        address admin;
        address gatekeeperSigner;
        address policyAuthority;
        bytes32 membershipRoot;
        bytes auditPublicKey;
        string manifestUri;
        bytes32 manifestHash;
        bytes32 policyProfile;
    }

    HazeAccess public immutable access;

    mapping(bytes32 => ApplicationRecord) private applications;
    mapping(bytes32 => uint48) public registerActivateAt;
    mapping(bytes32 => uint48) public suspendActivateAt;
    mapping(bytes32 => uint48) public reactivateActivateAt;
    mapping(bytes32 => uint48) public retireActivateAt;

    event ApplicationScheduled(
        bytes32 indexed applicationId, address indexed admin, uint48 activateAt, bytes32 manifestHash
    );
    event ApplicationActivated(bytes32 indexed applicationId);
    event ApplicationSuspendScheduled(bytes32 indexed applicationId, uint48 activateAt);
    event ApplicationSuspended(bytes32 indexed applicationId);
    event ApplicationReactivateScheduled(bytes32 indexed applicationId, uint48 activateAt);
    event ApplicationReactivated(bytes32 indexed applicationId);
    event ApplicationRetireScheduled(bytes32 indexed applicationId, uint48 activateAt);
    event ApplicationRetired(bytes32 indexed applicationId);
    event MembershipRootUpdated(bytes32 indexed applicationId, bytes32 membershipRoot, uint64 membershipVersion);
    event GatekeeperRotated(bytes32 indexed applicationId, address gatekeeperSigner);
    event ManifestUpdated(bytes32 indexed applicationId, string manifestUri, bytes32 manifestHash);

    constructor(HazeAccess access_) {
        require(address(access_) != address(0), "ENCODING_INVALID");
        access = access_;
    }

    function scheduleRegister(RegisterParams calldata params) external {
        _whenNotPaused();
        _onlyGovernance();
        require(params.applicationId != bytes32(0), "ENCODING_INVALID");
        require(
            params.admin != address(0) && params.gatekeeperSigner != address(0)
                && params.policyAuthority != address(0),
            "ENCODING_INVALID"
        );
        ApplicationRecord storage record = applications[params.applicationId];
        require(record.status == Status.Unspecified, "STATUS_INVALID");
        uint48 activateAt = uint48(block.timestamp) + access.minDelay();
        record.applicationId = params.applicationId;
        record.admin = params.admin;
        record.gatekeeperSigner = params.gatekeeperSigner;
        record.policyAuthority = params.policyAuthority;
        record.membershipRoot = params.membershipRoot;
        record.membershipVersion = 1;
        record.auditPublicKey = params.auditPublicKey;
        record.auditKeyVersion = params.auditPublicKey.length == 0 ? 0 : 1;
        record.manifestUri = params.manifestUri;
        record.manifestHash = params.manifestHash;
        record.policyProfile = params.policyProfile;
        record.status = Status.Pending;
        registerActivateAt[params.applicationId] = activateAt;
        emit ApplicationScheduled(params.applicationId, params.admin, activateAt, params.manifestHash);
    }

    function activateRegister(bytes32 applicationId) external {
        _whenNotPaused();
        ApplicationRecord storage record = applications[applicationId];
        require(record.status == Status.Pending, "STATUS_INVALID");
        require(block.timestamp >= registerActivateAt[applicationId], "TIMELOCK");
        record.status = Status.Active;
        emit ApplicationActivated(applicationId);
    }

    function scheduleSuspend(bytes32 applicationId) external {
        _whenNotPaused();
        _onlyGovernance();
        ApplicationRecord storage record = applications[applicationId];
        require(record.status == Status.Active, "STATUS_INVALID");
        uint48 activateAt = uint48(block.timestamp) + access.minDelay();
        suspendActivateAt[applicationId] = activateAt;
        emit ApplicationSuspendScheduled(applicationId, activateAt);
    }

    function activateSuspend(bytes32 applicationId) external {
        _whenNotPaused();
        ApplicationRecord storage record = applications[applicationId];
        require(record.status == Status.Active, "STATUS_INVALID");
        require(
            suspendActivateAt[applicationId] != 0 && block.timestamp >= suspendActivateAt[applicationId], "TIMELOCK"
        );
        record.status = Status.Suspended;
        suspendActivateAt[applicationId] = 0;
        emit ApplicationSuspended(applicationId);
    }

    function scheduleReactivate(bytes32 applicationId) external {
        _whenNotPaused();
        _onlyGovernance();
        ApplicationRecord storage record = applications[applicationId];
        require(record.status == Status.Suspended, "STATUS_INVALID");
        uint48 activateAt = uint48(block.timestamp) + access.minDelay();
        reactivateActivateAt[applicationId] = activateAt;
        emit ApplicationReactivateScheduled(applicationId, activateAt);
    }

    function activateReactivate(bytes32 applicationId) external {
        _whenNotPaused();
        ApplicationRecord storage record = applications[applicationId];
        require(record.status == Status.Suspended, "STATUS_INVALID");
        require(
            reactivateActivateAt[applicationId] != 0 && block.timestamp >= reactivateActivateAt[applicationId],
            "TIMELOCK"
        );
        record.status = Status.Active;
        reactivateActivateAt[applicationId] = 0;
        emit ApplicationReactivated(applicationId);
    }

    function scheduleRetire(bytes32 applicationId) external {
        _whenNotPaused();
        _onlyGovernance();
        ApplicationRecord storage record = applications[applicationId];
        require(record.status == Status.Active || record.status == Status.Suspended, "STATUS_INVALID");
        uint48 activateAt = uint48(block.timestamp) + access.minDelay();
        retireActivateAt[applicationId] = activateAt;
        emit ApplicationRetireScheduled(applicationId, activateAt);
    }

    function activateRetire(bytes32 applicationId) external {
        _whenNotPaused();
        ApplicationRecord storage record = applications[applicationId];
        require(record.status == Status.Active || record.status == Status.Suspended, "STATUS_INVALID");
        require(retireActivateAt[applicationId] != 0 && block.timestamp >= retireActivateAt[applicationId], "TIMELOCK");
        record.status = Status.Retired;
        retireActivateAt[applicationId] = 0;
        emit ApplicationRetired(applicationId);
    }

    function updateMembershipRoot(bytes32 applicationId, bytes32 membershipRoot) external {
        _whenNotPaused();
        ApplicationRecord storage record = applications[applicationId];
        require(record.status == Status.Active, "STATUS_INVALID");
        require(msg.sender == record.policyAuthority, "UNAUTHORIZED");
        record.membershipRoot = membershipRoot;
        record.membershipVersion += 1;
        emit MembershipRootUpdated(applicationId, membershipRoot, record.membershipVersion);
    }

    function rotateGatekeeper(bytes32 applicationId, address gatekeeperSigner) external {
        _whenNotPaused();
        ApplicationRecord storage record = applications[applicationId];
        require(record.status == Status.Active || record.status == Status.Suspended, "STATUS_INVALID");
        require(msg.sender == record.admin, "UNAUTHORIZED");
        require(gatekeeperSigner != address(0), "ENCODING_INVALID");
        record.gatekeeperSigner = gatekeeperSigner;
        emit GatekeeperRotated(applicationId, gatekeeperSigner);
    }

    function updateManifest(bytes32 applicationId, string calldata manifestUri, bytes32 manifestHash) external {
        _whenNotPaused();
        ApplicationRecord storage record = applications[applicationId];
        require(record.status == Status.Active, "STATUS_INVALID");
        require(msg.sender == record.admin, "UNAUTHORIZED");
        record.manifestUri = manifestUri;
        record.manifestHash = manifestHash;
        emit ManifestUpdated(applicationId, manifestUri, manifestHash);
    }

    function getApplication(bytes32 applicationId) external view returns (ApplicationRecord memory) {
        return applications[applicationId];
    }

    function isActive(bytes32 applicationId) external view returns (bool) {
        return applications[applicationId].status == Status.Active;
    }

    function _onlyGovernance() internal view {
        require(msg.sender == access.governance(), "UNAUTHORIZED");
    }

    function _whenNotPaused() internal view {
        require(!access.paused(), "PAUSED");
    }
}
