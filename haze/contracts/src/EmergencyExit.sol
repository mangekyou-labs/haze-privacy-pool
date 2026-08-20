// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {HazeAccess} from "./HazeAccess.sol";
import {HazePool} from "./HazePool.sol";
import {PolicyRegistry} from "./PolicyRegistry.sol";
import {VersionRegistry} from "./VersionRegistry.sol";

/// @title EmergencyExit
/// @notice Seven-day delayed public exit that ignores pause and application membership.
/// @dev Development 20-input digest only. Emergency Circom and production Groth16 remain later.
///      This contract has no owner, proxy, or upgrade path.
contract EmergencyExit {
    bool public constant NOT_FOR_PRODUCTION = true;
    uint256 public constant PUBLIC_INPUT_COUNT = 20;
    uint256 public constant COOLDOWN = 7 days;
    uint256 public constant SNARK_SCALAR_FIELD =
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    uint256 internal constant LIMB_MASK = (uint256(1) << 128) - 1;
    string internal constant REQUEST_TYPE =
        "HazeEmergencyExitRequest(uint256 chainId,address pool,bytes32 poolVersion,bytes32 applicationId,uint256 nullifier,address recipient,bytes32 requestSalt)";

    struct ExecuteArgs {
        bytes32 applicationId;
        uint256 noteTreeRoot;
        uint64 hazePolicyVersion;
        uint256 hazeBlocklistRoot;
        uint256 nullifier;
        uint64 publicAmount;
        address recipient;
        address requester;
        bytes32 requestSalt;
        uint256 auditDataCommitment;
        bytes32 auditCiphertextHash;
        bytes auditCiphertext;
        bytes proof;
    }

    HazeAccess public immutable access;
    HazePool public immutable pool;
    VersionRegistry public immutable versions;
    PolicyRegistry public immutable policies;

    mapping(bytes32 => uint48) public requestedAt;
    mapping(bytes32 => bool) public requestUsed;

    event EmergencyExitRequested(bytes32 indexed requestId, address indexed caller, uint48 requestedAt);
    event EmergencyExitExecuted(
        bytes32 indexed requestId, address indexed recipient, uint256 nullifier, uint64 amount
    );

    constructor(
        HazeAccess access_,
        HazePool pool_,
        VersionRegistry versions_,
        PolicyRegistry policies_
    ) {
        require(
            address(access_) != address(0) && address(pool_) != address(0)
                && address(versions_) != address(0) && address(policies_) != address(0),
            "ENCODING_INVALID"
        );
        require(pool_.approvedExit() == address(this), "UNAUTHORIZED");
        access = access_;
        pool = pool_;
        versions = versions_;
        policies = policies_;
    }

    function requestId(
        uint256 chainId,
        address pool_,
        bytes32 poolVersion,
        bytes32 applicationId,
        uint256 nullifier,
        address recipient,
        bytes32 requestSalt
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(bytes(REQUEST_TYPE)),
                chainId,
                pool_,
                poolVersion,
                applicationId,
                nullifier,
                recipient,
                requestSalt
            )
        );
    }

    function requestEmergencyExit(bytes32 requestId_) external {
        require(requestId_ != bytes32(0), "ENCODING_INVALID");
        require(requestedAt[requestId_] == 0, "STATUS_INVALID");
        uint48 at = uint48(block.timestamp);
        requestedAt[requestId_] = at;
        emit EmergencyExitRequested(requestId_, msg.sender, at);
    }

    function executeEmergencyExit(ExecuteArgs calldata args) external {
        require(args.nullifier != 0 && args.publicAmount != 0, "ENCODING_INVALID");
        require(
            args.recipient != address(0) && args.recipient != address(pool)
                && args.recipient != address(this),
            "ENCODING_INVALID"
        );
        require(keccak256(args.auditCiphertext) == args.auditCiphertextHash, "ENCODING_INVALID");
        require(args.proof.length == 32, "ENCODING_INVALID");

        bytes32 id = requestId(
            block.chainid,
            address(pool),
            pool.poolVersion(),
            args.applicationId,
            args.nullifier,
            args.recipient,
            args.requestSalt
        );
        uint48 at = requestedAt[id];
        require(at != 0 && !requestUsed[id], "STATUS_INVALID");
        require(block.timestamp >= uint256(at) + COOLDOWN, "AUTH_WINDOW");
        require(versions.isExitCapable(pool.poolVersion()), "VERSION_UNSUPPORTED");
        require(
            policies.isActivePolicy(args.hazePolicyVersion, bytes32(args.hazeBlocklistRoot)),
            "POLICY_INVALID"
        );
        require(pool.knownRoot(args.noteTreeRoot), "ROOT_UNKNOWN");

        uint256[20] memory inputs = publicInputs(args);
        for (uint256 i = 0; i < 20; ++i) {
            require(inputs[i] < SNARK_SCALAR_FIELD, "FIELD_OUT_OF_RANGE");
        }
        require(bytes32(args.proof) == keccak256(abi.encodePacked(inputs)), "ENCODING_INVALID");

        requestUsed[id] = true;
        pool.exitFromEmergency(
            args.applicationId,
            args.requester,
            args.noteTreeRoot,
            args.hazePolicyVersion,
            args.nullifier,
            args.publicAmount,
            args.recipient,
            args.auditDataCommitment,
            args.auditCiphertextHash,
            "",
            "",
            args.auditCiphertext
        );
        emit EmergencyExitExecuted(id, args.recipient, args.nullifier, args.publicAmount);
    }

    function publicInputs(ExecuteArgs memory args) public view returns (uint256[20] memory inputs) {
        bytes32 id = requestId(
            block.chainid,
            address(pool),
            pool.poolVersion(),
            args.applicationId,
            args.nullifier,
            args.recipient,
            args.requestSalt
        );
        bytes32 version = pool.poolVersion();
        inputs[0] = uint256(pool.PROTOCOL_VERSION_TAG());
        inputs[1] = block.chainid;
        inputs[2] = uint256(uint160(address(pool)));
        inputs[3] = uint256(version) >> 128;
        inputs[4] = uint256(version) & LIMB_MASK;
        inputs[5] = uint256(args.applicationId) >> 128;
        inputs[6] = uint256(args.applicationId) & LIMB_MASK;
        inputs[7] = args.noteTreeRoot;
        inputs[8] = args.hazePolicyVersion;
        inputs[9] = args.hazeBlocklistRoot;
        inputs[10] = args.nullifier;
        inputs[11] = 5;
        inputs[12] = args.publicAmount;
        inputs[13] = uint256(uint160(args.recipient));
        inputs[14] = uint256(uint160(args.requester));
        inputs[15] = uint256(id) >> 128;
        inputs[16] = uint256(id) & LIMB_MASK;
        inputs[17] = args.auditDataCommitment;
        inputs[18] = uint256(args.auditCiphertextHash) >> 128;
        inputs[19] = uint256(args.auditCiphertextHash) & LIMB_MASK;
    }
}
