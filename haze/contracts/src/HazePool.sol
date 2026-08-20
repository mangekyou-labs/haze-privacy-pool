// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ApplicationRegistry} from "./ApplicationRegistry.sol";
import {HazeAccess} from "./HazeAccess.sol";
import {HazeProtocolVectors} from "./HazeProtocolVectors.sol";
import {IHazeSpendVerifier} from "./HazeSpendVerifier.sol";
import {PolicyRegistry} from "./PolicyRegistry.sol";

interface IERC20Minimal {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title HazePool
/// @notice USDC custody, note-tree updates, and authorization for private actions.
/// @dev Development incremental tree uses keccak parents reduced mod r. On-chain
///      Poseidon2 updates and production Groth16 keys remain later tasks.
///      This contract has no owner, proxy, or upgrade path.
contract HazePool {
    bool public constant NOT_FOR_PRODUCTION = true;
    uint256 public constant PUBLIC_INPUT_COUNT = 29;
    uint256 public constant SNARK_SCALAR_FIELD =
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    bytes32 public constant PROTOCOL_VERSION_TAG =
        0x2afe8a5679df289719eae23ad89b300434b9dfbb8194dad0b50dee97f91a3868;
    bytes32 public constant SPEND_ARTIFACT_HASH =
        0xac2082ecb2129c571d2ddeb170f261a0da074491773102fa4f1544e97eb19281;
    string public constant DOMAIN_NAME = "Haze Avalanche Compliant Pool";
    string public constant DOMAIN_VERSION = "1";
    uint256 internal constant TREE_DEPTH = 32;
    uint256 internal constant LIMB_MASK = (uint256(1) << 128) - 1;

    struct TransactArgs {
        HazeProtocolVectors.IntentFields intent;
        HazeProtocolVectors.AuthorizationFields authorization;
        bytes authorizationSignature;
        bytes proof;
        bytes recipientCiphertext0;
        bytes recipientCiphertext1;
        bytes auditCiphertext;
    }

    HazeAccess public immutable access;
    ApplicationRegistry public immutable applications;
    PolicyRegistry public immutable policies;
    IHazeSpendVerifier public immutable verifier;
    IERC20Minimal public immutable usdc;
    address public immutable approvedRouter;
    address public immutable approvedExit;
    bytes32 public immutable poolVersion;
    uint256 public immutable rootHistorySize;

    uint256 public emptyTreeRoot;
    uint256 public currentRoot;
    uint256 public nextIndex;
    uint256 public rootHistoryCursor;
    uint256 public rootHistoryFilled;
    bool private locked;

    uint256[TREE_DEPTH] public zeros;
    uint256[TREE_DEPTH] public filledSubtrees;
    uint256[] public rootHistory;

    mapping(uint256 => bool) public knownRoot;
    mapping(uint256 => bool) public commitmentExists;
    mapping(uint256 => bool) public nullifierUsed;
    mapping(bytes32 => bool) public usedNonceKeys;

    event PrivateTransaction(
        bytes32 indexed applicationId,
        uint8 indexed action,
        address indexed user,
        uint64 applicationPolicyVersion,
        uint64 hazePolicyVersion,
        uint256 noteTreeRoot,
        uint256 inputNullifier0,
        uint256 inputNullifier1,
        uint256 outputCommitment0,
        uint256 outputCommitment1,
        uint64 publicAmount,
        address publicRecipient,
        bytes32 recipientCiphertextHash0,
        bytes32 recipientCiphertextHash1,
        uint256 auditDataCommitment,
        bytes32 auditCiphertextHash,
        bytes recipientCiphertext0,
        bytes recipientCiphertext1,
        bytes auditCiphertext
    );

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
    ) {
        require(
            address(access_) != address(0) && address(applications_) != address(0)
                && address(policies_) != address(0) && address(verifier_) != address(0)
                && usdc_ != address(0) && poolVersion_ != bytes32(0),
            "ENCODING_INVALID"
        );
        require(rootHistorySize_ != 0 && rootHistorySize_ <= 256, "ENCODING_INVALID");
        access = access_;
        applications = applications_;
        policies = policies_;
        verifier = verifier_;
        usdc = IERC20Minimal(usdc_);
        approvedRouter = approvedRouter_;
        approvedExit = approvedExit_;
        poolVersion = poolVersion_;
        rootHistorySize = rootHistorySize_;
        rootHistory = new uint256[](rootHistorySize_);

        uint256 zero;
        zeros[0] = 0;
        filledSubtrees[0] = 0;
        for (uint256 i = 1; i < TREE_DEPTH; ++i) {
            zero = _hashPairAt(i - 1, zero, zero);
            zeros[i] = zero;
            filledSubtrees[i] = zero;
        }
        emptyTreeRoot = _hashPairAt(TREE_DEPTH - 1, zero, zero);
        currentRoot = emptyTreeRoot;
        _storeRoot(emptyTreeRoot);
    }

    function deposit(TransactArgs calldata args) external {
        require(args.intent.action == 1, "ENCODING_INVALID");
        _execute(args, msg.sender, msg.sender);
    }

    function transact(TransactArgs calldata args) external {
        uint8 action = args.intent.action;
        require(action == 2 || action == 3, "ENCODING_INVALID");
        _execute(args, msg.sender, address(0));
    }

    function exitFromEmergency(
        bytes32 applicationId,
        address user,
        uint256 noteTreeRoot,
        uint64 hazePolicyVersion,
        uint256 nullifier,
        uint64 publicAmount,
        address publicRecipient,
        uint256 auditDataCommitment,
        bytes32 auditCiphertextHash,
        bytes calldata recipientCiphertext0,
        bytes calldata recipientCiphertext1,
        bytes calldata auditCiphertext
    ) external {
        require(!locked, "REENTRANCY");
        locked = true;
        require(msg.sender == approvedExit && approvedExit != address(0), "UNAUTHORIZED");
        require(nullifier != 0, "ENCODING_INVALID");
        _consumeNullifier(nullifier);
        _pushUsdc(publicRecipient, publicAmount);
        emit PrivateTransaction(
            applicationId,
            5,
            user,
            0,
            hazePolicyVersion,
            noteTreeRoot,
            nullifier,
            0,
            0,
            0,
            publicAmount,
            publicRecipient,
            keccak256(recipientCiphertext0),
            keccak256(recipientCiphertext1),
            auditDataCommitment,
            auditCiphertextHash,
            recipientCiphertext0,
            recipientCiphertext1,
            auditCiphertext
        );
        locked = false;
    }

    function depositFromRouter(address payer, TransactArgs calldata args) external {
        require(msg.sender == approvedRouter && approvedRouter != address(0), "UNAUTHORIZED");
        require(args.intent.action == 4, "ENCODING_INVALID");
        require(payer == args.intent.user, "UNAUTHORIZED");
        _execute(args, payer, msg.sender);
    }

    function nonceUsed(bytes32 applicationId, address gatekeeperSigner, bytes32 nonce)
        external
        view
        returns (bool)
    {
        return usedNonceKeys[_nonceKey(applicationId, gatekeeperSigner, nonce)];
    }

    function publicInputs(HazeProtocolVectors.IntentFields memory intent)
        public
        view
        returns (uint256[29] memory inputs)
    {
        bytes32 intentDigest = HazeProtocolVectors.typedDataDigest(
            HazeProtocolVectors.domainSeparator(DOMAIN_NAME, DOMAIN_VERSION, block.chainid, address(this)),
            HazeProtocolVectors.intentStructHash(intent)
        );
        inputs[0] = uint256(PROTOCOL_VERSION_TAG);
        inputs[1] = block.chainid;
        inputs[2] = uint256(uint160(address(this)));
        inputs[3] = uint256(poolVersion) >> 128;
        inputs[4] = uint256(poolVersion) & LIMB_MASK;
        inputs[5] = uint256(intent.applicationId) >> 128;
        inputs[6] = uint256(intent.applicationId) & LIMB_MASK;
        inputs[7] = intent.noteTreeRoot;
        inputs[8] = intent.applicationPolicyVersion;
        inputs[9] = intent.hazePolicyVersion;
        inputs[10] = intent.applicationMembershipRoot;
        inputs[11] = intent.hazeBlocklistRoot;
        inputs[12] = intent.inputNullifier0;
        inputs[13] = intent.inputNullifier1;
        inputs[14] = intent.outputCommitment0;
        inputs[15] = intent.outputCommitment1;
        inputs[16] = intent.action;
        inputs[17] = intent.publicAmount;
        inputs[18] = uint256(uint160(intent.publicRecipient));
        inputs[19] = uint256(uint160(intent.user));
        inputs[20] = uint256(intentDigest) >> 128;
        inputs[21] = uint256(intentDigest) & LIMB_MASK;
        inputs[22] = uint256(intent.recipientCiphertextHash0) >> 128;
        inputs[23] = uint256(intent.recipientCiphertextHash0) & LIMB_MASK;
        inputs[24] = uint256(intent.recipientCiphertextHash1) >> 128;
        inputs[25] = uint256(intent.recipientCiphertextHash1) & LIMB_MASK;
        inputs[26] = intent.auditDataCommitment;
        inputs[27] = uint256(intent.auditCiphertextHash) >> 128;
        inputs[28] = uint256(intent.auditCiphertextHash) & LIMB_MASK;
    }

    function _execute(TransactArgs calldata args, address expectedUser, address tokenFrom) internal {
        require(!locked, "REENTRANCY");
        locked = true;
        require(!access.paused(), "PAUSED");
        require(args.intent.user == expectedUser, "UNAUTHORIZED");

        ApplicationRegistry.ApplicationRecord memory app = _checkLiveContext(args.intent);
        _checkIntentShape(args.intent);
        _checkCiphertexts(args);
        _checkAuthorization(args, app.gatekeeperSigner);
        require(
            verifier.verify(publicInputs(args.intent), args.proof, SPEND_ARTIFACT_HASH, false),
            "ENCODING_INVALID"
        );

        bytes32 nonceKey = _nonceKey(args.intent.applicationId, app.gatekeeperSigner, args.authorization.nonce);
        require(!usedNonceKeys[nonceKey], "NONCE_USED");
        usedNonceKeys[nonceKey] = true;
        _consumeNullifier(args.intent.inputNullifier0);
        _consumeNullifier(args.intent.inputNullifier1);

        uint8 action = args.intent.action;
        if (action == 1 || action == 4) {
            _pullUsdc(tokenFrom, args.intent.publicAmount);
        }
        _insertOutput(args.intent.outputCommitment0);
        _insertOutput(args.intent.outputCommitment1);
        if (action == 3) {
            _pushUsdc(args.intent.publicRecipient, args.intent.publicAmount);
        }

        emit PrivateTransaction(
            args.intent.applicationId,
            action,
            args.intent.user,
            args.intent.applicationPolicyVersion,
            args.intent.hazePolicyVersion,
            args.intent.noteTreeRoot,
            args.intent.inputNullifier0,
            args.intent.inputNullifier1,
            args.intent.outputCommitment0,
            args.intent.outputCommitment1,
            args.intent.publicAmount,
            args.intent.publicRecipient,
            args.intent.recipientCiphertextHash0,
            args.intent.recipientCiphertextHash1,
            args.intent.auditDataCommitment,
            args.intent.auditCiphertextHash,
            args.recipientCiphertext0,
            args.recipientCiphertext1,
            args.auditCiphertext
        );
        locked = false;
    }

    function _checkLiveContext(HazeProtocolVectors.IntentFields calldata intent)
        internal
        view
        returns (ApplicationRegistry.ApplicationRecord memory app)
    {
        require(applications.isActive(intent.applicationId), "STATUS_INVALID");
        app = applications.getApplication(intent.applicationId);
        require(
            intent.applicationPolicyVersion == app.membershipVersion
                && intent.applicationMembershipRoot == uint256(app.membershipRoot),
            "POLICY_INVALID"
        );
        require(
            policies.isActivePolicy(intent.hazePolicyVersion, bytes32(intent.hazeBlocklistRoot)),
            "POLICY_INVALID"
        );
    }

    function _checkIntentShape(HazeProtocolVectors.IntentFields calldata intent) internal view {
        require(intent.pool == address(this) && intent.poolVersion == poolVersion, "ENCODING_INVALID");
        uint8 action = intent.action;
        require(action >= 1 && action <= 4, "ENCODING_INVALID");
        bool swapZero = intent.tokenIn == address(0) && intent.amountIn == 0
            && intent.minUsdcOut == 0 && intent.routeHash == bytes32(0) && intent.deadline == 0;
        if (action != 4) {
            require(swapZero, "ENCODING_INVALID");
        } else {
            require(intent.deadline == 0 || intent.deadline >= block.timestamp, "AUTH_WINDOW");
        }
        if (action == 1 || action == 4) {
            require(
                intent.noteTreeRoot == 0 && intent.inputNullifier0 == 0 && intent.inputNullifier1 == 0,
                "ENCODING_INVALID"
            );
            require(intent.publicAmount != 0 && intent.publicRecipient == address(0), "ENCODING_INVALID");
            require(intent.outputCommitment0 != 0 || intent.outputCommitment1 != 0, "ENCODING_INVALID");
        } else {
            require(knownRoot[intent.noteTreeRoot], "ROOT_UNKNOWN");
            require(intent.inputNullifier0 != 0 || intent.inputNullifier1 != 0, "ENCODING_INVALID");
            if (action == 2) {
                require(intent.publicAmount == 0 && intent.publicRecipient == address(0), "ENCODING_INVALID");
                require(intent.outputCommitment0 != 0 || intent.outputCommitment1 != 0, "ENCODING_INVALID");
            } else {
                require(intent.publicAmount != 0 && intent.publicRecipient != address(0), "ENCODING_INVALID");
            }
        }
    }

    function _ciphertextMatches(bytes32 expected, bytes calldata payload) internal pure returns (bool) {
        if (expected == bytes32(0)) {
            return payload.length == 0;
        }
        return keccak256(payload) == expected;
    }

    function _checkCiphertexts(TransactArgs calldata args) internal pure {
        require(
            _ciphertextMatches(args.intent.recipientCiphertextHash0, args.recipientCiphertext0)
                && _ciphertextMatches(args.intent.recipientCiphertextHash1, args.recipientCiphertext1)
                && _ciphertextMatches(args.intent.auditCiphertextHash, args.auditCiphertext),
            "ENCODING_INVALID"
        );
    }

    function _checkAuthorization(TransactArgs calldata args, address gatekeeperSigner) internal view {
        HazeProtocolVectors.AuthorizationFields calldata auth = args.authorization;
        HazeProtocolVectors.IntentFields calldata intent = args.intent;
        require(
            auth.applicationId == intent.applicationId && auth.user == intent.user
                && auth.pool == address(this) && auth.poolVersion == poolVersion
                && auth.action == intent.action
                && auth.applicationPolicyVersion == intent.applicationPolicyVersion
                && auth.hazePolicyVersion == intent.hazePolicyVersion
                && auth.auditDataCommitment == intent.auditDataCommitment
                && auth.auditCiphertextHash == intent.auditCiphertextHash
                && auth.intentHash == HazeProtocolVectors.intentStructHash(intent),
            "ENCODING_INVALID"
        );
        require(
            block.timestamp >= auth.validAfter && block.timestamp <= auth.validUntil, "AUTH_WINDOW"
        );
        bytes32 digest = HazeProtocolVectors.typedDataDigest(
            HazeProtocolVectors.domainSeparator(DOMAIN_NAME, DOMAIN_VERSION, block.chainid, address(this)),
            HazeProtocolVectors.authorizationStructHash(auth)
        );
        require(_recover(digest, args.authorizationSignature) == gatekeeperSigner, "UNAUTHORIZED");
    }

    function _consumeNullifier(uint256 nullifier) internal {
        if (nullifier == 0) {
            return;
        }
        require(!nullifierUsed[nullifier], "NULLIFIER_USED");
        nullifierUsed[nullifier] = true;
    }

    function _insertOutput(uint256 commitment) internal {
        if (commitment == 0) {
            return;
        }
        require(!commitmentExists[commitment], "COMMITMENT_DUPLICATE");
        commitmentExists[commitment] = true;
        require(nextIndex < (uint256(1) << TREE_DEPTH), "ENCODING_INVALID");
        uint256 index = nextIndex;
        uint256 node = commitment;
        for (uint256 i = 0; i < TREE_DEPTH; ++i) {
            if (index % 2 == 0) {
                filledSubtrees[i] = node;
                node = _hashPairAt(i, node, zeros[i]);
            } else {
                node = _hashPairAt(i, filledSubtrees[i], node);
            }
            index /= 2;
        }
        nextIndex += 1;
        currentRoot = node;
        _storeRoot(node);
    }

    function _storeRoot(uint256 root) internal {
        uint256 slot = rootHistoryCursor;
        if (rootHistoryFilled == rootHistorySize) {
            knownRoot[rootHistory[slot]] = false;
        }
        rootHistory[slot] = root;
        knownRoot[root] = true;
        uint256 next = slot + 1;
        rootHistoryCursor = next == rootHistorySize ? 0 : next;
        if (rootHistoryFilled < rootHistorySize) {
            rootHistoryFilled += 1;
        }
    }

    function _pullUsdc(address from, uint64 amount) internal {
        require(from != address(0) && amount != 0, "ENCODING_INVALID");
        require(usdc.transferFrom(from, address(this), amount), "ENCODING_INVALID");
    }

    function _pushUsdc(address to, uint64 amount) internal {
        require(to != address(0) && amount != 0, "ENCODING_INVALID");
        require(usdc.transfer(to, amount), "ENCODING_INVALID");
    }

    function _nonceKey(bytes32 applicationId, address gatekeeperSigner, bytes32 nonce)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(applicationId, gatekeeperSigner, nonce));
    }

    function _hashPair(uint256 left, uint256 right) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(left, right))) % SNARK_SCALAR_FIELD;
    }

    /// @dev Keccak sibling ignores `level`. Poseidon2 override binds domain + level.
    function _hashPairAt(uint256, uint256 left, uint256 right) internal view virtual returns (uint256) {
        return _hashPair(left, right);
    }

    function _recover(bytes32 digest, bytes memory signature) internal pure returns (address signer) {
        require(signature.length == 65, "ENCODING_INVALID");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
        if (v < 27) {
            v += 27;
        }
        signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "UNAUTHORIZED");
    }
}
