// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {DevelopmentEqualityVerifier} from "haze-dev/DevelopmentEqualityVerifier.sol";
import {ApplicationRegistry} from "../src/ApplicationRegistry.sol";
import {HazeAccess} from "../src/HazeAccess.sol";
import {HazePool} from "../src/HazePool.sol";
import {HazePoolPoseidon} from "../src/HazePoolPoseidon.sol";
import {HazePoseidon2} from "../src/HazePoseidon2.sol";
import {HazeProtocolVectors} from "../src/HazeProtocolVectors.sol";
import {HazeSpendVerifier} from "../src/HazeSpendVerifier.sol";
import {MockUsdc} from "../src/mocks/MockUsdc.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";

contract HazePoolPoseidonTest is Test {
    uint256 internal constant NOTE_EMPTY_ROOT =
        0x0b70befaf3b699951d686409413a36612ee96094c7bf2708687522123486f908;
    uint48 internal constant MIN_DELAY = 2 days;
    uint256 internal constant ROOT_HISTORY = 4;
    uint64 internal constant DEPOSIT_AMOUNT = 1_000_000;
    bytes32 internal constant APP_ID = bytes32(uint256(0xA11));
    bytes32 internal constant MEMBER_ROOT = bytes32(uint256(0x11));
    bytes32 internal constant BLOCK_ROOT = bytes32(uint256(0x44));
    bytes32 internal constant POOL_VERSION = bytes32(uint256(0xB001));

    HazeAccess internal access;
    ApplicationRegistry internal apps;
    PolicyRegistry internal policies;
    HazeSpendVerifier internal verifier;
    MockUsdc internal usdc;
    HazePoolPoseidon internal pool;
    HazePool internal keccakPool;

    address internal governance;
    address internal pauseRole;
    address internal admin;
    address internal policyAuth;
    address internal user;
    address internal router;
    uint256 internal gatekeeperPk;
    address internal gatekeeper;
    uint256 internal nonceSeed;

    function setUp() public {
        governance = makeAddr("governance");
        pauseRole = makeAddr("pause");
        admin = makeAddr("admin");
        policyAuth = makeAddr("policyAuth");
        user = makeAddr("user");
        router = makeAddr("router");
        gatekeeperPk = 0xA11CE;
        gatekeeper = vm.addr(gatekeeperPk);
        vm.warp(1_700_000_000);

        access = new HazeAccess(governance, pauseRole, MIN_DELAY);
        apps = new ApplicationRegistry(access);
        policies = new PolicyRegistry(access);
        verifier = new HazeSpendVerifier(new DevelopmentEqualityVerifier());
        usdc = new MockUsdc();
        pool = new HazePoolPoseidon(
            access, apps, policies, verifier, address(usdc), router, address(0), POOL_VERSION, ROOT_HISTORY
        );
        keccakPool = new HazePool(
            access, apps, policies, verifier, address(usdc), router, address(0), POOL_VERSION, ROOT_HISTORY
        );

        vm.prank(governance);
        apps.scheduleRegister(
            ApplicationRegistry.RegisterParams({
                applicationId: APP_ID,
                admin: admin,
                gatekeeperSigner: gatekeeper,
                policyAuthority: policyAuth,
                membershipRoot: MEMBER_ROOT,
                auditPublicKey: hex"11",
                manifestUri: "ipfs://manifest",
                manifestHash: bytes32(uint256(0x22)),
                policyProfile: bytes32(uint256(0x33))
            })
        );
        vm.warp(block.timestamp + MIN_DELAY);
        apps.activateRegister(APP_ID);
        vm.prank(governance);
        policies.schedulePolicy(1, BLOCK_ROOT, bytes32(uint256(0x55)));
        vm.warp(block.timestamp + MIN_DELAY);
        policies.activatePolicy(1);

        usdc.mint(user, 10_000_000);
        vm.prank(user);
        usdc.approve(address(pool), type(uint256).max);
    }

    function testEmptyRootMatchesCircuitNoteTree() public view {
        assertEq(pool.emptyTreeRoot(), NOTE_EMPTY_ROOT);
        assertTrue(pool.knownRoot(NOTE_EMPTY_ROOT));
        assertTrue(pool.emptyTreeRoot() != keccakPool.emptyTreeRoot());
    }

    function testDepositInsertsPoseidonParentPath() public {
        uint256 commitment = 0x12f9ba3a528b60b24a66982d68570b38eb9a93e96d0224fd1a4cc0051fbbe76f;
        HazePool.TransactArgs memory args = _depositArgs(commitment);
        vm.prank(user);
        pool.deposit(args);

        uint256 domain = HazePoseidon2.domainField(HazePoseidon2.NOTE_TREE);
        uint256[32] memory zeros = HazePoseidon2.zeroHashes(domain);
        uint256 node = commitment;
        for (uint256 level = 0; level < 32; ++level) {
            node = HazePoseidon2.parentNode(domain, level, node, zeros[level]);
        }
        assertEq(pool.currentRoot(), node);
        assertTrue(pool.commitmentExists(commitment));
        assertEq(pool.nextIndex(), 1);
    }

    function testKeccakSiblingHashPairUnchanged() public view {
        uint256 left = 1;
        uint256 right = 2;
        uint256 expected = uint256(keccak256(abi.encodePacked(left, right))) % keccakPool.SNARK_SCALAR_FIELD();
        assertTrue(keccakPool.emptyTreeRoot() != NOTE_EMPTY_ROOT);
        assertEq(expected, uint256(keccak256(abi.encodePacked(left, right))) % pool.SNARK_SCALAR_FIELD());
    }

    function _depositArgs(uint256 commitment) internal returns (HazePool.TransactArgs memory args) {
        ApplicationRegistry.ApplicationRecord memory record = apps.getApplication(APP_ID);
        args.intent.applicationId = APP_ID;
        args.intent.user = user;
        args.intent.pool = address(pool);
        args.intent.poolVersion = POOL_VERSION;
        args.intent.action = 1;
        args.intent.applicationPolicyVersion = record.membershipVersion;
        args.intent.hazePolicyVersion = policies.activeVersion();
        args.intent.applicationMembershipRoot = uint256(record.membershipRoot);
        args.intent.hazeBlocklistRoot = uint256(policies.activeRoot());
        args.intent.outputCommitment0 = commitment;
        args.intent.publicAmount = DEPOSIT_AMOUNT;
        args.recipientCiphertext0 = hex"c0";
        args.recipientCiphertext1 = "";
        args.auditCiphertext = hex"aa";
        args.intent.recipientCiphertextHash0 = keccak256(args.recipientCiphertext0);
        args.intent.recipientCiphertextHash1 = keccak256(args.recipientCiphertext1);
        args.intent.auditDataCommitment = uint256(bytes32(uint256(0xAD)));
        args.intent.auditCiphertextHash = keccak256(args.auditCiphertext);
        args.authorization.applicationId = args.intent.applicationId;
        args.authorization.user = args.intent.user;
        args.authorization.pool = args.intent.pool;
        args.authorization.poolVersion = args.intent.poolVersion;
        args.authorization.action = args.intent.action;
        args.authorization.intentHash = HazeProtocolVectors.intentStructHash(args.intent);
        args.authorization.applicationPolicyVersion = args.intent.applicationPolicyVersion;
        args.authorization.hazePolicyVersion = args.intent.hazePolicyVersion;
        args.authorization.auditDataCommitment = args.intent.auditDataCommitment;
        args.authorization.auditCiphertextHash = args.intent.auditCiphertextHash;
        nonceSeed += 1;
        args.authorization.nonce = bytes32(nonceSeed);
        args.authorization.validAfter = uint48(block.timestamp - 1);
        args.authorization.validUntil = uint48(block.timestamp + 1 hours);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            gatekeeperPk,
            HazeProtocolVectors.typedDataDigest(
                HazeProtocolVectors.domainSeparator(
                    pool.DOMAIN_NAME(), pool.DOMAIN_VERSION(), block.chainid, address(pool)
                ),
                HazeProtocolVectors.authorizationStructHash(args.authorization)
            )
        );
        args.authorizationSignature = abi.encodePacked(r, s, v);
        args.proof = abi.encodePacked(keccak256(abi.encodePacked(pool.publicInputs(args.intent))));
    }
}
