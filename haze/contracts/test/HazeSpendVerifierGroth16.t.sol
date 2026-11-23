// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ApplicationRegistry} from "../src/ApplicationRegistry.sol";
import {HazeAccess} from "../src/HazeAccess.sol";
import {IHazeGroth16Verifier} from "../src/HazeGroth16Verifier.sol";
import {HazePool} from "../src/HazePool.sol";
import {HazePoolPoseidon} from "../src/HazePoolPoseidon.sol";
import {HazeProtocolVectors} from "../src/HazeProtocolVectors.sol";
import {HazeSpendVerifierGroth16} from "../src/HazeSpendVerifierGroth16.sol";
import {MockUsdc} from "../src/mocks/MockUsdc.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";

/// @dev Configurable pairing backend. Returns `result`; never inspects the proof.
contract MockGroth16Backend is IHazeGroth16Verifier {
    bool public constant NOT_FOR_PRODUCTION = true;
    bool public result = true;

    function setResult(bool result_) external {
        result = result_;
    }

    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[29] calldata
    ) external view returns (bool) {
        return result;
    }
}

contract HazeSpendVerifierGroth16Test is Test {
    HazeSpendVerifierGroth16 internal verifier;
    MockGroth16Backend internal backend;

    function setUp() public {
        backend = new MockGroth16Backend();
        verifier = new HazeSpendVerifierGroth16(backend);
    }

    function _inputs() internal view returns (uint256[29] memory inputs) {
        inputs[0] = uint256(verifier.PROTOCOL_VERSION_TAG());
        inputs[1] = 43113;
        inputs[16] = 1;
        inputs[17] = 1_000_000;
    }

    function _proof() internal pure returns (bytes memory) {
        uint256[2] memory a = [uint256(1), 2];
        uint256[2][2] memory b = [[uint256(3), 4], [uint256(5), 6]];
        uint256[2] memory c = [uint256(7), 8];
        return abi.encode(a, b, c);
    }

    function testPinsConstantsAndBackend() public view {
        assertTrue(verifier.NOT_FOR_PRODUCTION());
        assertEq(verifier.PUBLIC_INPUT_COUNT(), 29);
        assertEq(verifier.PROOF_LENGTH(), 256);
        assertEq(address(verifier.pairingBackend()), address(backend));
    }

    function testDigestProofRejectedWhenProductionFalse() public {
        uint256[29] memory inputs = _inputs();
        bytes memory digest = abi.encodePacked(keccak256(abi.encodePacked(inputs)));
        assertEq(digest.length, 32);
        bytes32 artifactHash = verifier.SPEND_ARTIFACT_HASH();
        vm.expectRevert(bytes("ENCODING_INVALID"));
        verifier.verify(inputs, digest, artifactHash, false);
    }

    function testDigestProofRejectedWhenProductionTrue() public {
        uint256[29] memory inputs = _inputs();
        bytes memory digest = abi.encodePacked(keccak256(abi.encodePacked(inputs)));
        bytes32 artifactHash = verifier.SPEND_ARTIFACT_HASH();
        vm.expectRevert(bytes("ENCODING_INVALID"));
        verifier.verify(inputs, digest, artifactHash, true);
    }

    function testFuzzNon256ByteProofRejected(bytes memory proof, bool production) public {
        vm.assume(proof.length != 256);
        uint256[29] memory inputs = _inputs();
        bytes32 artifactHash = verifier.SPEND_ARTIFACT_HASH();
        vm.expectRevert(bytes("ENCODING_INVALID"));
        verifier.verify(inputs, proof, artifactHash, production);
    }

    function testGroth16ProofDelegatesToPairingBackend() public {
        uint256[29] memory inputs = _inputs();
        uint256[2] memory a = [uint256(1), 2];
        uint256[2][2] memory b = [[uint256(3), 4], [uint256(5), 6]];
        uint256[2] memory c = [uint256(7), 8];
        bytes32 artifactHash = verifier.SPEND_ARTIFACT_HASH();
        vm.expectCall(
            address(backend), abi.encodeCall(IHazeGroth16Verifier.verifyProof, (a, b, c, inputs))
        );
        assertTrue(verifier.verify(inputs, abi.encode(a, b, c), artifactHash, false));
    }

    function testProductionFlagIgnored() public {
        uint256[29] memory inputs = _inputs();
        bytes32 artifactHash = verifier.SPEND_ARTIFACT_HASH();
        assertTrue(verifier.verify(inputs, _proof(), artifactHash, false));
        assertTrue(verifier.verify(inputs, _proof(), artifactHash, true));
        backend.setResult(false);
        assertFalse(verifier.verify(inputs, _proof(), artifactHash, false));
        assertFalse(verifier.verify(inputs, _proof(), artifactHash, true));
    }

    function testRejectsWrongArtifactFieldAndVersion() public {
        uint256[29] memory inputs = _inputs();
        bytes memory proof = _proof();
        bytes32 artifactHash = verifier.SPEND_ARTIFACT_HASH();

        vm.expectRevert(bytes("ARTIFACT"));
        verifier.verify(inputs, proof, bytes32(uint256(1)), false);

        inputs[5] = verifier.SNARK_SCALAR_FIELD();
        vm.expectRevert(bytes("FIELD_OUT_OF_RANGE"));
        verifier.verify(inputs, proof, artifactHash, false);

        inputs = _inputs();
        inputs[0] = 1;
        vm.expectRevert(bytes("VERSION_UNSUPPORTED"));
        verifier.verify(inputs, proof, artifactHash, false);
    }

    function testConstructorRejectsMissingBackend() public {
        vm.expectRevert(bytes("ENCODING_INVALID"));
        new HazeSpendVerifierGroth16(IHazeGroth16Verifier(address(0)));
        vm.expectRevert(bytes("ENCODING_INVALID"));
        new HazeSpendVerifierGroth16(IHazeGroth16Verifier(makeAddr("eoa")));
    }
}

/// @notice Fuji v2 wiring: Poseidon pool + Groth16-only verifier + approvedExit = address(0).
contract HazePoolV2WiringTest is Test {
    uint48 internal constant MIN_DELAY = 2 days;
    uint256 internal constant ROOT_HISTORY = 4;
    uint64 internal constant DEPOSIT_AMOUNT = 1_000_000;
    bytes32 internal constant APP_ID = bytes32(uint256(0xA11));
    bytes32 internal constant MEMBER_ROOT = bytes32(uint256(0x11));
    bytes32 internal constant BLOCK_ROOT = bytes32(uint256(0x44));
    bytes32 internal constant POOL_VERSION = bytes32(uint256(0xB002));

    HazeAccess internal access;
    ApplicationRegistry internal apps;
    PolicyRegistry internal policies;
    MockGroth16Backend internal backend;
    HazeSpendVerifierGroth16 internal verifier;
    MockUsdc internal usdc;
    HazePoolPoseidon internal pool;

    address internal governance;
    address internal user;
    uint256 internal gatekeeperPk;
    uint256 internal nonceSeed;

    function setUp() public {
        governance = makeAddr("governance");
        user = makeAddr("user");
        gatekeeperPk = 0xA11CE;
        vm.warp(1_700_000_000);

        access = new HazeAccess(governance, makeAddr("pause"), MIN_DELAY);
        apps = new ApplicationRegistry(access);
        policies = new PolicyRegistry(access);
        backend = new MockGroth16Backend();
        verifier = new HazeSpendVerifierGroth16(backend);
        usdc = new MockUsdc();
        pool = new HazePoolPoseidon(
            access,
            apps,
            policies,
            verifier,
            address(usdc),
            makeAddr("router"),
            address(0),
            POOL_VERSION,
            ROOT_HISTORY
        );

        vm.prank(governance);
        apps.scheduleRegister(
            ApplicationRegistry.RegisterParams({
                applicationId: APP_ID,
                admin: makeAddr("admin"),
                gatekeeperSigner: vm.addr(gatekeeperPk),
                policyAuthority: makeAddr("policyAuth"),
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

    function testApprovedExitIsZero() public view {
        assertEq(pool.approvedExit(), address(0));
        assertEq(address(pool.verifier()), address(verifier));
    }

    function testFuzzExitFromEmergencyUnreachable(address caller) public {
        usdc.mint(address(pool), 5_000_000);
        uint256 root = pool.currentRoot();
        vm.prank(caller);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        pool.exitFromEmergency(
            APP_ID, caller, root, 1, 0xE1, 5_000_000, caller, 0, bytes32(0), "", "", ""
        );
        assertEq(usdc.balanceOf(address(pool)), 5_000_000);
        assertFalse(pool.nullifierUsed(0xE1));
    }

    function testExitFromEmergencyRejectsZeroAddressCaller() public {
        usdc.mint(address(pool), 5_000_000);
        uint256 root = pool.currentRoot();
        vm.prank(address(0));
        vm.expectRevert(bytes("UNAUTHORIZED"));
        pool.exitFromEmergency(
            APP_ID, user, root, 1, 0xE1, 5_000_000, user, 0, bytes32(0), "", "", ""
        );
        assertEq(usdc.balanceOf(address(pool)), 5_000_000);
    }

    function testDepositWithDigestProofReverts() public {
        HazePool.TransactArgs memory args = _depositArgs(0x1234);
        args.proof = abi.encodePacked(keccak256(abi.encodePacked(pool.publicInputs(args.intent))));
        vm.prank(user);
        vm.expectRevert(bytes("ENCODING_INVALID"));
        pool.deposit(args);
        assertEq(usdc.balanceOf(address(pool)), 0);
    }

    function testDepositWithGroth16ProofUsesBackend() public {
        HazePool.TransactArgs memory args = _depositArgs(0x1234);
        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        args.proof = abi.encode(a, b, c);

        backend.setResult(false);
        vm.prank(user);
        vm.expectRevert(bytes("ENCODING_INVALID"));
        pool.deposit(args);

        backend.setResult(true);
        vm.prank(user);
        pool.deposit(args);
        assertEq(usdc.balanceOf(address(pool)), DEPOSIT_AMOUNT);
        assertTrue(pool.commitmentExists(0x1234));
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
    }
}
