// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {DevelopmentEqualityVerifier} from "haze-dev/DevelopmentEqualityVerifier.sol";
import {ApplicationRegistry} from "../src/ApplicationRegistry.sol";
import {HazeAccess} from "../src/HazeAccess.sol";
import {HazePool} from "../src/HazePool.sol";
import {HazeProtocolVectors} from "../src/HazeProtocolVectors.sol";
import {HazeSpendVerifier} from "../src/HazeSpendVerifier.sol";
import {MockUsdc} from "../src/mocks/MockUsdc.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";

contract HazePoolTest is Test {
    uint48 internal constant MIN_DELAY = 2 days;
    uint256 internal constant ROOT_HISTORY = 4;
    uint64 internal constant DEPOSIT_AMOUNT = 1_000_000;
    bytes32 internal constant APP_ID = bytes32(uint256(0xA11));
    bytes32 internal constant APP_B = bytes32(uint256(0xB0B));
    bytes32 internal constant MEMBER_ROOT = bytes32(uint256(0x11));
    bytes32 internal constant BLOCK_ROOT = bytes32(uint256(0x44));
    bytes32 internal constant POOL_VERSION = bytes32(uint256(0xB001));
    bytes32 internal constant SPEND_ARTIFACT_HASH =
        0xac2082ecb2129c571d2ddeb170f261a0da074491773102fa4f1544e97eb19281;
    bytes32 internal constant PROTOCOL_VERSION_TAG =
        0x2afe8a5679df289719eae23ad89b300434b9dfbb8194dad0b50dee97f91a3868;

    HazeAccess internal access;
    ApplicationRegistry internal apps;
    PolicyRegistry internal policies;
    HazeSpendVerifier internal verifier;
    MockUsdc internal usdc;
    HazePool internal pool;

    address internal governance;
    address internal pauseRole;
    address internal admin;
    address internal policyAuth;
    address internal user;
    address internal recipient;
    address internal router;
    address internal stranger;

    uint256 internal gatekeeperPk;
    address internal gatekeeper;
    uint256 internal nonceSeed;

    function setUp() public {
        governance = makeAddr("governance");
        pauseRole = makeAddr("pause");
        admin = makeAddr("admin");
        policyAuth = makeAddr("policyAuth");
        user = makeAddr("user");
        recipient = makeAddr("recipient");
        router = makeAddr("router");
        stranger = makeAddr("stranger");
        gatekeeperPk = 0xA11CE;
        gatekeeper = vm.addr(gatekeeperPk);
        vm.warp(1_700_000_000);

        access = new HazeAccess(governance, pauseRole, MIN_DELAY);
        apps = new ApplicationRegistry(access);
        policies = new PolicyRegistry(access);
        verifier = new HazeSpendVerifier(new DevelopmentEqualityVerifier());
        usdc = new MockUsdc();
        pool = new HazePool(
            access, apps, policies, verifier, address(usdc), router, address(0), POOL_VERSION, ROOT_HISTORY
        );

        _registerAndActivateApp(APP_ID);
        vm.prank(governance);
        policies.schedulePolicy(1, BLOCK_ROOT, bytes32(uint256(0x55)));
        vm.warp(block.timestamp + MIN_DELAY);
        policies.activatePolicy(1);

        usdc.mint(user, 10_000_000);
        usdc.mint(router, 10_000_000);
        vm.prank(user);
        usdc.approve(address(pool), type(uint256).max);
        vm.prank(router);
        usdc.approve(address(pool), type(uint256).max);
    }

    function testPinsImmutablePoolAndHasNoProxyPath() public {
        assertTrue(pool.NOT_FOR_PRODUCTION());
        assertEq(pool.PROTOCOL_VERSION_TAG(), PROTOCOL_VERSION_TAG);
        assertEq(pool.SPEND_ARTIFACT_HASH(), SPEND_ARTIFACT_HASH);
        assertEq(pool.poolVersion(), POOL_VERSION);
        assertEq(pool.approvedRouter(), router);
        assertEq(address(pool.usdc()), address(usdc));
        assertEq(pool.rootHistorySize(), ROOT_HISTORY);
        assertTrue(pool.knownRoot(pool.emptyTreeRoot()));
        (bool okUpgrade,) = address(pool).call(abi.encodeWithSignature("upgradeTo(address)", address(1)));
        assertFalse(okUpgrade);
        (bool okInit,) = address(pool).call(abi.encodeWithSignature("initialize(address)", governance));
        assertFalse(okInit);
        (bool okOwner,) = address(pool).call(abi.encodeWithSignature("owner()"));
        assertFalse(okOwner);
    }

    function testDepositPullsExactUsdcBeforeInsertingBoundCommitment() public {
        HazePool.TransactArgs memory args = _depositArgs(APP_ID, user, DEPOSIT_AMOUNT, bytes32(uint256(0xC1)), bytes32(0));
        uint256 userBefore = usdc.balanceOf(user);
        uint256 poolBefore = usdc.balanceOf(address(pool));

        vm.expectEmit(true, true, true, true, address(pool));
        emit HazePool.PrivateTransaction(
            APP_ID,
            1,
            user,
            1,
            1,
            0,
            0,
            0,
            args.intent.outputCommitment0,
            0,
            DEPOSIT_AMOUNT,
            address(0),
            args.intent.recipientCiphertextHash0,
            args.intent.recipientCiphertextHash1,
            args.intent.auditDataCommitment,
            args.intent.auditCiphertextHash,
            args.recipientCiphertext0,
            args.recipientCiphertext1,
            args.auditCiphertext
        );
        vm.prank(user);
        pool.deposit(args);

        assertEq(usdc.balanceOf(user), userBefore - DEPOSIT_AMOUNT);
        assertEq(usdc.balanceOf(address(pool)), poolBefore + DEPOSIT_AMOUNT);
        assertTrue(pool.commitmentExists(args.intent.outputCommitment0));
        assertFalse(pool.commitmentExists(0));
        assertTrue(pool.knownRoot(pool.currentRoot()));
        assertTrue(pool.nonceUsed(APP_ID, gatekeeper, args.authorization.nonce));
    }

    function testRejectsUnregisteredPendingSuspendedAndRetiredApplications() public {
        HazePool.TransactArgs memory unknown = _depositArgs(bytes32(uint256(0xDEAD)), user, DEPOSIT_AMOUNT, bytes32(uint256(2)), bytes32(0));
        vm.prank(user);
        vm.expectRevert(bytes("STATUS_INVALID"));
        pool.deposit(unknown);

        bytes32 pendingId = bytes32(uint256(0x0E11));
        vm.prank(governance);
        apps.scheduleRegister(_registerArgs(pendingId));
        HazePool.TransactArgs memory pending = _depositArgs(pendingId, user, DEPOSIT_AMOUNT, bytes32(uint256(3)), bytes32(0));
        vm.prank(user);
        vm.expectRevert(bytes("STATUS_INVALID"));
        pool.deposit(pending);

        vm.prank(governance);
        apps.scheduleSuspend(APP_ID);
        vm.warp(block.timestamp + MIN_DELAY);
        apps.activateSuspend(APP_ID);
        HazePool.TransactArgs memory suspended = _depositArgs(APP_ID, user, DEPOSIT_AMOUNT, bytes32(uint256(4)), bytes32(0));
        vm.prank(user);
        vm.expectRevert(bytes("STATUS_INVALID"));
        pool.deposit(suspended);

        vm.prank(governance);
        apps.scheduleRetire(APP_ID);
        vm.warp(block.timestamp + MIN_DELAY);
        apps.activateRetire(APP_ID);
        HazePool.TransactArgs memory retired = _depositArgs(APP_ID, user, DEPOSIT_AMOUNT, bytes32(uint256(5)), bytes32(0));
        vm.prank(user);
        vm.expectRevert(bytes("STATUS_INVALID"));
        pool.deposit(retired);
    }

    function testRejectsMalformedWrongDomainExpiredAndWrongSignerAuthorizations() public {
        HazePool.TransactArgs memory missing = _depositArgs(APP_ID, user, DEPOSIT_AMOUNT, bytes32(uint256(6)), bytes32(0));
        missing.authorizationSignature = hex"";
        vm.prank(user);
        vm.expectRevert(bytes("ENCODING_INVALID"));
        pool.deposit(missing);

        HazePool.TransactArgs memory malformed = _depositArgs(APP_ID, user, DEPOSIT_AMOUNT, bytes32(uint256(7)), bytes32(0));
        malformed.authorizationSignature = hex"11";
        vm.prank(user);
        vm.expectRevert(bytes("ENCODING_INVALID"));
        pool.deposit(malformed);

        HazePool.TransactArgs memory wrongDomain = _depositArgs(APP_ID, user, DEPOSIT_AMOUNT, bytes32(uint256(8)), bytes32(0));
        wrongDomain.authorizationSignature = _signAuthorization(wrongDomain.authorization, "Wrong Domain", "1");
        vm.prank(user);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        pool.deposit(wrongDomain);

        HazePool.TransactArgs memory expired = _depositArgs(APP_ID, user, DEPOSIT_AMOUNT, bytes32(uint256(9)), bytes32(0));
        expired.authorization.validUntil = uint48(block.timestamp - 1);
        expired.authorizationSignature = _signAuthorization(expired.authorization, pool.DOMAIN_NAME(), pool.DOMAIN_VERSION());
        vm.prank(user);
        vm.expectRevert(bytes("AUTH_WINDOW"));
        pool.deposit(expired);

        HazePool.TransactArgs memory early = _depositArgs(APP_ID, user, DEPOSIT_AMOUNT, bytes32(uint256(10)), bytes32(0));
        early.authorization.validAfter = uint48(block.timestamp + 10);
        early.authorizationSignature = _signAuthorization(early.authorization, pool.DOMAIN_NAME(), pool.DOMAIN_VERSION());
        vm.prank(user);
        vm.expectRevert(bytes("AUTH_WINDOW"));
        pool.deposit(early);

        HazePool.TransactArgs memory wrongSigner = _depositArgs(APP_ID, user, DEPOSIT_AMOUNT, bytes32(uint256(11)), bytes32(0));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xB0B, _authDigest(wrongSigner.authorization, pool.DOMAIN_NAME(), pool.DOMAIN_VERSION()));
        wrongSigner.authorizationSignature = abi.encodePacked(r, s, v);
        vm.prank(user);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        pool.deposit(wrongSigner);
    }

    function testConsumesNonceOnceAndRejectsReplay() public {
        HazePool.TransactArgs memory args = _depositArgs(APP_ID, user, DEPOSIT_AMOUNT, bytes32(uint256(0xC2)), bytes32(0));
        vm.prank(user);
        pool.deposit(args);
        vm.prank(user);
        vm.expectRevert(bytes("NONCE_USED"));
        pool.deposit(args);
    }

    function testInvalidProofDoesNotConsumeNonceOrInsertCommitment() public {
        HazePool.TransactArgs memory args = _depositArgs(APP_ID, user, DEPOSIT_AMOUNT, bytes32(uint256(0xC3)), bytes32(0));
        bytes32 nonce = args.authorization.nonce;
        args.proof = abi.encodePacked(bytes32(uint256(1)));
        vm.prank(user);
        vm.expectRevert(bytes("ENCODING_INVALID"));
        pool.deposit(args);
        assertFalse(pool.nonceUsed(APP_ID, gatekeeper, nonce));
        assertFalse(pool.commitmentExists(uint256(bytes32(uint256(0xC3)))));

        args = _depositArgs(APP_ID, user, DEPOSIT_AMOUNT, bytes32(uint256(0xC3)), bytes32(0));
        args.authorization.nonce = nonce;
        args.authorization.intentHash = HazeProtocolVectors.intentStructHash(args.intent);
        args.authorizationSignature = _signAuthorization(args.authorization, pool.DOMAIN_NAME(), pool.DOMAIN_VERSION());
        args.proof = _developmentProof(args);
        vm.prank(user);
        pool.deposit(args);
        assertTrue(pool.nonceUsed(APP_ID, gatekeeper, nonce));
    }

    function testDirectCallerMustBeAuthorizedUser() public {
        HazePool.TransactArgs memory args = _depositArgs(APP_ID, user, DEPOSIT_AMOUNT, bytes32(uint256(0xC4)), bytes32(0));
        vm.prank(stranger);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        pool.deposit(args);
        vm.prank(router);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        pool.deposit(args);
    }

    function testDepositFromRouterBindsOriginalPayerAndRejectsGenericForwarding() public {
        HazePool.TransactArgs memory args = _swapArgs(user, DEPOSIT_AMOUNT, bytes32(uint256(0xC5)));
        vm.prank(stranger);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        pool.depositFromRouter(user, args);

        vm.prank(user);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        pool.depositFromRouter(user, args);

        vm.prank(router);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        pool.depositFromRouter(stranger, args);

        uint256 routerBefore = usdc.balanceOf(router);
        uint256 poolBefore = usdc.balanceOf(address(pool));
        vm.prank(router);
        pool.depositFromRouter(user, args);
        assertEq(usdc.balanceOf(router), routerBefore - DEPOSIT_AMOUNT);
        assertEq(usdc.balanceOf(address(pool)), poolBefore + DEPOSIT_AMOUNT);
        assertEq(usdc.balanceOf(user), 10_000_000);
    }

    function testAcceptsHistoricalRootsAndRejectsUnknownOrExpiredRoots() public {
        _depositAs(user, _depositArgs(APP_ID, user, DEPOSIT_AMOUNT, bytes32(uint256(0xD1)), bytes32(0)));
        uint256 firstRoot = pool.currentRoot();
        for (uint256 i = 1; i < ROOT_HISTORY; ++i) {
            _depositAs(user, _depositArgs(APP_ID, user, 1, bytes32(uint256(0xE0 + i)), bytes32(0)));
        }
        assertFalse(pool.knownRoot(pool.emptyTreeRoot()));
        HazePool.TransactArgs memory unknown = _transferArgs(user, uint256(bytes32(uint256(0xDEAD))), bytes32(uint256(0xF1)), bytes32(uint256(0xF2)));
        vm.prank(user);
        vm.expectRevert(bytes("ROOT_UNKNOWN"));
        pool.transact(unknown);

        HazePool.TransactArgs memory historical = _transferArgs(user, firstRoot, bytes32(uint256(0xF3)), bytes32(uint256(0xF4)));
        vm.prank(user);
        pool.transact(historical);
    }

    function testAcceptsOnlyActivePolicyVersionsAndRootsWithoutGrace() public {
        HazePool.TransactArgs memory stale = _depositArgs(APP_ID, user, DEPOSIT_AMOUNT, bytes32(uint256(0xC6)), bytes32(0));
        vm.prank(governance);
        policies.schedulePolicy(2, bytes32(uint256(0xABC)), bytes32(uint256(0xDEF)));
        vm.warp(block.timestamp + MIN_DELAY);
        policies.activatePolicy(2);
        vm.prank(user);
        vm.expectRevert(bytes("POLICY_INVALID"));
        pool.deposit(stale);

        HazePool.TransactArgs memory live = _depositArgs(APP_ID, user, DEPOSIT_AMOUNT, bytes32(uint256(0xC7)), bytes32(0));
        live.intent.hazePolicyVersion = 2;
        live.intent.hazeBlocklistRoot = uint256(bytes32(uint256(0xABC)));
        _finalize(live);
        vm.prank(user);
        pool.deposit(live);
    }

    function testRejectsStaleApplicationMembershipRoot() public {
        HazePool.TransactArgs memory stale = _depositArgs(APP_ID, user, DEPOSIT_AMOUNT, bytes32(uint256(0xC8)), bytes32(0));
        vm.prank(policyAuth);
        apps.updateMembershipRoot(APP_ID, bytes32(uint256(0x99)));
        vm.prank(user);
        vm.expectRevert(bytes("POLICY_INVALID"));
        pool.deposit(stale);
    }

    function testTransferPreservesUsdcAndRejectsReusedNullifier() public {
        _depositAs(user, _depositArgs(APP_ID, user, DEPOSIT_AMOUNT, bytes32(uint256(0xC9)), bytes32(0)));
        uint256 root = pool.currentRoot();
        uint256 poolBal = usdc.balanceOf(address(pool));
        HazePool.TransactArgs memory send = _transferArgs(user, root, bytes32(uint256(0xA1)), bytes32(uint256(0xA2)));
        vm.prank(user);
        pool.transact(send);
        assertEq(usdc.balanceOf(address(pool)), poolBal);
        assertTrue(pool.nullifierUsed(uint256(bytes32(uint256(0xA1)))));

        HazePool.TransactArgs memory replay = _transferArgs(user, pool.currentRoot(), bytes32(uint256(0xA1)), bytes32(uint256(0xA3)));
        vm.prank(user);
        vm.expectRevert(bytes("NULLIFIER_USED"));
        pool.transact(replay);
    }

    function testWithdrawSendsExactUsdcToPublicRecipient() public {
        _depositAs(user, _depositArgs(APP_ID, user, DEPOSIT_AMOUNT, bytes32(uint256(0xCA)), bytes32(0)));
        uint256 root = pool.currentRoot();
        uint256 recipientBefore = usdc.balanceOf(recipient);
        HazePool.TransactArgs memory wd = _withdrawArgs(user, root, DEPOSIT_AMOUNT, recipient, bytes32(uint256(0xA4)));
        vm.prank(user);
        pool.transact(wd);
        assertEq(usdc.balanceOf(recipient), recipientBefore + DEPOSIT_AMOUNT);
        assertEq(usdc.balanceOf(address(pool)), 0);
    }

    function testRejectsDuplicateCommitmentsAndBothZeroOutputs() public {
        _depositAs(user, _depositArgs(APP_ID, user, DEPOSIT_AMOUNT, bytes32(uint256(0xCB)), bytes32(0)));
        HazePool.TransactArgs memory dup = _depositArgs(APP_ID, user, DEPOSIT_AMOUNT, bytes32(uint256(0xCB)), bytes32(0));
        vm.prank(user);
        vm.expectRevert(bytes("COMMITMENT_DUPLICATE"));
        pool.deposit(dup);

        HazePool.TransactArgs memory empty = _depositArgs(APP_ID, user, DEPOSIT_AMOUNT, bytes32(0), bytes32(0));
        vm.prank(user);
        vm.expectRevert(bytes("ENCODING_INVALID"));
        pool.deposit(empty);
    }

    function testBindsCiphertextHashesAndRejectsAlteredPayloads() public {
        HazePool.TransactArgs memory args = _depositArgs(APP_ID, user, DEPOSIT_AMOUNT, bytes32(uint256(0xCC)), bytes32(0));
        args.recipientCiphertext0 = hex"ffff";
        vm.prank(user);
        vm.expectRevert(bytes("ENCODING_INVALID"));
        pool.deposit(args);

        args = _depositArgs(APP_ID, user, DEPOSIT_AMOUNT, bytes32(uint256(0xCC)), bytes32(0));
        args.auditCiphertext = hex"eeee";
        vm.prank(user);
        vm.expectRevert(bytes("ENCODING_INVALID"));
        pool.deposit(args);
    }

    function testAllowsZeroCiphertextHashWhenUnusedPayloadEmpty() public {
        HazePool.TransactArgs memory args =
            _depositArgs(APP_ID, user, DEPOSIT_AMOUNT, bytes32(uint256(0xCE)), bytes32(0));
        args.recipientCiphertext1 = "";
        args.intent.recipientCiphertextHash1 = 0;
        _finalize(args);
        vm.prank(user);
        pool.deposit(args);
        assertTrue(pool.commitmentExists(uint256(bytes32(uint256(0xCE)))));
    }

    function testRejectsZeroCiphertextHashWhenPayloadPresent() public {
        HazePool.TransactArgs memory args =
            _depositArgs(APP_ID, user, DEPOSIT_AMOUNT, bytes32(uint256(0xCF)), bytes32(0));
        args.recipientCiphertext1 = hex"01";
        args.intent.recipientCiphertextHash1 = 0;
        _finalize(args);
        vm.prank(user);
        vm.expectRevert(bytes("ENCODING_INVALID"));
        pool.deposit(args);
    }

    function testRejectsEmergencyExitAndSwapOnDirectPaths() public {
        HazePool.TransactArgs memory exitTx = _depositArgs(APP_ID, user, DEPOSIT_AMOUNT, bytes32(uint256(0xCD)), bytes32(0));
        exitTx.intent.action = 5;
        _finalize(exitTx);
        vm.prank(user);
        vm.expectRevert(bytes("ENCODING_INVALID"));
        pool.deposit(exitTx);
        vm.prank(user);
        vm.expectRevert(bytes("ENCODING_INVALID"));
        pool.transact(exitTx);

        HazePool.TransactArgs memory swap = _swapArgs(user, DEPOSIT_AMOUNT, bytes32(uint256(0xCE)));
        vm.prank(user);
        vm.expectRevert(bytes("ENCODING_INVALID"));
        pool.deposit(swap);
    }

    function testPauseBlocksPoolActions() public {
        HazePool.TransactArgs memory args = _depositArgs(APP_ID, user, DEPOSIT_AMOUNT, bytes32(uint256(0xCF)), bytes32(0));
        vm.prank(pauseRole);
        access.pause();
        vm.prank(user);
        vm.expectRevert(bytes("PAUSED"));
        pool.deposit(args);
        HazePool.TransactArgs memory transferArgs =
            _transferArgs(user, pool.emptyTreeRoot(), bytes32(uint256(1)), bytes32(uint256(2)));
        vm.prank(user);
        vm.expectRevert(bytes("PAUSED"));
        pool.transact(transferArgs);
        HazePool.TransactArgs memory routed = _swapArgs(user, DEPOSIT_AMOUNT, bytes32(uint256(0xD0)));
        vm.prank(router);
        vm.expectRevert(bytes("PAUSED"));
        pool.depositFromRouter(user, routed);
    }

    function testFuzzDirectCallerMustMatchUser(address caller) public {
        vm.assume(caller != user);
        HazePool.TransactArgs memory args = _depositArgs(APP_ID, user, DEPOSIT_AMOUNT, bytes32(uint256(0xD2)), bytes32(0));
        vm.prank(caller);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        pool.deposit(args);
    }

    function testFuzzUnknownRootIsRejected(uint256 root) public {
        vm.assume(!pool.knownRoot(root));
        HazePool.TransactArgs memory args = _transferArgs(user, root, bytes32(uint256(0xAA)), bytes32(uint256(0xBB)));
        vm.prank(user);
        vm.expectRevert(bytes("ROOT_UNKNOWN"));
        pool.transact(args);
    }

    function testFuzzDepositConservesUsdc(uint64 amount) public {
        amount = uint64(bound(amount, 1, 1_000_000));
        uint256 userBefore = usdc.balanceOf(user);
        uint256 poolBefore = usdc.balanceOf(address(pool));
        _depositAs(user, _depositArgs(APP_ID, user, amount, bytes32(uint256(amount) | (1 << 200)), bytes32(0)));
        assertEq(usdc.balanceOf(user), userBefore - amount);
        assertEq(usdc.balanceOf(address(pool)), poolBefore + amount);
    }

    function testApplicationIsolationRejectsForeignAuthorization() public {
        _registerAndActivateApp(APP_B);
        HazePool.TransactArgs memory foreign = _depositArgs(APP_B, user, DEPOSIT_AMOUNT, bytes32(uint256(0xD3)), bytes32(0));
        vm.prank(user);
        pool.deposit(foreign);

        HazePool.TransactArgs memory mismatched = _depositArgs(APP_B, user, DEPOSIT_AMOUNT, bytes32(uint256(0xD4)), bytes32(0));
        mismatched.intent.applicationId = APP_ID;
        vm.prank(user);
        vm.expectRevert(bytes("ENCODING_INVALID"));
        pool.deposit(mismatched);
    }

    function _depositAs(address account, HazePool.TransactArgs memory args) internal {
        vm.prank(account);
        pool.deposit(args);
    }

    function _registerArgs(bytes32 applicationId) internal view returns (ApplicationRegistry.RegisterParams memory params) {
        params = ApplicationRegistry.RegisterParams({
            applicationId: applicationId,
            admin: admin,
            gatekeeperSigner: gatekeeper,
            policyAuthority: policyAuth,
            membershipRoot: MEMBER_ROOT,
            auditPublicKey: hex"11",
            manifestUri: "ipfs://manifest",
            manifestHash: bytes32(uint256(0x22)),
            policyProfile: bytes32(uint256(0x33))
        });
    }

    function _registerAndActivateApp(bytes32 applicationId) internal {
        vm.prank(governance);
        apps.scheduleRegister(_registerArgs(applicationId));
        vm.warp(block.timestamp + MIN_DELAY);
        apps.activateRegister(applicationId);
    }

    function _nextNonce() internal returns (bytes32 nonce) {
        nonceSeed += 1;
        nonce = bytes32(nonceSeed);
    }

    function _baseIntent(bytes32 applicationId, address account, uint8 action)
        internal
        view
        returns (HazeProtocolVectors.IntentFields memory intent)
    {
        ApplicationRegistry.ApplicationRecord memory record = apps.getApplication(applicationId);
        intent.applicationId = applicationId;
        intent.user = account;
        intent.pool = address(pool);
        intent.poolVersion = POOL_VERSION;
        intent.action = action;
        intent.applicationPolicyVersion = record.membershipVersion;
        intent.hazePolicyVersion = policies.activeVersion();
        intent.applicationMembershipRoot = uint256(record.membershipRoot);
        intent.hazeBlocklistRoot = uint256(policies.activeRoot());
    }

    function _depositArgs(bytes32 applicationId, address account, uint64 amount, bytes32 cm0, bytes32 cm1)
        internal
        returns (HazePool.TransactArgs memory args)
    {
        args.intent = _baseIntent(applicationId, account, 1);
        args.intent.outputCommitment0 = uint256(cm0);
        args.intent.outputCommitment1 = uint256(cm1);
        args.intent.publicAmount = amount;
        args.recipientCiphertext0 = cm0 == bytes32(0) ? bytes("") : bytes(hex"c0");
        args.recipientCiphertext1 = cm1 == bytes32(0) ? bytes("") : bytes(hex"c1");
        args.auditCiphertext = hex"aa";
        args.intent.recipientCiphertextHash0 = keccak256(args.recipientCiphertext0);
        args.intent.recipientCiphertextHash1 = keccak256(args.recipientCiphertext1);
        args.intent.auditDataCommitment = uint256(bytes32(uint256(0xAD)));
        args.intent.auditCiphertextHash = keccak256(args.auditCiphertext);
        _finalize(args);
    }

    function _swapArgs(address account, uint64 amount, bytes32 cm0)
        internal
        returns (HazePool.TransactArgs memory args)
    {
        args = _depositArgs(APP_ID, account, amount, cm0, bytes32(0));
        args.intent.action = 4;
        args.intent.tokenIn = address(usdc);
        args.intent.amountIn = uint256(amount);
        args.intent.minUsdcOut = amount;
        args.intent.routeHash = keccak256("route");
        args.intent.deadline = uint48(block.timestamp + 60);
        _finalize(args);
    }

    function _transferArgs(address account, uint256 root, bytes32 nf0, bytes32 nf1)
        internal
        returns (HazePool.TransactArgs memory args)
    {
        args.intent = _baseIntent(APP_ID, account, 2);
        args.intent.noteTreeRoot = root;
        args.intent.inputNullifier0 = uint256(nf0);
        args.intent.inputNullifier1 = 0;
        args.intent.outputCommitment0 = uint256(nf1);
        args.intent.outputCommitment1 = 0;
        args.recipientCiphertext0 = hex"c0";
        args.recipientCiphertext1 = "";
        args.auditCiphertext = hex"aa";
        args.intent.recipientCiphertextHash0 = keccak256(args.recipientCiphertext0);
        args.intent.recipientCiphertextHash1 = keccak256(args.recipientCiphertext1);
        args.intent.auditDataCommitment = uint256(bytes32(uint256(0xAD)));
        args.intent.auditCiphertextHash = keccak256(args.auditCiphertext);
        _finalize(args);
    }

    function _withdrawArgs(address account, uint256 root, uint64 amount, address to, bytes32 nf0)
        internal
        returns (HazePool.TransactArgs memory args)
    {
        args.intent = _baseIntent(APP_ID, account, 3);
        args.intent.noteTreeRoot = root;
        args.intent.inputNullifier0 = uint256(nf0);
        args.intent.publicAmount = amount;
        args.intent.publicRecipient = to;
        args.recipientCiphertext0 = "";
        args.recipientCiphertext1 = "";
        args.auditCiphertext = hex"aa";
        args.intent.recipientCiphertextHash0 = keccak256(args.recipientCiphertext0);
        args.intent.recipientCiphertextHash1 = keccak256(args.recipientCiphertext1);
        args.intent.auditDataCommitment = uint256(bytes32(uint256(0xAD)));
        args.intent.auditCiphertextHash = keccak256(args.auditCiphertext);
        _finalize(args);
    }

    function _finalize(HazePool.TransactArgs memory args) internal {
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
        if (args.authorization.nonce == bytes32(0)) {
            args.authorization.nonce = _nextNonce();
        }
        args.authorization.validAfter = uint48(block.timestamp - 1);
        args.authorization.validUntil = uint48(block.timestamp + 1 hours);
        args.authorizationSignature = _signAuthorization(args.authorization, pool.DOMAIN_NAME(), pool.DOMAIN_VERSION());
        args.proof = _developmentProof(args);
    }

    function _developmentProof(HazePool.TransactArgs memory args) internal view returns (bytes memory) {
        return abi.encodePacked(keccak256(abi.encodePacked(pool.publicInputs(args.intent))));
    }

    function _signAuthorization(
        HazeProtocolVectors.AuthorizationFields memory auth,
        string memory name,
        string memory version
    ) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(gatekeeperPk, _authDigest(auth, name, version));
        return abi.encodePacked(r, s, v);
    }

    function _authDigest(
        HazeProtocolVectors.AuthorizationFields memory auth,
        string memory name,
        string memory version
    ) internal view returns (bytes32) {
        return HazeProtocolVectors.typedDataDigest(
            HazeProtocolVectors.domainSeparator(name, version, block.chainid, address(pool)),
            HazeProtocolVectors.authorizationStructHash(auth)
        );
    }
}
