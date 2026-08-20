// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {DevelopmentEqualityVerifier} from "haze-dev/DevelopmentEqualityVerifier.sol";
import {ApplicationRegistry} from "../src/ApplicationRegistry.sol";
import {EmergencyExit} from "../src/EmergencyExit.sol";
import {HazeAccess} from "../src/HazeAccess.sol";
import {HazePool} from "../src/HazePool.sol";
import {HazeProtocolVectors} from "../src/HazeProtocolVectors.sol";
import {HazeSpendVerifier} from "../src/HazeSpendVerifier.sol";
import {MockUsdc} from "../src/mocks/MockUsdc.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {VersionRegistry} from "../src/VersionRegistry.sol";

contract EmergencyExitTest is Test {
    uint48 internal constant MIN_DELAY = 2 days;
    uint256 internal constant ROOT_HISTORY = 4;
    uint64 internal constant DEPOSIT_AMOUNT = 1_000_000;
    uint256 internal constant COOLDOWN = 7 days;
    bytes32 internal constant APP_ID = bytes32(uint256(0xA11));
    bytes32 internal constant MEMBER_ROOT = bytes32(uint256(0x11));
    bytes32 internal constant BLOCK_ROOT = bytes32(uint256(0x44));
    bytes32 internal constant POOL_VERSION = bytes32(uint256(0xB001));
    bytes32 internal constant NEXT_VERSION = bytes32(uint256(0xB002));
    bytes32 internal constant FROZEN_REQUEST_ID =
        0xfc7450e6893c57123a3119a83330cfdd6243ed448260c3bca6a9ae484f5d4a63;
    bytes32 internal constant FROZEN_NULLIFIER =
        0x00695bdec935d3e0429c3a04acc43b60d6d736e31f5d0eb49b71ebda82a421ad;

    HazeAccess internal access;
    ApplicationRegistry internal apps;
    PolicyRegistry internal policies;
    VersionRegistry internal versions;
    HazeSpendVerifier internal verifier;
    MockUsdc internal usdc;
    HazePool internal pool;
    EmergencyExit internal exitContract;

    address internal governance;
    address internal pauseRole;
    address internal admin;
    address internal policyAuth;
    address internal user;
    address internal recipient;
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
        stranger = makeAddr("stranger");
        gatekeeperPk = 0xA11CE;
        gatekeeper = vm.addr(gatekeeperPk);
        vm.warp(1_700_000_000);

        access = new HazeAccess(governance, pauseRole, MIN_DELAY);
        apps = new ApplicationRegistry(access);
        policies = new PolicyRegistry(access);
        versions = new VersionRegistry(access);
        verifier = new HazeSpendVerifier(new DevelopmentEqualityVerifier());
        usdc = new MockUsdc();

        address predictedExit = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 1);
        pool = new HazePool(
            access,
            apps,
            policies,
            verifier,
            address(usdc),
            address(0),
            predictedExit,
            POOL_VERSION,
            ROOT_HISTORY
        );
        exitContract = new EmergencyExit(access, pool, versions, policies);
        assertEq(address(exitContract), predictedExit);
        assertEq(pool.approvedExit(), address(exitContract));

        _registerAndActivateApp(APP_ID);
        vm.prank(governance);
        policies.schedulePolicy(1, BLOCK_ROOT, bytes32(uint256(0x55)));
        vm.warp(vm.getBlockTimestamp() + MIN_DELAY);
        policies.activatePolicy(1);

        usdc.mint(user, 10_000_000);
        vm.prank(user);
        usdc.approve(address(pool), type(uint256).max);
    }

    function testPinsFrozenRequestIdAndHasNoProxyPath() public {
        assertTrue(exitContract.NOT_FOR_PRODUCTION());
        assertEq(exitContract.PUBLIC_INPUT_COUNT(), 20);
        assertEq(exitContract.COOLDOWN(), COOLDOWN);
        assertEq(
            exitContract.requestId(
                43113,
                address(0x1111111111111111111111111111111111111111),
                bytes32(uint256(0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)),
                bytes32(uint256(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)),
                uint256(FROZEN_NULLIFIER),
                address(0x2222222222222222222222222222222222222222),
                bytes32(uint256(0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc))
            ),
            FROZEN_REQUEST_ID
        );
        (bool okUpgrade,) = address(exitContract).call(abi.encodeWithSignature("upgradeTo(address)", address(1)));
        assertFalse(okUpgrade);
        (bool okInit,) = address(exitContract).call(abi.encodeWithSignature("initialize(address)", governance));
        assertFalse(okInit);
        (bool okOwner,) = address(exitContract).call(abi.encodeWithSignature("owner()"));
        assertFalse(okOwner);
    }

    function testAnyoneCanRegisterWithoutApplicationOutage() public {
        bytes32 id = _requestId(bytes32(uint256(0xE1)), recipient, bytes32(uint256(1)));
        vm.prank(stranger);
        exitContract.requestEmergencyExit(id);
        assertEq(uint256(exitContract.requestedAt(id)), vm.getBlockTimestamp());
        assertFalse(exitContract.requestUsed(id));
        assertFalse(pool.nullifierUsed(uint256(bytes32(uint256(0xE1)))));
    }

    function testDuplicateRequestReverts() public {
        bytes32 id = _requestId(bytes32(uint256(0xE2)), recipient, bytes32(uint256(2)));
        exitContract.requestEmergencyExit(id);
        vm.expectRevert(bytes("STATUS_INVALID"));
        exitContract.requestEmergencyExit(id);
    }

    function testEarlyExecuteLeavesNullifierUnused() public {
        _depositAs(user, _depositArgs(bytes32(uint256(0xC1))));
        bytes32 nf = bytes32(uint256(0xE3));
        bytes32 salt = bytes32(uint256(3));
        bytes32 id = _requestId(nf, recipient, salt);
        exitContract.requestEmergencyExit(id);

        EmergencyExit.ExecuteArgs memory args = _exitArgs(nf, DEPOSIT_AMOUNT, recipient, salt);
        uint256 early = vm.getBlockTimestamp() + COOLDOWN - 1;
        vm.warp(early);
        vm.expectRevert(bytes("AUTH_WINDOW"));
        exitContract.executeEmergencyExit(args);
        assertFalse(pool.nullifierUsed(uint256(nf)));
        assertFalse(exitContract.requestUsed(id));
        assertEq(usdc.balanceOf(recipient), 0);
    }

    function testExecuteAfterSevenDaysWithdrawsExactUsdc() public {
        _depositAs(user, _depositArgs(bytes32(uint256(0xC2))));
        bytes32 nf = bytes32(uint256(0xE4));
        bytes32 salt = bytes32(uint256(4));
        bytes32 id = _requestId(nf, recipient, salt);
        exitContract.requestEmergencyExit(id);
        vm.warp(vm.getBlockTimestamp() + COOLDOWN);

        uint256 poolBefore = usdc.balanceOf(address(pool));
        EmergencyExit.ExecuteArgs memory args = _exitArgs(nf, DEPOSIT_AMOUNT, recipient, salt);
        vm.expectEmit(true, true, true, true, address(pool));
        emit HazePool.PrivateTransaction(
            APP_ID,
            5,
            user,
            0,
            1,
            args.noteTreeRoot,
            uint256(nf),
            0,
            0,
            0,
            DEPOSIT_AMOUNT,
            recipient,
            keccak256(""),
            keccak256(""),
            args.auditDataCommitment,
            args.auditCiphertextHash,
            "",
            "",
            args.auditCiphertext
        );
        exitContract.executeEmergencyExit(args);

        assertEq(usdc.balanceOf(recipient), DEPOSIT_AMOUNT);
        assertEq(usdc.balanceOf(address(pool)), poolBefore - DEPOSIT_AMOUNT);
        assertTrue(pool.nullifierUsed(uint256(nf)));
        assertTrue(exitContract.requestUsed(id));
    }

    function testNormalWithdrawDuringCooldownThenExitFails() public {
        _depositAs(user, _depositArgs(bytes32(uint256(0xC3))));
        bytes32 nf = bytes32(uint256(0xA4));
        bytes32 salt = bytes32(uint256(5));
        bytes32 id = _requestId(nf, recipient, salt);
        exitContract.requestEmergencyExit(id);

        HazePool.TransactArgs memory wd =
            _withdrawArgs(user, pool.currentRoot(), DEPOSIT_AMOUNT, recipient, nf);
        vm.prank(user);
        pool.transact(wd);
        assertTrue(pool.nullifierUsed(uint256(nf)));

        vm.warp(vm.getBlockTimestamp() + COOLDOWN);
        EmergencyExit.ExecuteArgs memory late = _exitArgs(nf, DEPOSIT_AMOUNT, recipient, salt);
        vm.expectRevert(bytes("NULLIFIER_USED"));
        exitContract.executeEmergencyExit(late);
        assertFalse(exitContract.requestUsed(id));
    }

    function testRejectsInvalidHazePolicyAndZeroRecipient() public {
        _depositAs(user, _depositArgs(bytes32(uint256(0xC4))));
        bytes32 nf = bytes32(uint256(0xE6));
        bytes32 salt = bytes32(uint256(6));
        exitContract.requestEmergencyExit(_requestId(nf, recipient, salt));
        bytes32 zeroId = _requestId(bytes32(uint256(0xE7)), address(0), bytes32(uint256(7)));
        exitContract.requestEmergencyExit(zeroId);
        vm.warp(vm.getBlockTimestamp() + COOLDOWN);

        EmergencyExit.ExecuteArgs memory stale = _exitArgs(nf, DEPOSIT_AMOUNT, recipient, salt);
        vm.prank(governance);
        policies.schedulePolicy(2, bytes32(uint256(0xABC)), bytes32(uint256(0xDEF)));
        vm.warp(vm.getBlockTimestamp() + MIN_DELAY);
        policies.activatePolicy(2);
        vm.expectRevert(bytes("POLICY_INVALID"));
        exitContract.executeEmergencyExit(stale);

        EmergencyExit.ExecuteArgs memory zeroRecipient =
            _exitArgs(bytes32(uint256(0xE7)), DEPOSIT_AMOUNT, address(0), bytes32(uint256(7)));
        vm.expectRevert(bytes("ENCODING_INVALID"));
        exitContract.executeEmergencyExit(zeroRecipient);
    }

    function testRejectsInvalidProofAndMismatchedAuditEnvelope() public {
        _depositAs(user, _depositArgs(bytes32(uint256(0xC5))));
        bytes32 nf = bytes32(uint256(0xE8));
        bytes32 salt = bytes32(uint256(8));
        exitContract.requestEmergencyExit(_requestId(nf, recipient, salt));
        vm.warp(vm.getBlockTimestamp() + COOLDOWN);

        EmergencyExit.ExecuteArgs memory badProof = _exitArgs(nf, DEPOSIT_AMOUNT, recipient, salt);
        badProof.proof = abi.encodePacked(bytes32(uint256(1)));
        vm.expectRevert(bytes("ENCODING_INVALID"));
        exitContract.executeEmergencyExit(badProof);
        assertFalse(pool.nullifierUsed(uint256(nf)));

        EmergencyExit.ExecuteArgs memory badAudit = _exitArgs(nf, DEPOSIT_AMOUNT, recipient, salt);
        badAudit.auditCiphertext = hex"eeee";
        vm.expectRevert(bytes("ENCODING_INVALID"));
        exitContract.executeEmergencyExit(badAudit);
        assertFalse(exitContract.requestUsed(_requestId(nf, recipient, salt)));
    }

    function testRejectsReusedNullifierAndUsedRequest() public {
        _depositAs(user, _depositArgs(bytes32(uint256(0xC6))));
        bytes32 nf = bytes32(uint256(0xE9));
        bytes32 salt = bytes32(uint256(9));
        bytes32 id = _requestId(nf, recipient, salt);
        exitContract.requestEmergencyExit(id);
        vm.warp(vm.getBlockTimestamp() + COOLDOWN);
        exitContract.executeEmergencyExit(_exitArgs(nf, DEPOSIT_AMOUNT, recipient, salt));

        EmergencyExit.ExecuteArgs memory replay = _exitArgs(nf, DEPOSIT_AMOUNT, recipient, salt);
        vm.expectRevert(bytes("STATUS_INVALID"));
        exitContract.executeEmergencyExit(replay);

        usdc.mint(user, DEPOSIT_AMOUNT);
        _depositAs(user, _depositArgs(bytes32(uint256(0xC7))));
        bytes32 otherSalt = bytes32(uint256(10));
        exitContract.requestEmergencyExit(_requestId(nf, recipient, otherSalt));
        vm.warp(vm.getBlockTimestamp() + COOLDOWN);
        EmergencyExit.ExecuteArgs memory reused = _exitArgs(nf, DEPOSIT_AMOUNT, recipient, otherSalt);
        vm.expectRevert(bytes("NULLIFIER_USED"));
        exitContract.executeEmergencyExit(reused);
    }

    function testPauseBlocksNormalActionsButNotRequestOrExecute() public {
        _depositAs(user, _depositArgs(bytes32(uint256(0xC8))));
        bytes32 nf = bytes32(uint256(0xEA));
        bytes32 salt = bytes32(uint256(11));
        bytes32 id = _requestId(nf, recipient, salt);

        vm.prank(pauseRole);
        access.pause();
        HazePool.TransactArgs memory blocked = _depositArgs(bytes32(uint256(0xC9)));
        vm.prank(user);
        vm.expectRevert(bytes("PAUSED"));
        pool.deposit(blocked);

        vm.prank(stranger);
        exitContract.requestEmergencyExit(id);
        vm.warp(vm.getBlockTimestamp() + COOLDOWN);
        exitContract.executeEmergencyExit(_exitArgs(nf, DEPOSIT_AMOUNT, recipient, salt));
        assertEq(usdc.balanceOf(recipient), DEPOSIT_AMOUNT);
        assertTrue(exitContract.requestUsed(id));
    }

    function testGovernanceCannotSpendNotesOrShortenCooldown() public {
        _depositAs(user, _depositArgs(bytes32(uint256(0xCA))));
        bytes32 nf = bytes32(uint256(0xEB));
        bytes32 salt = bytes32(uint256(12));
        bytes32 id = _requestId(nf, recipient, salt);
        exitContract.requestEmergencyExit(id);

        uint256 root = pool.currentRoot();
        vm.prank(governance);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        pool.exitFromEmergency(
            APP_ID, user, root, 1, uint256(nf), DEPOSIT_AMOUNT, governance, 0, bytes32(0), "", "", ""
        );

        EmergencyExit.ExecuteArgs memory args = _exitArgs(nf, DEPOSIT_AMOUNT, recipient, salt);
        uint256 early = vm.getBlockTimestamp() + COOLDOWN - 1;
        vm.warp(early);
        vm.prank(governance);
        vm.expectRevert(bytes("AUTH_WINDOW"));
        exitContract.executeEmergencyExit(args);
        assertFalse(pool.nullifierUsed(uint256(nf)));
        assertFalse(exitContract.requestUsed(id));
        assertEq(usdc.balanceOf(governance), 0);
    }

    function testSuspendedAndRetiredApplicationsCanStillExit() public {
        _depositAs(user, _depositArgs(bytes32(uint256(0xCB))));
        vm.prank(governance);
        apps.scheduleSuspend(APP_ID);
        vm.warp(vm.getBlockTimestamp() + MIN_DELAY);
        apps.activateSuspend(APP_ID);

        bytes32 nf = bytes32(uint256(0xEC));
        bytes32 salt = bytes32(uint256(13));
        exitContract.requestEmergencyExit(_requestId(nf, recipient, salt));
        vm.warp(vm.getBlockTimestamp() + COOLDOWN);
        exitContract.executeEmergencyExit(_exitArgs(nf, DEPOSIT_AMOUNT, recipient, salt));
        assertEq(usdc.balanceOf(recipient), DEPOSIT_AMOUNT);

        usdc.mint(user, DEPOSIT_AMOUNT);
        vm.prank(governance);
        apps.scheduleRetire(APP_ID);
        vm.warp(vm.getBlockTimestamp() + MIN_DELAY);
        apps.activateRetire(APP_ID);
        _registerAndActivateApp(bytes32(uint256(0xA12)));
        // Deposit is blocked on retired APP_ID; mint extra USDC via a live app then exit the retired one.
        vm.prank(user);
        usdc.approve(address(pool), type(uint256).max);
        HazePool.TransactArgs memory liveDeposit = _depositArgsFor(bytes32(uint256(0xA12)), bytes32(uint256(0xCC)));
        vm.prank(user);
        pool.deposit(liveDeposit);

        bytes32 retiredNf = bytes32(uint256(0xED));
        bytes32 retiredSalt = bytes32(uint256(14));
        exitContract.requestEmergencyExit(_requestIdFor(APP_ID, retiredNf, recipient, retiredSalt));
        vm.warp(vm.getBlockTimestamp() + COOLDOWN);
        EmergencyExit.ExecuteArgs memory retiredExit = _exitArgs(retiredNf, DEPOSIT_AMOUNT, recipient, retiredSalt);
        retiredExit.applicationId = APP_ID;
        retiredExit.proof = _developmentProof(retiredExit);
        exitContract.executeEmergencyExit(retiredExit);
        assertEq(usdc.balanceOf(recipient), 2 * DEPOSIT_AMOUNT);
    }

    function testRetiredVersionExitCapableUntilSupportUntil() public {
        _depositAs(user, _depositArgs(bytes32(uint256(0xCD))));
        uint48 supportUntil = uint48(vm.getBlockTimestamp() + 30 days);
        vm.prank(governance);
        versions.scheduleRelease(POOL_VERSION, bytes32(uint256(0x51)), "ipfs://v1", supportUntil);
        vm.warp(vm.getBlockTimestamp() + MIN_DELAY);
        versions.activateRelease(POOL_VERSION);
        vm.prank(governance);
        versions.scheduleRelease(NEXT_VERSION, bytes32(uint256(0x52)), "ipfs://v2", uint48(vm.getBlockTimestamp() + 60 days));
        vm.warp(vm.getBlockTimestamp() + MIN_DELAY);
        versions.activateRelease(NEXT_VERSION);
        assertEq(uint256(versions.release(POOL_VERSION).status), uint256(VersionRegistry.Status.Retired));
        assertTrue(versions.isExitCapable(POOL_VERSION));

        bytes32 nf = bytes32(uint256(0xEE));
        bytes32 salt = bytes32(uint256(15));
        exitContract.requestEmergencyExit(_requestId(nf, recipient, salt));
        vm.warp(vm.getBlockTimestamp() + COOLDOWN);
        exitContract.executeEmergencyExit(_exitArgs(nf, DEPOSIT_AMOUNT, recipient, salt));
        assertEq(usdc.balanceOf(recipient), DEPOSIT_AMOUNT);

        usdc.mint(user, DEPOSIT_AMOUNT);
        _depositAs(user, _depositArgs(bytes32(uint256(0xCE))));
        bytes32 lateNf = bytes32(uint256(0xEF));
        bytes32 lateSalt = bytes32(uint256(16));
        exitContract.requestEmergencyExit(_requestId(lateNf, recipient, lateSalt));
        uint256 expired = uint256(supportUntil) + 1;
        vm.warp(expired);
        assertFalse(versions.isExitCapable(POOL_VERSION));
        EmergencyExit.ExecuteArgs memory late = _exitArgs(lateNf, DEPOSIT_AMOUNT, recipient, lateSalt);
        vm.expectRevert(bytes("VERSION_UNSUPPORTED"));
        exitContract.executeEmergencyExit(late);
    }

    function testPublicWithdrawThenReshieldIntoReplacementVersion() public {
        _depositAs(user, _depositArgs(bytes32(uint256(0xCF))));
        uint256 root = pool.currentRoot();
        HazePool.TransactArgs memory wd =
            _withdrawArgs(user, root, DEPOSIT_AMOUNT, user, bytes32(uint256(0xA5)));
        vm.prank(user);
        pool.transact(wd);
        assertEq(usdc.balanceOf(user), 10_000_000);

        HazePool replacement = new HazePool(
            access,
            apps,
            policies,
            verifier,
            address(usdc),
            address(0),
            address(0),
            NEXT_VERSION,
            ROOT_HISTORY
        );
        vm.prank(user);
        usdc.approve(address(replacement), type(uint256).max);
        HazePool.TransactArgs memory shield = _depositArgs(bytes32(uint256(0xD0)));
        shield.intent.pool = address(replacement);
        shield.intent.poolVersion = NEXT_VERSION;
        _finalizeFor(shield, replacement);
        vm.prank(user);
        replacement.deposit(shield);
        assertEq(usdc.balanceOf(address(replacement)), DEPOSIT_AMOUNT);
        assertEq(usdc.balanceOf(address(pool)), 0);
        assertTrue(replacement.commitmentExists(shield.intent.outputCommitment0));
    }

    function testFuzzEarlyElapsedRejects(uint32 elapsed) public {
        elapsed = uint32(bound(elapsed, 0, COOLDOWN - 1));
        _depositAs(user, _depositArgs(bytes32(uint256(0xD1))));
        bytes32 nf = bytes32(uint256(0xF1));
        bytes32 salt = bytes32(uint256(0xF2));
        exitContract.requestEmergencyExit(_requestId(nf, recipient, salt));
        EmergencyExit.ExecuteArgs memory args = _exitArgs(nf, DEPOSIT_AMOUNT, recipient, salt);
        uint256 early = vm.getBlockTimestamp() + elapsed;
        vm.warp(early);
        vm.expectRevert(bytes("AUTH_WINDOW"));
        exitContract.executeEmergencyExit(args);
        assertFalse(pool.nullifierUsed(uint256(nf)));
    }

    function testFuzzSuccessfulExitConservesUsdc(uint64 amount) public {
        amount = uint64(bound(amount, 1, 1_000_000));
        _depositAs(user, _depositArgsAmount(bytes32(uint256(amount) | (1 << 200)), amount));
        bytes32 nf = bytes32(uint256(amount) | (1 << 180));
        bytes32 salt = bytes32(uint256(amount) | (1 << 160));
        exitContract.requestEmergencyExit(_requestId(nf, recipient, salt));
        vm.warp(vm.getBlockTimestamp() + COOLDOWN);
        uint256 poolBefore = usdc.balanceOf(address(pool));
        uint256 recipientBefore = usdc.balanceOf(recipient);
        exitContract.executeEmergencyExit(_exitArgs(nf, amount, recipient, salt));
        assertEq(usdc.balanceOf(recipient), recipientBefore + amount);
        assertEq(usdc.balanceOf(address(pool)), poolBefore - amount);
        assertEq(usdc.balanceOf(address(exitContract)), 0);
    }

    function _requestId(bytes32 nf, address to, bytes32 salt) internal view returns (bytes32) {
        return _requestIdFor(APP_ID, nf, to, salt);
    }

    function _requestIdFor(bytes32 applicationId, bytes32 nf, address to, bytes32 salt)
        internal
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                keccak256(
                    "HazeEmergencyExitRequest(uint256 chainId,address pool,bytes32 poolVersion,bytes32 applicationId,uint256 nullifier,address recipient,bytes32 requestSalt)"
                ),
                block.chainid,
                address(pool),
                POOL_VERSION,
                applicationId,
                uint256(nf),
                to,
                salt
            )
        );
    }

    function _exitArgs(bytes32 nf, uint64 amount, address to, bytes32 salt)
        internal
        view
        returns (EmergencyExit.ExecuteArgs memory args)
    {
        args.applicationId = APP_ID;
        args.noteTreeRoot = pool.currentRoot();
        args.hazePolicyVersion = policies.activeVersion();
        args.hazeBlocklistRoot = uint256(policies.activeRoot());
        args.nullifier = uint256(nf);
        args.publicAmount = amount;
        args.recipient = to;
        args.requester = user;
        args.requestSalt = salt;
        args.auditCiphertext = hex"aa";
        args.auditDataCommitment = uint256(bytes32(uint256(0xAD)));
        args.auditCiphertextHash = keccak256(args.auditCiphertext);
        args.proof = _developmentProof(args);
    }

    function _developmentProof(EmergencyExit.ExecuteArgs memory args) internal view returns (bytes memory) {
        return abi.encodePacked(keccak256(abi.encodePacked(exitContract.publicInputs(args))));
    }

    function _registerArgs(bytes32 applicationId)
        internal
        view
        returns (ApplicationRegistry.RegisterParams memory params)
    {
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
        vm.warp(vm.getBlockTimestamp() + MIN_DELAY);
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

    function _depositArgs(bytes32 cm0) internal returns (HazePool.TransactArgs memory args) {
        return _depositArgsAmount(cm0, DEPOSIT_AMOUNT);
    }

    function _depositArgsFor(bytes32 applicationId, bytes32 cm0)
        internal
        returns (HazePool.TransactArgs memory args)
    {
        args.intent = _baseIntent(applicationId, user, 1);
        args.intent.outputCommitment0 = uint256(cm0);
        args.intent.publicAmount = DEPOSIT_AMOUNT;
        args.recipientCiphertext0 = hex"c0";
        args.recipientCiphertext1 = "";
        args.auditCiphertext = hex"aa";
        args.intent.recipientCiphertextHash0 = keccak256(args.recipientCiphertext0);
        args.intent.recipientCiphertextHash1 = keccak256(args.recipientCiphertext1);
        args.intent.auditDataCommitment = uint256(bytes32(uint256(0xAD)));
        args.intent.auditCiphertextHash = keccak256(args.auditCiphertext);
        _finalizeFor(args, pool);
    }

    function _depositArgsAmount(bytes32 cm0, uint64 amount) internal returns (HazePool.TransactArgs memory args) {
        args.intent = _baseIntent(APP_ID, user, 1);
        args.intent.outputCommitment0 = uint256(cm0);
        args.intent.publicAmount = amount;
        args.recipientCiphertext0 = hex"c0";
        args.recipientCiphertext1 = "";
        args.auditCiphertext = hex"aa";
        args.intent.recipientCiphertextHash0 = keccak256(args.recipientCiphertext0);
        args.intent.recipientCiphertextHash1 = keccak256(args.recipientCiphertext1);
        args.intent.auditDataCommitment = uint256(bytes32(uint256(0xAD)));
        args.intent.auditCiphertextHash = keccak256(args.auditCiphertext);
        _finalizeFor(args, pool);
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
        _finalizeFor(args, pool);
    }

    function _finalizeFor(HazePool.TransactArgs memory args, HazePool target) internal {
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
        args.authorization.validAfter = uint48(vm.getBlockTimestamp() - 1);
        args.authorization.validUntil = uint48(vm.getBlockTimestamp() + 1 hours);
        args.authorizationSignature = _signAuthorization(args.authorization, target);
        args.proof = abi.encodePacked(keccak256(abi.encodePacked(target.publicInputs(args.intent))));
    }

    function _signAuthorization(HazeProtocolVectors.AuthorizationFields memory auth, HazePool target)
        internal
        view
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            gatekeeperPk,
            HazeProtocolVectors.typedDataDigest(
                HazeProtocolVectors.domainSeparator(
                    target.DOMAIN_NAME(), target.DOMAIN_VERSION(), block.chainid, address(target)
                ),
                HazeProtocolVectors.authorizationStructHash(auth)
            )
        );
        return abi.encodePacked(r, s, v);
    }

    function _depositAs(address account, HazePool.TransactArgs memory args) internal {
        vm.prank(account);
        pool.deposit(args);
    }
}
