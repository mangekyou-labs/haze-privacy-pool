// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {HazeAccess} from "../src/HazeAccess.sol";
import {ApplicationRegistry} from "../src/ApplicationRegistry.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {VersionRegistry} from "../src/VersionRegistry.sol";

contract RegistriesTest is Test {
    uint48 internal constant MIN_DELAY = 2 days;

    HazeAccess internal access;
    ApplicationRegistry internal apps;
    PolicyRegistry internal policies;
    VersionRegistry internal versions;

    address internal governance;
    address internal pauseRole;
    address internal admin;
    address internal gatekeeper;
    address internal policyAuth;
    address internal stranger;
    address internal auditor;

    bytes32 internal constant APP_ID = bytes32(uint256(0xA11));
    bytes32 internal constant MEMBER_ROOT = bytes32(uint256(0x11));
    bytes32 internal constant MANIFEST_HASH = bytes32(uint256(0x22));
    bytes32 internal constant POLICY_PROFILE = bytes32(uint256(0x33));
    bytes32 internal constant BLOCK_ROOT = bytes32(uint256(0x44));
    bytes32 internal constant POLICY_ARTIFACT = bytes32(uint256(0x55));
    bytes32 internal constant RELEASE_TAG = bytes32(uint256(0x66));
    bytes32 internal constant RELEASE_ARTIFACT = bytes32(uint256(0x77));

    function setUp() public {
        governance = makeAddr("governance");
        pauseRole = makeAddr("pause");
        admin = makeAddr("admin");
        gatekeeper = makeAddr("gatekeeper");
        policyAuth = makeAddr("policyAuth");
        stranger = makeAddr("stranger");
        auditor = makeAddr("auditor");
        vm.warp(1_700_000_000);
        access = new HazeAccess(governance, pauseRole, MIN_DELAY);
        apps = new ApplicationRegistry(access);
        policies = new PolicyRegistry(access);
        versions = new VersionRegistry(access);
    }

    function testRolesAreDistinctAndPauseIsImmediate() public {
        assertEq(access.governance(), governance);
        assertEq(access.pauseRole(), pauseRole);
        assertEq(access.minDelay(), MIN_DELAY);
        assertFalse(access.paused());
        assertFalse(access.isSuperAuditor(auditor));

        vm.prank(governance);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        access.pause();

        vm.prank(stranger);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        access.pause();

        vm.prank(pauseRole);
        access.pause();
        assertTrue(access.paused());

        vm.prank(governance);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        access.unpause();

        vm.prank(pauseRole);
        access.unpause();
        assertFalse(access.paused());
    }

    function testSuperAuditorGrantIsTimelockedAndGrantsNoMutation() public {
        vm.prank(stranger);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        access.scheduleSuperAuditor(auditor, true);

        vm.prank(governance);
        access.scheduleSuperAuditor(auditor, true);
        assertFalse(access.isSuperAuditor(auditor));

        vm.expectRevert(bytes("TIMELOCK"));
        access.activateSuperAuditor();

        vm.warp(block.timestamp + MIN_DELAY);
        access.activateSuperAuditor();
        assertTrue(access.isSuperAuditor(auditor));

        vm.prank(auditor);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        apps.scheduleRegister(_registerArgs());

        vm.prank(auditor);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        policies.schedulePolicy(1, BLOCK_ROOT, POLICY_ARTIFACT);

        vm.prank(auditor);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        versions.scheduleRelease(RELEASE_TAG, RELEASE_ARTIFACT, "ipfs://release");

        vm.prank(auditor);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        access.pause();
    }

    function testScheduleAndActivateApplicationAfterTimelock() public {
        vm.prank(governance);
        apps.scheduleRegister(_registerArgs());

        ApplicationRegistry.ApplicationRecord memory pending = apps.getApplication(APP_ID);
        assertEq(uint256(pending.status), uint256(ApplicationRegistry.Status.Pending));
        assertEq(pending.admin, admin);
        assertEq(pending.gatekeeperSigner, gatekeeper);
        assertEq(pending.policyAuthority, policyAuth);
        assertEq(pending.membershipRoot, MEMBER_ROOT);
        assertEq(pending.membershipVersion, 1);
        assertEq(pending.manifestHash, MANIFEST_HASH);
        assertEq(pending.manifestUri, "ipfs://manifest");
        assertFalse(apps.isActive(APP_ID));

        vm.expectRevert(bytes("TIMELOCK"));
        apps.activateRegister(APP_ID);

        vm.warp(block.timestamp + MIN_DELAY - 1);
        vm.expectRevert(bytes("TIMELOCK"));
        apps.activateRegister(APP_ID);

        vm.warp(block.timestamp + 1);
        apps.activateRegister(APP_ID);
        assertTrue(apps.isActive(APP_ID));
        assertEq(uint256(apps.getApplication(APP_ID).status), uint256(ApplicationRegistry.Status.Active));
    }

    function testUnauthorizedCannotScheduleOrActivateRegistries() public {
        vm.prank(stranger);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        apps.scheduleRegister(_registerArgs());

        vm.prank(admin);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        apps.scheduleRegister(_registerArgs());

        vm.prank(pauseRole);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        policies.schedulePolicy(1, BLOCK_ROOT, POLICY_ARTIFACT);

        vm.prank(stranger);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        versions.scheduleRelease(RELEASE_TAG, RELEASE_ARTIFACT, "ipfs://release");
    }

    function testApplicationProvenanceEventsPreservePriorConfigUntilActivation() public {
        vm.prank(governance);
        vm.expectEmit(true, true, false, true, address(apps));
        emit ApplicationRegistry.ApplicationScheduled(APP_ID, admin, uint48(block.timestamp + MIN_DELAY), MANIFEST_HASH);
        apps.scheduleRegister(_registerArgs());

        ApplicationRegistry.ApplicationRecord memory beforeActivate = apps.getApplication(APP_ID);
        vm.warp(block.timestamp + MIN_DELAY);
        vm.expectEmit(true, false, false, true, address(apps));
        emit ApplicationRegistry.ApplicationActivated(APP_ID);
        apps.activateRegister(APP_ID);

        ApplicationRegistry.ApplicationRecord memory afterActivate = apps.getApplication(APP_ID);
        assertEq(afterActivate.admin, beforeActivate.admin);
        assertEq(afterActivate.gatekeeperSigner, beforeActivate.gatekeeperSigner);
        assertEq(afterActivate.policyAuthority, beforeActivate.policyAuthority);
        assertEq(afterActivate.membershipRoot, beforeActivate.membershipRoot);
        assertEq(afterActivate.manifestHash, beforeActivate.manifestHash);
        assertEq(uint256(afterActivate.status), uint256(ApplicationRegistry.Status.Active));
    }

    function testOnlyPolicyAuthorityUpdatesMembershipRoot() public {
        _registerAndActivateApp();

        bytes32 nextRoot = bytes32(uint256(0x99));
        vm.prank(governance);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        apps.updateMembershipRoot(APP_ID, nextRoot);

        vm.prank(admin);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        apps.updateMembershipRoot(APP_ID, nextRoot);

        vm.prank(policyAuth);
        vm.expectEmit(true, false, false, true, address(apps));
        emit ApplicationRegistry.MembershipRootUpdated(APP_ID, nextRoot, 2);
        apps.updateMembershipRoot(APP_ID, nextRoot);

        ApplicationRegistry.ApplicationRecord memory record = apps.getApplication(APP_ID);
        assertEq(record.membershipRoot, nextRoot);
        assertEq(record.membershipVersion, 2);
    }

    function testAdminRotatesGatekeeperAndManifest() public {
        _registerAndActivateApp();

        address nextSigner = makeAddr("nextGatekeeper");
        vm.prank(stranger);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        apps.rotateGatekeeper(APP_ID, nextSigner);

        vm.prank(admin);
        vm.expectEmit(true, false, false, true, address(apps));
        emit ApplicationRegistry.GatekeeperRotated(APP_ID, nextSigner);
        apps.rotateGatekeeper(APP_ID, nextSigner);
        assertEq(apps.getApplication(APP_ID).gatekeeperSigner, nextSigner);

        vm.prank(admin);
        apps.updateManifest(APP_ID, "ipfs://manifest-2", bytes32(uint256(0x222)));
        assertEq(apps.getApplication(APP_ID).manifestUri, "ipfs://manifest-2");
        assertEq(apps.getApplication(APP_ID).manifestHash, bytes32(uint256(0x222)));
    }

    function testSuspendDoesNotGrantNoteSpendAndLeavesKeysIntact() public {
        _registerAndActivateApp();
        ApplicationRegistry.ApplicationRecord memory before = apps.getApplication(APP_ID);

        vm.prank(governance);
        apps.scheduleSuspend(APP_ID);
        assertTrue(apps.isActive(APP_ID));

        vm.expectRevert(bytes("TIMELOCK"));
        apps.activateSuspend(APP_ID);

        vm.warp(block.timestamp + MIN_DELAY);
        apps.activateSuspend(APP_ID);
        assertFalse(apps.isActive(APP_ID));
        assertEq(uint256(apps.getApplication(APP_ID).status), uint256(ApplicationRegistry.Status.Suspended));

        ApplicationRegistry.ApplicationRecord memory afterSuspend = apps.getApplication(APP_ID);
        assertEq(afterSuspend.admin, before.admin);
        assertEq(afterSuspend.gatekeeperSigner, before.gatekeeperSigner);
        assertEq(afterSuspend.membershipRoot, before.membershipRoot);
        assertEq(afterSuspend.policyAuthority, before.policyAuthority);

        (bool okSpend,) = address(apps).call(abi.encodeWithSignature("spend(bytes32)", APP_ID));
        assertFalse(okSpend);
        (bool okWithdraw,) = address(apps).call(abi.encodeWithSignature("withdraw(address,uint256)", admin, 1));
        assertFalse(okWithdraw);
        (bool okTransfer,) = address(apps).call(abi.encodeWithSignature("transfer(address,uint256)", admin, 1));
        assertFalse(okTransfer);

        vm.prank(policyAuth);
        vm.expectRevert(bytes("STATUS_INVALID"));
        apps.updateMembershipRoot(APP_ID, bytes32(uint256(3)));
    }

    function testRetireIsTerminalAndReactivateRequiresTimelock() public {
        _registerAndActivateApp();

        vm.prank(governance);
        apps.scheduleSuspend(APP_ID);
        vm.warp(block.timestamp + MIN_DELAY);
        apps.activateSuspend(APP_ID);

        vm.prank(governance);
        apps.scheduleReactivate(APP_ID);
        vm.expectRevert(bytes("TIMELOCK"));
        apps.activateReactivate(APP_ID);
        vm.warp(block.timestamp + MIN_DELAY);
        apps.activateReactivate(APP_ID);
        assertTrue(apps.isActive(APP_ID));

        vm.prank(governance);
        apps.scheduleRetire(APP_ID);
        vm.warp(block.timestamp + MIN_DELAY);
        apps.activateRetire(APP_ID);
        assertEq(uint256(apps.getApplication(APP_ID).status), uint256(ApplicationRegistry.Status.Retired));

        vm.prank(governance);
        vm.expectRevert(bytes("STATUS_INVALID"));
        apps.scheduleReactivate(APP_ID);
        vm.prank(governance);
        vm.expectRevert(bytes("STATUS_INVALID"));
        apps.scheduleRegister(_registerArgs());
    }

    function testPolicyActivationHasNoGracePeriod() public {
        vm.prank(governance);
        policies.schedulePolicy(1, BLOCK_ROOT, POLICY_ARTIFACT);
        PolicyRegistry.PolicyVersion memory scheduled = policies.policy(1);
        assertEq(uint256(scheduled.status), uint256(PolicyRegistry.Status.Scheduled));
        assertFalse(policies.isActivePolicy(1, BLOCK_ROOT));

        vm.expectRevert(bytes("TIMELOCK"));
        policies.activatePolicy(1);

        vm.warp(block.timestamp + MIN_DELAY);
        policies.activatePolicy(1);
        assertTrue(policies.isActivePolicy(1, BLOCK_ROOT));
        assertFalse(policies.isActivePolicy(1, bytes32(uint256(0xdead))));
        assertFalse(policies.isActivePolicy(2, BLOCK_ROOT));
        assertFalse(policies.isActivePolicy(0, BLOCK_ROOT));

        bytes32 nextRoot = bytes32(uint256(0xabc));
        vm.prank(governance);
        policies.schedulePolicy(2, nextRoot, bytes32(uint256(0xdef)));
        assertTrue(policies.isActivePolicy(1, BLOCK_ROOT));
        assertFalse(policies.isActivePolicy(2, nextRoot));

        vm.warp(block.timestamp + MIN_DELAY);
        policies.activatePolicy(2);
        assertTrue(policies.isActivePolicy(2, nextRoot));
        assertFalse(policies.isActivePolicy(1, BLOCK_ROOT));
        assertEq(uint256(policies.policy(1).status), uint256(PolicyRegistry.Status.Retired));
        assertEq(policies.activeVersion(), 2);
        assertEq(policies.activeRoot(), nextRoot);
    }

    function testVersionRegistryPublishesHashesWithoutUpgradePath() public {
        vm.prank(governance);
        versions.scheduleRelease(RELEASE_TAG, RELEASE_ARTIFACT, "ipfs://release");
        assertFalse(versions.isActiveRelease(RELEASE_TAG, RELEASE_ARTIFACT));

        vm.expectRevert(bytes("TIMELOCK"));
        versions.activateRelease(RELEASE_TAG);

        vm.warp(block.timestamp + MIN_DELAY);
        versions.activateRelease(RELEASE_TAG);
        assertTrue(versions.isActiveRelease(RELEASE_TAG, RELEASE_ARTIFACT));
        assertEq(versions.activeRelease().artifactHash, RELEASE_ARTIFACT);
        assertEq(versions.activeRelease().metadataUri, "ipfs://release");

        (bool okUpgrade,) = address(versions).call(abi.encodeWithSignature("upgradeTo(address)", address(1)));
        assertFalse(okUpgrade);
        (bool okUpgradeCall,) =
            address(versions).call(abi.encodeWithSignature("upgradeToAndCall(address,bytes)", address(1), ""));
        assertFalse(okUpgradeCall);
        (bool okInit,) = address(versions).call(abi.encodeWithSignature("initialize(address)", governance));
        assertFalse(okInit);
        (bool okOwner,) = address(versions).call(abi.encodeWithSignature("owner()"));
        assertFalse(okOwner);
    }

    function testPauseBlocksMutationsAndLeavesReads() public {
        vm.prank(governance);
        apps.scheduleRegister(_registerArgs());
        vm.prank(governance);
        policies.schedulePolicy(1, BLOCK_ROOT, POLICY_ARTIFACT);

        vm.prank(pauseRole);
        access.pause();

        vm.prank(governance);
        vm.expectRevert(bytes("PAUSED"));
        apps.scheduleRegister(_registerArgs());
        vm.expectRevert(bytes("PAUSED"));
        apps.activateRegister(APP_ID);
        vm.prank(governance);
        vm.expectRevert(bytes("PAUSED"));
        policies.schedulePolicy(2, BLOCK_ROOT, POLICY_ARTIFACT);
        vm.expectRevert(bytes("PAUSED"));
        policies.activatePolicy(1);

        ApplicationRegistry.ApplicationRecord memory pending = apps.getApplication(APP_ID);
        assertEq(uint256(pending.status), uint256(ApplicationRegistry.Status.Pending));
        assertFalse(policies.isActivePolicy(1, BLOCK_ROOT));
    }

    function testFuzzUnauthorizedCannotSchedulePolicy(address caller) public {
        vm.assume(caller != governance);
        vm.prank(caller);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        policies.schedulePolicy(1, BLOCK_ROOT, POLICY_ARTIFACT);
    }

    function testFuzzPolicyFreshnessRejectsNonActive(uint64 version, bytes32 root) public {
        vm.prank(governance);
        policies.schedulePolicy(1, BLOCK_ROOT, POLICY_ARTIFACT);
        vm.warp(block.timestamp + MIN_DELAY);
        policies.activatePolicy(1);
        vm.assume(version != 1 || root != BLOCK_ROOT);
        assertFalse(policies.isActivePolicy(version, root));
        assertTrue(policies.isActivePolicy(1, BLOCK_ROOT));
    }

    function testFuzzUnauthorizedMembershipUpdate(address caller, bytes32 root) public {
        _registerAndActivateApp();
        vm.assume(caller != policyAuth);
        vm.prank(caller);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        apps.updateMembershipRoot(APP_ID, root);
    }

    function _registerArgs() internal view returns (ApplicationRegistry.RegisterParams memory params) {
        params = ApplicationRegistry.RegisterParams({
            applicationId: APP_ID,
            admin: admin,
            gatekeeperSigner: gatekeeper,
            policyAuthority: policyAuth,
            membershipRoot: MEMBER_ROOT,
            auditPublicKey: hex"11",
            manifestUri: "ipfs://manifest",
            manifestHash: MANIFEST_HASH,
            policyProfile: POLICY_PROFILE
        });
    }

    function _registerAndActivateApp() internal {
        vm.prank(governance);
        apps.scheduleRegister(_registerArgs());
        vm.warp(block.timestamp + MIN_DELAY);
        apps.activateRegister(APP_ID);
    }
}
