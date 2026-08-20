// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {EmergencyExit} from "../src/EmergencyExit.sol";
import {HazePool} from "../src/HazePool.sol";
import {HazeProtocolFixture} from "./HazeProtocolFixture.sol";
import {SwapAndShieldRouter} from "../src/SwapAndShieldRouter.sol";

/// @dev Ghost-accounted handler: development proofs do not bind note values, so
///      live notes must be tracked here to stop fake double-spends of USDC.
contract ProtocolHandler is HazeProtocolFixture {
    uint256 internal constant MAX_NOTES = 48;

    struct GhostNote {
        uint256 nullifier;
        uint256 commitment;
        uint64 amount;
        bool live;
    }

    struct GhostExit {
        uint256 noteIndex;
        bytes32 salt;
        bytes32 id;
        bool used;
    }

    GhostNote[] public notes;
    GhostExit[] public exits;

    uint256 public nextCommitment = 0xC000;
    uint256 public nextNullifier = 0xE000;
    uint256 public nextSalt = 1;
    uint256 public nextApp = 0xB00;
    uint256 public nextRelease = 0xC001;
    uint64 public nextPolicy = 2;

    bytes32 public pendingAppId;
    bool public appScheduled;
    uint64 public pendingPolicyVersion;
    bool public policyScheduled;
    bytes32 public pendingReleaseTag;
    bool public releaseScheduled;
    bool public tokenScheduled;
    bool public governanceSpent;

    constructor() {
        setUpProtocol();
    }

    function conservedUsdc() external view returns (uint256) {
        return _sumUsdc();
    }

    function deposit(uint64 amount) external {
        if (access.paused() || notes.length >= MAX_NOTES) {
            return;
        }
        amount = uint64(bound(amount, 1, DEPOSIT_AMOUNT));
        if (usdc.balanceOf(user) < amount) {
            return;
        }
        nextCommitment += 1;
        HazePool.TransactArgs memory args = _depositArgs(user, amount, bytes32(nextCommitment));
        vm.prank(user);
        try pool.deposit(args) {
            _pushNote(uint256(bytes32(nextCommitment)), amount);
        } catch {}
    }

    function transfer(uint256 seed) external {
        if (access.paused()) {
            return;
        }
        (bool ok, uint256 idx) = _pickLive(seed);
        if (!ok || notes.length >= MAX_NOTES) {
            return;
        }
        nextCommitment += 1;
        HazePool.TransactArgs memory args =
            _transferArgs(user, pool.currentRoot(), notes[idx].nullifier, bytes32(nextCommitment));
        vm.prank(user);
        try pool.transact(args) {
            notes[idx].live = false;
            _pushNote(uint256(bytes32(nextCommitment)), notes[idx].amount);
        } catch {}
    }

    function withdraw(uint256 seed) external {
        if (access.paused()) {
            return;
        }
        (bool ok, uint256 idx) = _pickLive(seed);
        if (!ok) {
            return;
        }
        HazePool.TransactArgs memory args = _withdrawArgs(
            user, pool.currentRoot(), notes[idx].amount, recipient, notes[idx].nullifier
        );
        vm.prank(user);
        try pool.transact(args) {
            notes[idx].live = false;
        } catch {}
    }

    function swapAndShield(uint64 amount) external {
        if (access.paused() || notes.length >= MAX_NOTES) {
            return;
        }
        amount = uint64(bound(amount, 1, DEPOSIT_AMOUNT));
        if (source.balanceOf(user) < amount || usdc.balanceOf(address(dex)) < amount) {
            return;
        }
        bytes memory data = _dexData(address(source), amount, amount, address(router));
        SwapAndShieldRouter.SwapRoute memory route = _route(address(dex), data);
        nextCommitment += 1;
        HazePool.TransactArgs memory args =
            _swapArgs(user, amount, bytes32(nextCommitment), route.expectedRouteHash);
        vm.prank(user);
        try router.swapAndShield(args, route) {
            _pushNote(uint256(bytes32(nextCommitment)), amount);
        } catch {}
    }

    function requestEmergencyExit(uint256 seed) external {
        (bool ok, uint256 idx) = _pickLive(seed);
        if (!ok) {
            return;
        }
        nextSalt += 1;
        bytes32 salt = bytes32(nextSalt);
        bytes32 id = _requestId(notes[idx].nullifier, recipient, salt);
        try exitContract.requestEmergencyExit(id) {
            exits.push(GhostExit({noteIndex: idx, salt: salt, id: id, used: false}));
        } catch {}
    }

    function executeEmergencyExit(uint256 seed) external {
        (bool ok, uint256 idx) = _pickOpenExit(seed);
        if (!ok) {
            return;
        }
        GhostExit storage pending = exits[idx];
        GhostNote storage note = notes[pending.noteIndex];
        uint48 requestedAt = exitContract.requestedAt(pending.id);
        uint256 readyAt = uint256(requestedAt) + COOLDOWN;
        if (vm.getBlockTimestamp() < readyAt) {
            vm.warp(readyAt);
        }
        EmergencyExit.ExecuteArgs memory args =
            _exitArgs(note.nullifier, note.amount, recipient, pending.salt);
        try exitContract.executeEmergencyExit(args) {
            note.live = false;
            pending.used = true;
        } catch {}
    }

    function scheduleRegister(uint256 seed) external {
        if (access.paused() || appScheduled) {
            return;
        }
        nextApp += 1 + (seed % 7);
        bytes32 applicationId = bytes32(nextApp);
        vm.prank(governance);
        try apps.scheduleRegister(_registerArgs(applicationId)) {
            pendingAppId = applicationId;
            appScheduled = true;
        } catch {}
    }

    function activateRegister() external {
        if (access.paused() || !appScheduled) {
            return;
        }
        uint256 readyAt = uint256(apps.registerActivateAt(pendingAppId));
        if (vm.getBlockTimestamp() < readyAt) {
            vm.warp(readyAt);
        }
        try apps.activateRegister(pendingAppId) {
            appScheduled = false;
        } catch {}
    }

    function schedulePolicy(uint256 seed) external {
        if (access.paused() || policyScheduled) {
            return;
        }
        uint64 version = nextPolicy;
        bytes32 root = bytes32(uint256(0x4400) + version + (seed % 13));
        bytes32 artifact = bytes32(uint256(0x5500) + version);
        vm.prank(governance);
        try policies.schedulePolicy(version, root, artifact) {
            pendingPolicyVersion = version;
            policyScheduled = true;
            nextPolicy = version + 1;
        } catch {}
    }

    function activatePolicy() external {
        if (access.paused() || !policyScheduled) {
            return;
        }
        uint256 readyAt = uint256(policies.policy(pendingPolicyVersion).activateAt);
        if (vm.getBlockTimestamp() < readyAt) {
            vm.warp(readyAt);
        }
        try policies.activatePolicy(pendingPolicyVersion) {
            policyScheduled = false;
        } catch {}
    }

    function scheduleRelease(uint256 seed) external {
        if (access.paused() || releaseScheduled) {
            return;
        }
        nextRelease += 1 + (seed % 5);
        bytes32 tag = bytes32(nextRelease);
        vm.prank(governance);
        try versions.scheduleRelease(tag, bytes32(uint256(0xAB) + nextRelease), "ipfs://rel", 0) {
            pendingReleaseTag = tag;
            releaseScheduled = true;
        } catch {}
    }

    function activateRelease() external {
        if (access.paused() || !releaseScheduled) {
            return;
        }
        uint256 readyAt = uint256(versions.release(pendingReleaseTag).activateAt);
        if (vm.getBlockTimestamp() < readyAt) {
            vm.warp(readyAt);
        }
        try versions.activateRelease(pendingReleaseTag) {
            releaseScheduled = false;
        } catch {}
    }

    function pause() external {
        vm.prank(pauseRole);
        try access.pause() {} catch {}
    }

    function unpause() external {
        vm.prank(pauseRole);
        try access.unpause() {} catch {}
    }

    function scheduleToken() external {
        if (access.paused() || tokenScheduled) {
            return;
        }
        vm.prank(governance);
        try router.scheduleToken(address(extraToken), true) {
            tokenScheduled = true;
        } catch {}
    }

    function activateToken() external {
        if (access.paused() || !tokenScheduled) {
            return;
        }
        uint256 readyAt = uint256(router.pendingTokenEta());
        if (vm.getBlockTimestamp() < readyAt) {
            vm.warp(readyAt);
        }
        try router.activateToken() {
            tokenScheduled = false;
        } catch {}
    }

    function governanceDeposit(uint64 amount) external {
        amount = uint64(bound(amount, 1, DEPOSIT_AMOUNT));
        nextCommitment += 1;
        HazePool.TransactArgs memory args = _depositArgs(user, amount, bytes32(nextCommitment));
        vm.prank(governance);
        try pool.deposit(args) {
            governanceSpent = true;
        } catch {}
        vm.prank(pauseRole);
        try pool.deposit(args) {
            governanceSpent = true;
        } catch {}
    }

    function routerHasResidue() external view returns (uint256) {
        return usdc.balanceOf(address(router)) + source.balanceOf(address(router));
    }

    function exitHasResidue() external view returns (uint256) {
        return usdc.balanceOf(address(exitContract));
    }

    function roleUsdc() external view returns (uint256) {
        return usdc.balanceOf(governance) + usdc.balanceOf(pauseRole);
    }

    function nullifiersConsistent() external view returns (bool) {
        for (uint256 i; i < notes.length; ++i) {
            bool used = pool.nullifierUsed(notes[i].nullifier);
            if (notes[i].live && used) {
                return false;
            }
            if (!notes[i].live && !used) {
                return false;
            }
        }
        return true;
    }

    function _pushNote(uint256 commitment, uint64 amount) internal {
        nextNullifier += 1;
        notes.push(
            GhostNote({nullifier: nextNullifier, commitment: commitment, amount: amount, live: true})
        );
    }

    function _pickLive(uint256 seed) internal view returns (bool ok, uint256 idx) {
        uint256 n;
        for (uint256 i; i < notes.length; ++i) {
            if (notes[i].live) {
                n += 1;
            }
        }
        if (n == 0) {
            return (false, 0);
        }
        uint256 skip = seed % n;
        for (uint256 i; i < notes.length; ++i) {
            if (notes[i].live) {
                if (skip == 0) {
                    return (true, i);
                }
                skip -= 1;
            }
        }
    }

    function _pickOpenExit(uint256 seed) internal view returns (bool ok, uint256 idx) {
        uint256 n;
        for (uint256 i; i < exits.length; ++i) {
            if (!exits[i].used && notes[exits[i].noteIndex].live) {
                n += 1;
            }
        }
        if (n == 0) {
            return (false, 0);
        }
        uint256 skip = seed % n;
        for (uint256 i; i < exits.length; ++i) {
            if (!exits[i].used && notes[exits[i].noteIndex].live) {
                if (skip == 0) {
                    return (true, i);
                }
                skip -= 1;
            }
        }
    }
}

contract ProtocolInvariantsTest is Test {
    ProtocolHandler internal handler;

    function setUp() public {
        handler = new ProtocolHandler();
        targetContract(address(handler));
        bytes4[] memory selectors = new bytes4[](17);
        selectors[0] = ProtocolHandler.deposit.selector;
        selectors[1] = ProtocolHandler.transfer.selector;
        selectors[2] = ProtocolHandler.withdraw.selector;
        selectors[3] = ProtocolHandler.swapAndShield.selector;
        selectors[4] = ProtocolHandler.requestEmergencyExit.selector;
        selectors[5] = ProtocolHandler.executeEmergencyExit.selector;
        selectors[6] = ProtocolHandler.scheduleRegister.selector;
        selectors[7] = ProtocolHandler.activateRegister.selector;
        selectors[8] = ProtocolHandler.schedulePolicy.selector;
        selectors[9] = ProtocolHandler.activatePolicy.selector;
        selectors[10] = ProtocolHandler.scheduleRelease.selector;
        selectors[11] = ProtocolHandler.activateRelease.selector;
        selectors[12] = ProtocolHandler.pause.selector;
        selectors[13] = ProtocolHandler.unpause.selector;
        selectors[14] = ProtocolHandler.scheduleToken.selector;
        selectors[15] = ProtocolHandler.activateToken.selector;
        selectors[16] = ProtocolHandler.governanceDeposit.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    function testHandlerDepositIsLive() public {
        handler.deposit(1);
        assertEq(handler.conservedUsdc(), handler.initialUsdc());
    }

    function testDeterministicConservationPath() public {
        handler.deposit(1_000_000);
        handler.transfer(0);
        handler.swapAndShield(1_000_000);
        handler.requestEmergencyExit(1);
        handler.executeEmergencyExit(0);
        handler.withdraw(0);
        handler.scheduleRegister(0);
        handler.activateRegister();
        handler.schedulePolicy(0);
        handler.activatePolicy();
        handler.scheduleRelease(0);
        handler.activateRelease();
        handler.scheduleToken();
        handler.activateToken();
        handler.pause();
        handler.deposit(1);
        handler.requestEmergencyExit(0);
        handler.unpause();
        handler.governanceDeposit(1);
        assertEq(handler.conservedUsdc(), handler.initialUsdc());
        assertEq(handler.routerHasResidue(), 0);
        assertFalse(handler.governanceSpent());
    }

    function invariant_usdcConserved() public view {
        assertEq(handler.conservedUsdc(), handler.initialUsdc());
    }

    function invariant_routerHasNoResidue() public view {
        assertEq(handler.routerHasResidue(), 0);
        assertEq(handler.exitHasResidue(), 0);
    }

    function invariant_nullifiersConsumedOnce() public view {
        assertTrue(handler.nullifiersConsistent());
    }

    function invariant_rolesCannotSpendNotes() public view {
        assertFalse(handler.governanceSpent());
        assertEq(handler.roleUsdc(), 0);
    }
}
