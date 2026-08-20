// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {EmergencyExit} from "../src/EmergencyExit.sol";
import {HazePool} from "../src/HazePool.sol";
import {HazeProtocolFixture} from "./HazeProtocolFixture.sol";
import {SwapAndShieldRouter} from "../src/SwapAndShieldRouter.sol";

contract GasBudgetsTest is HazeProtocolFixture {
    function setUp() public {
        setUpProtocol();
    }

    function testGasReportCoversEveryUserAndGovernanceAction() public {
        string memory path = string.concat(vm.projectRoot(), "/../dev/artifacts/haze-gas-v1.json");
        string memory raw = vm.readFile(path);
        require(bytes(raw).length != 0, "GAS_REPORT");

        uint256 verifyUsed = _measureVerify();
        uint256 depositUsed = _measureDeposit();
        uint256 transferUsed = _measureTransfer();
        uint256 withdrawUsed = _measureWithdraw();
        uint256 swapUsed = _measureSwap();
        uint256 requestUsed = _measureRequest();
        uint256 executeUsed = _measureExecute();
        uint256 scheduleRegisterUsed = _measureScheduleRegister();
        uint256 activateRegisterUsed = _measureActivateRegister();
        uint256 schedulePolicyUsed = _measureSchedulePolicy();
        uint256 activatePolicyUsed = _measureActivatePolicy();
        uint256 scheduleReleaseUsed = _measureScheduleRelease();
        uint256 activateReleaseUsed = _measureActivateRelease();
        uint256 pauseUsed = _measurePause();
        uint256 unpauseUsed = _measureUnpause();
        uint256 scheduleTokenUsed = _measureScheduleToken();
        uint256 activateTokenUsed = _measureActivateToken();

        emit log_named_uint("gas.verify", verifyUsed);
        emit log_named_uint("gas.deposit", depositUsed);
        emit log_named_uint("gas.transfer", transferUsed);
        emit log_named_uint("gas.withdraw", withdrawUsed);
        emit log_named_uint("gas.swapAndShield", swapUsed);
        emit log_named_uint("gas.requestEmergencyExit", requestUsed);
        emit log_named_uint("gas.executeEmergencyExit", executeUsed);
        emit log_named_uint("gas.scheduleRegister", scheduleRegisterUsed);
        emit log_named_uint("gas.activateRegister", activateRegisterUsed);
        emit log_named_uint("gas.schedulePolicy", schedulePolicyUsed);
        emit log_named_uint("gas.activatePolicy", activatePolicyUsed);
        emit log_named_uint("gas.scheduleRelease", scheduleReleaseUsed);
        emit log_named_uint("gas.activateRelease", activateReleaseUsed);
        emit log_named_uint("gas.pause", pauseUsed);
        emit log_named_uint("gas.unpause", unpauseUsed);
        emit log_named_uint("gas.scheduleToken", scheduleTokenUsed);
        emit log_named_uint("gas.activateToken", activateTokenUsed);

        _assertAction(raw, "verify", verifyUsed);
        _assertAction(raw, "deposit", depositUsed);
        _assertAction(raw, "transfer", transferUsed);
        _assertAction(raw, "withdraw", withdrawUsed);
        _assertAction(raw, "swapAndShield", swapUsed);
        _assertAction(raw, "requestEmergencyExit", requestUsed);
        _assertAction(raw, "executeEmergencyExit", executeUsed);
        _assertAction(raw, "scheduleRegister", scheduleRegisterUsed);
        _assertAction(raw, "activateRegister", activateRegisterUsed);
        _assertAction(raw, "schedulePolicy", schedulePolicyUsed);
        _assertAction(raw, "activatePolicy", activatePolicyUsed);
        _assertAction(raw, "scheduleRelease", scheduleReleaseUsed);
        _assertAction(raw, "activateRelease", activateReleaseUsed);
        _assertAction(raw, "pause", pauseUsed);
        _assertAction(raw, "unpause", unpauseUsed);
        _assertAction(raw, "scheduleToken", scheduleTokenUsed);
        _assertAction(raw, "activateToken", activateTokenUsed);
    }

    function _assertAction(string memory raw, string memory action, uint256 used) internal pure {
        uint256 measured = vm.parseJsonUint(raw, string.concat(".actions.", action, ".measured"));
        uint256 budget = vm.parseJsonUint(raw, string.concat(".actions.", action, ".budget"));
        require(used > 0, "measured");
        require(budget >= measured, "budget");
        require(used <= budget, "over");
        uint256 delta = used > measured ? used - measured : measured - used;
        require(delta <= 64, "pin");
    }

    function _measureVerify() internal returns (uint256 used) {
        HazePool.TransactArgs memory args = _depositArgs(user, DEPOSIT_AMOUNT, bytes32(uint256(0xC100)));
        uint256[29] memory inputs = pool.publicInputs(args.intent);
        uint256 start = gasleft();
        verifier.verify(inputs, args.proof, verifier.SPEND_ARTIFACT_HASH(), false);
        used = start - gasleft();
    }

    function _measureDeposit() internal returns (uint256 used) {
        HazePool.TransactArgs memory args = _depositArgs(user, DEPOSIT_AMOUNT, bytes32(uint256(0xC101)));
        uint256 start = gasleft();
        vm.prank(user);
        pool.deposit(args);
        used = start - gasleft();
    }

    function _measureTransfer() internal returns (uint256 used) {
        HazePool.TransactArgs memory args =
            _transferArgs(user, pool.currentRoot(), uint256(bytes32(uint256(0xE101))), bytes32(uint256(0xC102)));
        uint256 start = gasleft();
        vm.prank(user);
        pool.transact(args);
        used = start - gasleft();
    }

    function _measureWithdraw() internal returns (uint256 used) {
        HazePool.TransactArgs memory funded = _depositArgs(user, DEPOSIT_AMOUNT, bytes32(uint256(0xC103)));
        vm.prank(user);
        pool.deposit(funded);
        HazePool.TransactArgs memory args = _withdrawArgs(
            user, pool.currentRoot(), DEPOSIT_AMOUNT, recipient, uint256(bytes32(uint256(0xE103)))
        );
        uint256 start = gasleft();
        vm.prank(user);
        pool.transact(args);
        used = start - gasleft();
    }

    function _measureSwap() internal returns (uint256 used) {
        bytes memory data = _dexData(address(source), DEPOSIT_AMOUNT, DEPOSIT_AMOUNT, address(router));
        SwapAndShieldRouter.SwapRoute memory route = _route(address(dex), data);
        HazePool.TransactArgs memory args =
            _swapArgs(user, DEPOSIT_AMOUNT, bytes32(uint256(0xC104)), route.expectedRouteHash);
        uint256 start = gasleft();
        vm.prank(user);
        router.swapAndShield(args, route);
        used = start - gasleft();
    }

    function _measureRequest() internal returns (uint256 used) {
        bytes32 id = _requestId(uint256(bytes32(uint256(0xE104))), recipient, bytes32(uint256(0x51)));
        uint256 start = gasleft();
        exitContract.requestEmergencyExit(id);
        used = start - gasleft();
    }

    function _measureExecute() internal returns (uint256 used) {
        HazePool.TransactArgs memory funded = _depositArgs(user, DEPOSIT_AMOUNT, bytes32(uint256(0xC105)));
        vm.prank(user);
        pool.deposit(funded);
        bytes32 salt = bytes32(uint256(0x52));
        uint256 nf = uint256(bytes32(uint256(0xE105)));
        bytes32 id = _requestId(nf, recipient, salt);
        exitContract.requestEmergencyExit(id);
        vm.warp(vm.getBlockTimestamp() + COOLDOWN);
        EmergencyExit.ExecuteArgs memory args = _exitArgs(nf, DEPOSIT_AMOUNT, recipient, salt);
        uint256 start = gasleft();
        exitContract.executeEmergencyExit(args);
        used = start - gasleft();
    }

    function _measureScheduleRegister() internal returns (uint256 used) {
        bytes32 applicationId = bytes32(uint256(0xB101));
        uint256 start = gasleft();
        vm.prank(governance);
        apps.scheduleRegister(_registerArgs(applicationId));
        used = start - gasleft();
    }

    function _measureActivateRegister() internal returns (uint256 used) {
        bytes32 applicationId = bytes32(uint256(0xB102));
        vm.prank(governance);
        apps.scheduleRegister(_registerArgs(applicationId));
        vm.warp(vm.getBlockTimestamp() + MIN_DELAY);
        uint256 start = gasleft();
        apps.activateRegister(applicationId);
        used = start - gasleft();
    }

    function _measureSchedulePolicy() internal returns (uint256 used) {
        uint256 start = gasleft();
        vm.prank(governance);
        policies.schedulePolicy(2, bytes32(uint256(0x46)), bytes32(uint256(0x56)));
        used = start - gasleft();
    }

    function _measureActivatePolicy() internal returns (uint256 used) {
        vm.prank(governance);
        policies.schedulePolicy(3, bytes32(uint256(0x47)), bytes32(uint256(0x57)));
        vm.warp(vm.getBlockTimestamp() + MIN_DELAY);
        uint256 start = gasleft();
        policies.activatePolicy(3);
        used = start - gasleft();
    }

    function _measureScheduleRelease() internal returns (uint256 used) {
        uint256 start = gasleft();
        vm.prank(governance);
        versions.scheduleRelease(bytes32(uint256(0xC101)), bytes32(uint256(0xD101)), "ipfs://rel", 0);
        used = start - gasleft();
    }

    function _measureActivateRelease() internal returns (uint256 used) {
        vm.prank(governance);
        versions.scheduleRelease(bytes32(uint256(0xC102)), bytes32(uint256(0xD102)), "ipfs://rel2", 0);
        vm.warp(vm.getBlockTimestamp() + MIN_DELAY);
        uint256 start = gasleft();
        versions.activateRelease(bytes32(uint256(0xC102)));
        used = start - gasleft();
    }

    function _measurePause() internal returns (uint256 used) {
        uint256 start = gasleft();
        vm.prank(pauseRole);
        access.pause();
        used = start - gasleft();
    }

    function _measureUnpause() internal returns (uint256 used) {
        if (!access.paused()) {
            vm.prank(pauseRole);
            access.pause();
        }
        uint256 start = gasleft();
        vm.prank(pauseRole);
        access.unpause();
        used = start - gasleft();
    }

    function _measureScheduleToken() internal returns (uint256 used) {
        uint256 start = gasleft();
        vm.prank(governance);
        router.scheduleToken(address(extraToken), true);
        used = start - gasleft();
    }

    function _measureActivateToken() internal returns (uint256 used) {
        if (!router.tokenScheduled()) {
            vm.prank(governance);
            router.scheduleToken(address(extraToken), true);
        }
        vm.warp(vm.getBlockTimestamp() + MIN_DELAY);
        uint256 start = gasleft();
        router.activateToken();
        used = start - gasleft();
    }
}
