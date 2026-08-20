// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {DevelopmentEqualityVerifier} from "haze-dev/DevelopmentEqualityVerifier.sol";
import {ApplicationRegistry} from "../src/ApplicationRegistry.sol";
import {HazeAccess} from "../src/HazeAccess.sol";
import {HazePool} from "../src/HazePool.sol";
import {HazeProtocolVectors} from "../src/HazeProtocolVectors.sol";
import {HazeSpendVerifier} from "../src/HazeSpendVerifier.sol";
import {MockDex} from "../src/mocks/MockDex.sol";
import {MockSourceToken} from "../src/mocks/MockSourceToken.sol";
import {MockUsdc} from "../src/mocks/MockUsdc.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {SwapAndShieldRouter} from "../src/SwapAndShieldRouter.sol";

contract SwapAndShieldRouterTest is Test {
    uint48 internal constant MIN_DELAY = 2 days;
    uint256 internal constant ROOT_HISTORY = 4;
    uint64 internal constant SWAP_AMOUNT = 1_000_000;
    bytes32 internal constant APP_ID = bytes32(uint256(0xA11));
    bytes32 internal constant MEMBER_ROOT = bytes32(uint256(0x11));
    bytes32 internal constant BLOCK_ROOT = bytes32(uint256(0x44));
    bytes32 internal constant POOL_VERSION = bytes32(uint256(0xB001));

    HazeAccess internal access;
    ApplicationRegistry internal apps;
    PolicyRegistry internal policies;
    HazeSpendVerifier internal verifier;
    MockUsdc internal usdc;
    MockSourceToken internal source;
    MockDex internal dex;
    HazePool internal pool;
    SwapAndShieldRouter internal router;

    address internal governance;
    address internal pauseRole;
    address internal admin;
    address internal policyAuth;
    address internal user;
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
        stranger = makeAddr("stranger");
        gatekeeperPk = 0xA11CE;
        gatekeeper = vm.addr(gatekeeperPk);
        vm.warp(1_700_000_000);

        access = new HazeAccess(governance, pauseRole, MIN_DELAY);
        apps = new ApplicationRegistry(access);
        policies = new PolicyRegistry(access);
        verifier = new HazeSpendVerifier(new DevelopmentEqualityVerifier());
        usdc = new MockUsdc();
        source = new MockSourceToken();
        dex = new MockDex(address(usdc));

        address predictedRouter = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 1);
        pool = new HazePool(
            access,
            apps,
            policies,
            verifier,
            address(usdc),
            predictedRouter,
            address(0),
            POOL_VERSION,
            ROOT_HISTORY
        );

        address[] memory tokens = new address[](1);
        tokens[0] = address(source);
        address[] memory adapters = new address[](1);
        adapters[0] = address(dex);
        router = new SwapAndShieldRouter(access, pool, address(usdc), tokens, adapters);
        assertEq(address(router), predictedRouter);
        assertEq(pool.approvedRouter(), address(router));

        _registerAndActivateApp(APP_ID);
        vm.prank(governance);
        policies.schedulePolicy(1, BLOCK_ROOT, bytes32(uint256(0x55)));
        vm.warp(block.timestamp + MIN_DELAY);
        policies.activatePolicy(1);

        source.mint(user, 100_000_000);
        usdc.mint(address(dex), 100_000_000);
        vm.prank(user);
        source.approve(address(router), type(uint256).max);
    }

    function testRouteHashMatchesFrozenVector() public pure {
        assertEq(
            keccak256(abi.encode(address(1), hex"aabb")),
            bytes32(0x9576e86422a342327f8825ee310e5fd1c9f7b6e57c8e8cff95e057ba8850db7a)
        );
    }

    function testPinsImmutableRouterAndHasNoProxyOrVendorPath() public {
        assertTrue(router.NOT_FOR_PRODUCTION());
        assertEq(address(router.access()), address(access));
        assertEq(address(router.pool()), address(pool));
        assertEq(address(router.usdc()), address(usdc));
        assertTrue(router.tokenAllowed(address(source)));
        assertTrue(router.adapterAllowed(address(dex)));
        assertFalse(router.tokenAllowed(address(usdc)));
        (bool okUpgrade,) = address(router).call(abi.encodeWithSignature("upgradeTo(address)", address(1)));
        assertFalse(okUpgrade);
        (bool okInit,) = address(router).call(abi.encodeWithSignature("initialize(address)", governance));
        assertFalse(okInit);
        (bool okOwner,) = address(router).call(abi.encodeWithSignature("owner()"));
        assertFalse(okOwner);
        (bool okWithdraw,) =
            address(router).call(abi.encodeWithSignature("withdraw(address,uint256)", address(usdc), 1));
        assertFalse(okWithdraw);
    }

    function testApprovedRouteSwapsAndDepositsExactUsdcDelta() public {
        (HazePool.TransactArgs memory args, SwapAndShieldRouter.SwapRoute memory route) = _happyPath(SWAP_AMOUNT, 0xC1);
        uint256 userSourceBefore = source.balanceOf(user);
        uint256 poolUsdcBefore = usdc.balanceOf(address(pool));

        vm.expectEmit(true, true, true, true, address(pool));
        emit HazePool.PrivateTransaction(
            APP_ID,
            4,
            user,
            1,
            1,
            0,
            0,
            0,
            args.intent.outputCommitment0,
            0,
            SWAP_AMOUNT,
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
        router.swapAndShield(args, route);

        assertEq(source.balanceOf(user), userSourceBefore - SWAP_AMOUNT);
        assertEq(usdc.balanceOf(address(pool)), poolUsdcBefore + SWAP_AMOUNT);
        assertEq(source.balanceOf(address(router)), 0);
        assertEq(usdc.balanceOf(address(router)), 0);
        assertEq(source.allowance(address(router), address(dex)), 0);
        assertEq(usdc.allowance(address(router), address(pool)), 0);
        assertTrue(pool.commitmentExists(args.intent.outputCommitment0));
        assertTrue(pool.nonceUsed(APP_ID, gatekeeper, args.authorization.nonce));
    }

    function testRejectsUnallowlistedToken() public {
        MockSourceToken other = new MockSourceToken();
        other.mint(user, SWAP_AMOUNT);
        vm.prank(user);
        other.approve(address(router), SWAP_AMOUNT);

        (HazePool.TransactArgs memory args, SwapAndShieldRouter.SwapRoute memory route) = _happyPath(SWAP_AMOUNT, 0xC2);
        args.intent.tokenIn = address(other);
        _finalize(args);
        vm.prank(user);
        vm.expectRevert(bytes("TOKEN_NOT_ALLOWED"));
        router.swapAndShield(args, route);
        assertEq(other.balanceOf(user), SWAP_AMOUNT);
        assertEq(source.balanceOf(address(router)), 0);
        assertEq(usdc.balanceOf(address(router)), 0);
    }

    function testRejectsUnallowlistedAdapter() public {
        MockDex other = new MockDex(address(usdc));
        (HazePool.TransactArgs memory args,) = _happyPath(SWAP_AMOUNT, 0xC3);
        bytes memory data = _dexData(address(source), SWAP_AMOUNT, SWAP_AMOUNT, address(router));
        SwapAndShieldRouter.SwapRoute memory route = _route(address(other), data);
        args.intent.routeHash = route.expectedRouteHash;
        _finalize(args);
        vm.prank(user);
        vm.expectRevert(bytes("TOKEN_NOT_ALLOWED"));
        router.swapAndShield(args, route);
        assertEq(source.balanceOf(address(router)), 0);
        assertEq(usdc.balanceOf(address(router)), 0);
    }

    function testRejectsMismatchedCalldataHashAndRouteSubstitution() public {
        (HazePool.TransactArgs memory args, SwapAndShieldRouter.SwapRoute memory route) = _happyPath(SWAP_AMOUNT, 0xC4);
        bytes memory otherData = _dexData(address(source), SWAP_AMOUNT, 1, address(router));
        SwapAndShieldRouter.SwapRoute memory substituted = _route(address(dex), otherData);

        vm.prank(user);
        vm.expectRevert(bytes("ENCODING_INVALID"));
        router.swapAndShield(args, substituted);

        route.expectedRouteHash = bytes32(uint256(1));
        vm.prank(user);
        vm.expectRevert(bytes("ENCODING_INVALID"));
        router.swapAndShield(args, route);
        assertFalse(pool.commitmentExists(args.intent.outputCommitment0));
    }

    function testRejectsExpiredDeadlineAndOutputBelowMinUsdcOut() public {
        (HazePool.TransactArgs memory expired, SwapAndShieldRouter.SwapRoute memory route) =
            _happyPath(SWAP_AMOUNT, 0xC5);
        expired.intent.deadline = uint48(block.timestamp - 1);
        _finalize(expired);
        vm.prank(user);
        vm.expectRevert(bytes("AUTH_WINDOW"));
        router.swapAndShield(expired, route);

        (HazePool.TransactArgs memory slip, SwapAndShieldRouter.SwapRoute memory slipRoute) =
            _happyPath(SWAP_AMOUNT, 0xC6);
        slip.intent.minUsdcOut = SWAP_AMOUNT + 1;
        bytes memory data = _dexData(address(source), SWAP_AMOUNT, SWAP_AMOUNT + 1, address(router));
        slipRoute = _route(address(dex), data);
        slip.intent.routeHash = slipRoute.expectedRouteHash;
        _finalize(slip);
        vm.prank(user);
        vm.expectRevert();
        router.swapAndShield(slip, slipRoute);
        assertEq(source.balanceOf(address(router)), 0);
        assertEq(usdc.balanceOf(address(router)), 0);
        assertFalse(pool.commitmentExists(slip.intent.outputCommitment0));
    }

    function testRevertsSwapAndDepositTogetherOnProofPolicyAndAuthFailure() public {
        uint256 userSourceBefore = source.balanceOf(user);
        uint256 poolUsdcBefore = usdc.balanceOf(address(pool));

        (HazePool.TransactArgs memory badProof, SwapAndShieldRouter.SwapRoute memory route) =
            _happyPath(SWAP_AMOUNT, 0xC7);
        badProof.proof = abi.encodePacked(bytes32(uint256(1)));
        vm.prank(user);
        vm.expectRevert(bytes("ENCODING_INVALID"));
        router.swapAndShield(badProof, route);
        assertFalse(pool.nonceUsed(APP_ID, gatekeeper, badProof.authorization.nonce));
        assertFalse(pool.commitmentExists(badProof.intent.outputCommitment0));

        vm.prank(governance);
        apps.scheduleSuspend(APP_ID);
        vm.warp(block.timestamp + MIN_DELAY);
        apps.activateSuspend(APP_ID);
        (HazePool.TransactArgs memory suspended, SwapAndShieldRouter.SwapRoute memory suspendedRoute) =
            _happyPath(SWAP_AMOUNT, 0xC8);
        vm.prank(user);
        vm.expectRevert(bytes("STATUS_INVALID"));
        router.swapAndShield(suspended, suspendedRoute);

        assertEq(source.balanceOf(user), userSourceBefore);
        assertEq(usdc.balanceOf(address(pool)), poolUsdcBefore);
        assertEq(source.balanceOf(address(router)), 0);
        assertEq(usdc.balanceOf(address(router)), 0);
    }

    function testRejectsWrongActionStrangerAndUsdcSource() public {
        (HazePool.TransactArgs memory args, SwapAndShieldRouter.SwapRoute memory route) = _happyPath(SWAP_AMOUNT, 0xC9);
        args.intent.action = 1;
        args.intent.tokenIn = address(0);
        args.intent.amountIn = 0;
        args.intent.minUsdcOut = 0;
        args.intent.routeHash = bytes32(0);
        args.intent.deadline = 0;
        _finalize(args);
        vm.prank(user);
        vm.expectRevert(bytes("ENCODING_INVALID"));
        router.swapAndShield(args, route);

        (args, route) = _happyPath(SWAP_AMOUNT, 0xCA);
        vm.prank(stranger);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        router.swapAndShield(args, route);

        (args, route) = _happyPath(SWAP_AMOUNT, 0xCB);
        args.intent.tokenIn = address(usdc);
        _finalize(args);
        vm.prank(user);
        vm.expectRevert(bytes("TOKEN_NOT_ALLOWED"));
        router.swapAndShield(args, route);
    }

    function testPauseBlocksRouterAndLeavesNoResidue() public {
        (HazePool.TransactArgs memory args, SwapAndShieldRouter.SwapRoute memory route) = _happyPath(SWAP_AMOUNT, 0xCC);
        vm.prank(pauseRole);
        access.pause();
        vm.prank(user);
        vm.expectRevert(bytes("PAUSED"));
        router.swapAndShield(args, route);
        assertEq(source.balanceOf(address(router)), 0);
        assertEq(usdc.balanceOf(address(router)), 0);
    }

    function testRejectsFeeOnTransferAndRebasingSourceTokens() public {
        FeeOnTransferToken fee = new FeeOnTransferToken();
        _allowToken(address(fee));
        fee.mint(user, SWAP_AMOUNT);
        vm.prank(user);
        fee.approve(address(router), SWAP_AMOUNT);
        (HazePool.TransactArgs memory args, SwapAndShieldRouter.SwapRoute memory route) = _happyPath(SWAP_AMOUNT, 0xCD);
        args.intent.tokenIn = address(fee);
        bytes memory data = _dexData(address(fee), SWAP_AMOUNT, SWAP_AMOUNT, address(router));
        route = _route(address(dex), data);
        args.intent.routeHash = route.expectedRouteHash;
        _finalize(args);
        vm.prank(user);
        vm.expectRevert(bytes("ENCODING_INVALID"));
        router.swapAndShield(args, route);
        assertEq(fee.balanceOf(user), SWAP_AMOUNT);

        RebasingToken rebase = new RebasingToken();
        _allowToken(address(rebase));
        rebase.mint(user, SWAP_AMOUNT);
        vm.prank(user);
        rebase.approve(address(router), SWAP_AMOUNT);
        (args, route) = _happyPath(SWAP_AMOUNT, 0xCE);
        args.intent.tokenIn = address(rebase);
        data = _dexData(address(rebase), SWAP_AMOUNT, SWAP_AMOUNT, address(router));
        route = _route(address(dex), data);
        args.intent.routeHash = route.expectedRouteHash;
        _finalize(args);
        vm.prank(user);
        vm.expectRevert(bytes("ENCODING_INVALID"));
        router.swapAndShield(args, route);
        assertEq(source.balanceOf(address(router)), 0);
        assertEq(usdc.balanceOf(address(router)), 0);
    }

    function testRejectsLeftoverSourceWrongRecipientAndMissingUsdc() public {
        (HazePool.TransactArgs memory leftoverArgs,) = _happyPath(SWAP_AMOUNT, 0xCF);
        bytes memory leftoverData = _dexData(address(source), SWAP_AMOUNT - 1, SWAP_AMOUNT - 1, address(router));
        SwapAndShieldRouter.SwapRoute memory leftoverRoute = _route(address(dex), leftoverData);
        leftoverArgs.intent.routeHash = leftoverRoute.expectedRouteHash;
        leftoverArgs.intent.publicAmount = SWAP_AMOUNT;
        leftoverArgs.intent.minUsdcOut = SWAP_AMOUNT;
        leftoverArgs.intent.amountIn = SWAP_AMOUNT;
        _finalize(leftoverArgs);
        vm.prank(user);
        vm.expectRevert(bytes("ENCODING_INVALID"));
        router.swapAndShield(leftoverArgs, leftoverRoute);

        (HazePool.TransactArgs memory diverted, SwapAndShieldRouter.SwapRoute memory divertedRoute) =
            _happyPath(SWAP_AMOUNT, 0xD0);
        bytes memory toUser = _dexData(address(source), SWAP_AMOUNT, SWAP_AMOUNT, user);
        divertedRoute = _route(address(dex), toUser);
        diverted.intent.routeHash = divertedRoute.expectedRouteHash;
        _finalize(diverted);
        vm.prank(user);
        vm.expectRevert(bytes("SLIPPAGE"));
        router.swapAndShield(diverted, divertedRoute);

        NoUsdcAdapter empty = new NoUsdcAdapter(address(source));
        _allowAdapter(address(empty));
        (HazePool.TransactArgs memory none,) = _happyPath(SWAP_AMOUNT, 0xD1);
        bytes memory emptyData = abi.encodeWithSelector(NoUsdcAdapter.swapExactIn.selector, SWAP_AMOUNT);
        SwapAndShieldRouter.SwapRoute memory emptyRoute = _route(address(empty), emptyData);
        none.intent.routeHash = emptyRoute.expectedRouteHash;
        _finalize(none);
        vm.prank(user);
        vm.expectRevert(bytes("SLIPPAGE"));
        router.swapAndShield(none, emptyRoute);

        assertEq(source.balanceOf(address(router)), 0);
        assertEq(usdc.balanceOf(address(router)), 0);
        assertFalse(pool.commitmentExists(leftoverArgs.intent.outputCommitment0));
    }

    function testRejectsReentrancyAndDoesNotExposeArbitraryCalls() public {
        ReentrantAdapter attack = new ReentrantAdapter();
        _allowAdapter(address(attack));
        (HazePool.TransactArgs memory args, SwapAndShieldRouter.SwapRoute memory inner) = _happyPath(SWAP_AMOUNT, 0xD2);
        bytes memory payload = abi.encodeWithSelector(SwapAndShieldRouter.swapAndShield.selector, args, inner);
        bytes memory data = abi.encodeWithSelector(ReentrantAdapter.attack.selector, address(router), payload);
        SwapAndShieldRouter.SwapRoute memory route = _route(address(attack), data);
        args.intent.routeHash = route.expectedRouteHash;
        _finalize(args);
        payload = abi.encodeWithSelector(SwapAndShieldRouter.swapAndShield.selector, args, inner);
        data = abi.encodeWithSelector(ReentrantAdapter.attack.selector, address(router), payload);
        route = _route(address(attack), data);
        args.intent.routeHash = route.expectedRouteHash;
        _finalize(args);

        vm.prank(user);
        vm.expectRevert(bytes("REENTRANCY"));
        router.swapAndShield(args, route);

        (bool okDelegate,) = address(router).call(abi.encodeWithSignature("delegatecall(address,bytes)", address(dex), ""));
        assertFalse(okDelegate);
    }

    function testTokenAndAdapterAllowlistChangesAreTimelocked() public {
        MockSourceToken extra = new MockSourceToken();
        assertFalse(router.tokenAllowed(address(extra)));
        vm.prank(stranger);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        router.scheduleToken(address(extra), true);

        vm.prank(governance);
        router.scheduleToken(address(extra), true);
        assertFalse(router.tokenAllowed(address(extra)));
        vm.expectRevert(bytes("TIMELOCK"));
        router.activateToken();
        vm.warp(block.timestamp + MIN_DELAY);
        router.activateToken();
        assertTrue(router.tokenAllowed(address(extra)));

        vm.prank(governance);
        router.scheduleToken(address(source), false);
        assertTrue(router.tokenAllowed(address(source)));
        vm.warp(block.timestamp + MIN_DELAY);
        router.activateToken();
        assertFalse(router.tokenAllowed(address(source)));

        MockDex extraDex = new MockDex(address(usdc));
        vm.prank(governance);
        router.scheduleAdapter(address(extraDex), true);
        assertFalse(router.adapterAllowed(address(extraDex)));
        vm.warp(block.timestamp + MIN_DELAY);
        router.activateAdapter();
        assertTrue(router.adapterAllowed(address(extraDex)));
    }

    function testGovernanceCannotSpendUserNotesThroughRouter() public {
        (HazePool.TransactArgs memory args, SwapAndShieldRouter.SwapRoute memory route) = _happyPath(SWAP_AMOUNT, 0xD3);
        vm.prank(user);
        router.swapAndShield(args, route);

        vm.prank(governance);
        vm.expectRevert(bytes("UNAUTHORIZED"));
        pool.depositFromRouter(user, args);
        (bool okSkim,) = address(router).call(abi.encodeWithSignature("skim(address)", address(usdc)));
        assertFalse(okSkim);
        assertTrue(pool.commitmentExists(args.intent.outputCommitment0));
    }

    function testFuzzSuccessfulRouteLeavesNoResidue(uint64 amount) public {
        amount = uint64(bound(amount, 1, 10_000_000));
        source.mint(user, amount);
        usdc.mint(address(dex), amount);
        (HazePool.TransactArgs memory args, SwapAndShieldRouter.SwapRoute memory route) = _happyPath(amount, amount);
        uint256 userSourceBefore = source.balanceOf(user);
        uint256 poolUsdcBefore = usdc.balanceOf(address(pool));
        vm.prank(user);
        router.swapAndShield(args, route);
        assertEq(source.balanceOf(user), userSourceBefore - amount);
        assertEq(usdc.balanceOf(address(pool)), poolUsdcBefore + amount);
        assertEq(source.balanceOf(address(router)), 0);
        assertEq(usdc.balanceOf(address(router)), 0);
        assertEq(source.allowance(address(router), address(dex)), 0);
        assertEq(usdc.allowance(address(router), address(pool)), 0);
    }

    function testFuzzUnallowlistedTokenReverts(address token) public {
        vm.assume(token != address(source) && token != address(0) && token.code.length == 0);
        (HazePool.TransactArgs memory args, SwapAndShieldRouter.SwapRoute memory route) = _happyPath(SWAP_AMOUNT, 0xD4);
        args.intent.tokenIn = token;
        _finalize(args);
        vm.prank(user);
        vm.expectRevert(bytes("TOKEN_NOT_ALLOWED"));
        router.swapAndShield(args, route);
        assertEq(source.balanceOf(address(router)), 0);
        assertEq(usdc.balanceOf(address(router)), 0);
    }

    function testFuzzUnallowlistedAdapterReverts(address adapter) public {
        vm.assume(adapter != address(dex) && adapter != address(0) && adapter.code.length == 0);
        (HazePool.TransactArgs memory args,) = _happyPath(SWAP_AMOUNT, 0xD5);
        bytes memory data = _dexData(address(source), SWAP_AMOUNT, SWAP_AMOUNT, address(router));
        SwapAndShieldRouter.SwapRoute memory route = _route(adapter, data);
        args.intent.routeHash = route.expectedRouteHash;
        _finalize(args);
        vm.prank(user);
        vm.expectRevert(bytes("TOKEN_NOT_ALLOWED"));
        router.swapAndShield(args, route);
    }

    function _happyPath(uint64 amount, uint256 commitmentSeed)
        internal
        returns (HazePool.TransactArgs memory args, SwapAndShieldRouter.SwapRoute memory route)
    {
        bytes memory data = _dexData(address(source), amount, amount, address(router));
        route = _route(address(dex), data);
        args.intent = _baseIntent(APP_ID, user, 4);
        args.intent.outputCommitment0 = uint256(bytes32(commitmentSeed == 0 ? uint256(0xC1) : commitmentSeed));
        args.intent.publicAmount = amount;
        args.intent.tokenIn = address(source);
        args.intent.amountIn = amount;
        args.intent.minUsdcOut = amount;
        args.intent.routeHash = route.expectedRouteHash;
        args.intent.deadline = uint48(vm.getBlockTimestamp() + 60);
        args.recipientCiphertext0 = hex"c0";
        args.recipientCiphertext1 = "";
        args.auditCiphertext = hex"aa";
        args.intent.recipientCiphertextHash0 = keccak256(args.recipientCiphertext0);
        args.intent.recipientCiphertextHash1 = keccak256(args.recipientCiphertext1);
        args.intent.auditDataCommitment = uint256(bytes32(uint256(0xAD)));
        args.intent.auditCiphertextHash = keccak256(args.auditCiphertext);
        _finalize(args);
    }

    function _route(address adapter, bytes memory data)
        internal
        pure
        returns (SwapAndShieldRouter.SwapRoute memory route)
    {
        route.adapter = adapter;
        route.data = data;
        route.expectedRouteHash = keccak256(abi.encode(adapter, data));
    }

    function _dexData(address tokenIn, uint256 amountIn, uint256 minUsdcOut, address recipient)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSelector(MockDex.swapExactIn.selector, tokenIn, amountIn, minUsdcOut, recipient);
    }

    function _allowToken(address token) internal {
        vm.prank(governance);
        router.scheduleToken(token, true);
        vm.warp(block.timestamp + MIN_DELAY);
        router.activateToken();
    }

    function _allowAdapter(address adapter) internal {
        vm.prank(governance);
        router.scheduleAdapter(adapter, true);
        vm.warp(block.timestamp + MIN_DELAY);
        router.activateAdapter();
    }

    function _registerAndActivateApp(bytes32 applicationId) internal {
        vm.prank(governance);
        apps.scheduleRegister(
            ApplicationRegistry.RegisterParams({
                applicationId: applicationId,
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
        apps.activateRegister(applicationId);
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
            nonceSeed += 1;
            args.authorization.nonce = bytes32(nonceSeed);
        }
        args.authorization.validAfter = uint48(vm.getBlockTimestamp() - 1);
        args.authorization.validUntil = uint48(vm.getBlockTimestamp() + 1 hours);
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

contract FeeOnTransferToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        return _move(msg.sender, to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        return _move(from, to, amount);
    }

    function _move(address from, address to, uint256 amount) internal returns (bool) {
        require(amount > 0, "amount");
        balanceOf[from] -= amount;
        balanceOf[to] += amount - 1;
        return true;
    }
}

contract RebasingToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        return _move(msg.sender, to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        return _move(from, to, amount);
    }

    function _move(address from, address to, uint256 amount) internal returns (bool) {
        balanceOf[from] -= amount;
        balanceOf[to] += amount + 1;
        return true;
    }
}

contract NoUsdcAdapter {
    MockSourceToken public immutable token;

    constructor(address token_) {
        token = MockSourceToken(token_);
    }

    function swapExactIn(uint256 amountIn) external {
        require(token.transferFrom(msg.sender, address(this), amountIn), "in");
    }
}

contract ReentrantAdapter {
    function attack(address target, bytes calldata payload) external {
        (bool ok, bytes memory ret) = target.call(payload);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 32), mload(ret))
            }
        }
    }
}
