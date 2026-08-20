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
import {MockDex} from "../src/mocks/MockDex.sol";
import {MockSourceToken} from "../src/mocks/MockSourceToken.sol";
import {MockUsdc} from "../src/mocks/MockUsdc.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";
import {SwapAndShieldRouter} from "../src/SwapAndShieldRouter.sol";
import {VersionRegistry} from "../src/VersionRegistry.sol";

/// @dev Shared local stack for T2.6 invariant handlers and gas snapshots.
abstract contract HazeProtocolFixture is Test {
    uint48 internal constant MIN_DELAY = 2 days;
    uint256 internal constant ROOT_HISTORY = 4;
    uint64 internal constant DEPOSIT_AMOUNT = 1_000_000;
    uint256 internal constant COOLDOWN = 7 days;
    bytes32 internal constant APP_ID = bytes32(uint256(0xA11));
    bytes32 internal constant MEMBER_ROOT = bytes32(uint256(0x11));
    bytes32 internal constant BLOCK_ROOT = bytes32(uint256(0x44));
    bytes32 internal constant POOL_VERSION = bytes32(uint256(0xB001));

    HazeAccess internal access;
    ApplicationRegistry internal apps;
    PolicyRegistry internal policies;
    VersionRegistry internal versions;
    HazeSpendVerifier internal verifier;
    MockUsdc internal usdc;
    MockSourceToken internal source;
    MockSourceToken internal extraToken;
    MockDex internal dex;
    HazePool internal pool;
    SwapAndShieldRouter internal router;
    EmergencyExit internal exitContract;

    address internal governance;
    address internal pauseRole;
    address internal admin;
    address internal policyAuth;
    address internal user;
    address internal recipient;

    uint256 internal gatekeeperPk;
    address internal gatekeeper;
    uint256 internal nonceSeed;
    uint256 public initialUsdc;

    function setUpProtocol() internal {
        governance = makeAddr("governance");
        pauseRole = makeAddr("pause");
        admin = makeAddr("admin");
        policyAuth = makeAddr("policyAuth");
        user = makeAddr("user");
        recipient = makeAddr("recipient");
        gatekeeperPk = 0xA11CE;
        gatekeeper = vm.addr(gatekeeperPk);
        vm.warp(1_700_000_000);

        access = new HazeAccess(governance, pauseRole, MIN_DELAY);
        apps = new ApplicationRegistry(access);
        policies = new PolicyRegistry(access);
        versions = new VersionRegistry(access);
        verifier = new HazeSpendVerifier(new DevelopmentEqualityVerifier());
        usdc = new MockUsdc();
        source = new MockSourceToken();
        extraToken = new MockSourceToken();
        dex = new MockDex(address(usdc));

        uint64 nonce = vm.getNonce(address(this));
        address predictedRouter = vm.computeCreateAddress(address(this), nonce + 1);
        address predictedExit = vm.computeCreateAddress(address(this), nonce + 2);
        pool = new HazePool(
            access,
            apps,
            policies,
            verifier,
            address(usdc),
            predictedRouter,
            predictedExit,
            POOL_VERSION,
            ROOT_HISTORY
        );

        address[] memory tokens = new address[](1);
        tokens[0] = address(source);
        address[] memory adapters = new address[](1);
        adapters[0] = address(dex);
        router = new SwapAndShieldRouter(access, pool, address(usdc), tokens, adapters);
        exitContract = new EmergencyExit(access, pool, versions, policies);
        require(address(router) == predictedRouter, "router");
        require(address(exitContract) == predictedExit, "exit");

        vm.prank(governance);
        apps.scheduleRegister(_registerArgs(APP_ID));
        vm.warp(vm.getBlockTimestamp() + MIN_DELAY);
        apps.activateRegister(APP_ID);
        vm.prank(governance);
        policies.schedulePolicy(1, BLOCK_ROOT, bytes32(uint256(0x55)));
        vm.warp(vm.getBlockTimestamp() + MIN_DELAY);
        policies.activatePolicy(1);

        usdc.mint(user, 50_000_000);
        usdc.mint(address(dex), 100_000_000);
        source.mint(user, 100_000_000);
        extraToken.mint(user, 1_000_000);
        vm.prank(user);
        usdc.approve(address(pool), type(uint256).max);
        vm.prank(user);
        source.approve(address(router), type(uint256).max);
        vm.prank(user);
        extraToken.approve(address(router), type(uint256).max);

        initialUsdc = _sumUsdc();
    }

    function _sumUsdc() internal view returns (uint256) {
        return usdc.balanceOf(user) + usdc.balanceOf(recipient) + usdc.balanceOf(address(dex))
            + usdc.balanceOf(address(pool)) + usdc.balanceOf(address(router)) + usdc.balanceOf(address(exitContract))
            + usdc.balanceOf(governance) + usdc.balanceOf(pauseRole) + usdc.balanceOf(admin) + usdc.balanceOf(address(this));
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

    function _depositArgs(address account, uint64 amount, bytes32 cm0)
        internal
        returns (HazePool.TransactArgs memory args)
    {
        args.intent = _baseIntent(APP_ID, account, 1);
        args.intent.outputCommitment0 = uint256(cm0);
        args.intent.publicAmount = amount;
        args.recipientCiphertext0 = hex"c0";
        args.recipientCiphertext1 = "";
        args.auditCiphertext = hex"aa";
        args.intent.recipientCiphertextHash0 = keccak256(args.recipientCiphertext0);
        args.intent.recipientCiphertextHash1 = keccak256(args.recipientCiphertext1);
        args.intent.auditDataCommitment = uint256(bytes32(uint256(0xAD)));
        args.intent.auditCiphertextHash = keccak256(args.auditCiphertext);
        _finalize(args);
    }

    function _transferArgs(address account, uint256 root, uint256 nf0, bytes32 cm0)
        internal
        returns (HazePool.TransactArgs memory args)
    {
        args.intent = _baseIntent(APP_ID, account, 2);
        args.intent.noteTreeRoot = root;
        args.intent.inputNullifier0 = nf0;
        args.intent.outputCommitment0 = uint256(cm0);
        args.recipientCiphertext0 = hex"c0";
        args.recipientCiphertext1 = "";
        args.auditCiphertext = hex"aa";
        args.intent.recipientCiphertextHash0 = keccak256(args.recipientCiphertext0);
        args.intent.recipientCiphertextHash1 = keccak256(args.recipientCiphertext1);
        args.intent.auditDataCommitment = uint256(bytes32(uint256(0xAD)));
        args.intent.auditCiphertextHash = keccak256(args.auditCiphertext);
        _finalize(args);
    }

    function _withdrawArgs(address account, uint256 root, uint64 amount, address to, uint256 nf0)
        internal
        returns (HazePool.TransactArgs memory args)
    {
        args.intent = _baseIntent(APP_ID, account, 3);
        args.intent.noteTreeRoot = root;
        args.intent.inputNullifier0 = nf0;
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

    function _swapArgs(address account, uint64 amount, bytes32 cm0, bytes32 routeHash)
        internal
        returns (HazePool.TransactArgs memory args)
    {
        args.intent = _baseIntent(APP_ID, account, 4);
        args.intent.outputCommitment0 = uint256(cm0);
        args.intent.publicAmount = amount;
        args.intent.tokenIn = address(source);
        args.intent.amountIn = amount;
        args.intent.minUsdcOut = amount;
        args.intent.routeHash = routeHash;
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

    function _dexData(address tokenIn, uint256 amountIn, uint256 minUsdcOut, address to)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSelector(MockDex.swapExactIn.selector, tokenIn, amountIn, minUsdcOut, to);
    }

    function _requestId(uint256 nf, address to, bytes32 salt) internal view returns (bytes32) {
        return exitContract.requestId(
            block.chainid, address(pool), POOL_VERSION, APP_ID, nf, to, salt
        );
    }

    function _exitArgs(uint256 nf, uint64 amount, address to, bytes32 salt)
        internal
        view
        returns (EmergencyExit.ExecuteArgs memory args)
    {
        args.applicationId = APP_ID;
        args.noteTreeRoot = pool.currentRoot();
        args.hazePolicyVersion = policies.activeVersion();
        args.hazeBlocklistRoot = uint256(policies.activeRoot());
        args.nullifier = nf;
        args.publicAmount = amount;
        args.recipient = to;
        args.requester = user;
        args.requestSalt = salt;
        args.auditCiphertext = hex"aa";
        args.auditDataCommitment = uint256(bytes32(uint256(0xAD)));
        args.auditCiphertextHash = keccak256(args.auditCiphertext);
        args.proof = abi.encodePacked(keccak256(abi.encodePacked(exitContract.publicInputs(args))));
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
