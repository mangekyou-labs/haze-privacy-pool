// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {ApplicationRegistry} from "../src/ApplicationRegistry.sol";
import {HazePool} from "../src/HazePool.sol";
import {HazeProtocolVectors} from "../src/HazeProtocolVectors.sol";
import {PolicyRegistry} from "../src/PolicyRegistry.sol";

interface IERC20Live {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @notice Approves Circle USDC and broadcasts one development-digest HazePool.deposit on Fuji.
/// @dev Does not invent production Groth16 keys or flip SC-09.
contract DepositFujiLive is Script {
    address internal constant USDC = 0x5425890298aed601595a70AB815c96711a31Bc65;
    bytes32 internal constant APP_ID = bytes32(uint256(0xA11));
    uint64 internal constant DEFAULT_AMOUNT = 1_000_000;

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address user = vm.addr(pk);
        HazePool pool = HazePool(vm.envAddress("HAZE_POOL"));
        uint64 amount = uint64(vm.envOr("HAZE_DEPOSIT_AMOUNT", uint256(DEFAULT_AMOUNT)));
        require(block.chainid == 43113, "VERSION_UNSUPPORTED");
        require(address(pool.usdc()) == USDC, "USDC");
        require(pool.NOT_FOR_PRODUCTION(), "VERSION_UNSUPPORTED");
        require(IERC20Live(USDC).balanceOf(user) >= amount, "USDC_BALANCE");

        ApplicationRegistry.ApplicationRecord memory app = pool.applications().getApplication(APP_ID);
        require(pool.applications().isActive(APP_ID), "STATUS_INVALID");
        PolicyRegistry policies = pool.policies();

        bytes memory recipientCiphertext0 = hex"c0";
        bytes memory recipientCiphertext1 = "";
        bytes memory auditCiphertext = hex"aa";

        HazePool.TransactArgs memory args;
        args.intent.applicationId = APP_ID;
        args.intent.user = user;
        args.intent.pool = address(pool);
        args.intent.poolVersion = pool.poolVersion();
        args.intent.action = 1;
        args.intent.applicationPolicyVersion = app.membershipVersion;
        args.intent.hazePolicyVersion = policies.activeVersion();
        args.intent.applicationMembershipRoot = uint256(app.membershipRoot);
        args.intent.hazeBlocklistRoot = uint256(policies.activeRoot());
        args.intent.outputCommitment0 =
            uint256(keccak256(abi.encodePacked("haze-fuji-live-deposit", user, amount, block.timestamp)))
                % pool.SNARK_SCALAR_FIELD();
        require(args.intent.outputCommitment0 != 0, "ENCODING_INVALID");
        args.intent.publicAmount = amount;
        args.recipientCiphertext0 = recipientCiphertext0;
        args.recipientCiphertext1 = recipientCiphertext1;
        args.auditCiphertext = auditCiphertext;
        args.intent.recipientCiphertextHash0 = keccak256(recipientCiphertext0);
        args.intent.recipientCiphertextHash1 = keccak256(recipientCiphertext1);
        args.intent.auditDataCommitment = uint256(bytes32(uint256(0xAD)));
        args.intent.auditCiphertextHash = keccak256(auditCiphertext);

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
        args.authorization.nonce = keccak256(abi.encodePacked("haze-fuji-live-nonce", user, block.timestamp));
        args.authorization.validAfter = uint48(block.timestamp - 1);
        args.authorization.validUntil = uint48(block.timestamp + 1 hours);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            pk,
            HazeProtocolVectors.typedDataDigest(
                HazeProtocolVectors.domainSeparator(
                    pool.DOMAIN_NAME(), pool.DOMAIN_VERSION(), block.chainid, address(pool)
                ),
                HazeProtocolVectors.authorizationStructHash(args.authorization)
            )
        );
        args.authorizationSignature = abi.encodePacked(r, s, v);
        args.proof = abi.encodePacked(keccak256(abi.encodePacked(pool.publicInputs(args.intent))));

        vm.startBroadcast(pk);
        require(IERC20Live(USDC).approve(address(pool), amount), "approve");
        pool.deposit(args);
        vm.stopBroadcast();

        console2.log("deposit pool", address(pool));
        console2.log("deposit user", user);
        console2.log("deposit amount", amount);
    }
}
