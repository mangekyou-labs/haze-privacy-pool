// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Keccak-side protocol constants used by the T0.2 Solidity vector harness.
library HazeProtocolVectors {
    string internal constant EIP712_DOMAIN_TYPE =
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
    string internal constant INTENT_TYPE =
        "HazeIntent(bytes32 applicationId,address user,address pool,bytes32 poolVersion,uint8 action,uint256 noteTreeRoot,uint64 applicationPolicyVersion,uint64 hazePolicyVersion,uint256 applicationMembershipRoot,uint256 hazeBlocklistRoot,uint256 inputNullifier0,uint256 inputNullifier1,uint256 outputCommitment0,uint256 outputCommitment1,uint64 publicAmount,address publicRecipient,bytes32 recipientCiphertextHash0,bytes32 recipientCiphertextHash1,uint256 auditDataCommitment,bytes32 auditCiphertextHash,address tokenIn,uint256 amountIn,uint64 minUsdcOut,bytes32 routeHash,uint48 deadline)";
    string internal constant AUTH_TYPE =
        "ApplicationAuthorization(bytes32 applicationId,address user,address pool,bytes32 poolVersion,uint8 action,bytes32 intentHash,uint64 applicationPolicyVersion,uint64 hazePolicyVersion,uint256 auditDataCommitment,bytes32 auditCiphertextHash,bytes32 nonce,uint48 validAfter,uint48 validUntil)";
    string internal constant KEY_TYPE =
        "HazeKeyDerivation(address wallet,bytes32 applicationId,bytes32 poolVersion)";

    function domainTypeHash() internal pure returns (bytes32) {
        return keccak256(bytes(EIP712_DOMAIN_TYPE));
    }

    function intentTypeHash() internal pure returns (bytes32) {
        return keccak256(bytes(INTENT_TYPE));
    }

    function authorizationTypeHash() internal pure returns (bytes32) {
        return keccak256(bytes(AUTH_TYPE));
    }

    function keyDerivationTypeHash() internal pure returns (bytes32) {
        return keccak256(bytes(KEY_TYPE));
    }

    function domainTag(string memory label) internal pure returns (bytes32) {
        return keccak256(bytes(label));
    }

    function domainSeparator(
        string memory name,
        string memory version,
        uint256 chainId,
        address verifyingContract
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                domainTypeHash(),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifyingContract
            )
        );
    }

    function typedDataDigest(bytes32 separator, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(bytes2(0x1901), separator, structHash));
    }

    struct IntentFields {
        bytes32 applicationId;
        address user;
        address pool;
        bytes32 poolVersion;
        uint8 action;
        uint256 noteTreeRoot;
        uint64 applicationPolicyVersion;
        uint64 hazePolicyVersion;
        uint256 applicationMembershipRoot;
        uint256 hazeBlocklistRoot;
        uint256 inputNullifier0;
        uint256 inputNullifier1;
        uint256 outputCommitment0;
        uint256 outputCommitment1;
        uint64 publicAmount;
        address publicRecipient;
        bytes32 recipientCiphertextHash0;
        bytes32 recipientCiphertextHash1;
        uint256 auditDataCommitment;
        bytes32 auditCiphertextHash;
        address tokenIn;
        uint256 amountIn;
        uint64 minUsdcOut;
        bytes32 routeHash;
        uint48 deadline;
    }

    function intentStructHash(IntentFields memory fields) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                intentTypeHash(),
                fields.applicationId,
                fields.user,
                fields.pool,
                fields.poolVersion,
                fields.action,
                fields.noteTreeRoot,
                fields.applicationPolicyVersion,
                fields.hazePolicyVersion,
                fields.applicationMembershipRoot,
                fields.hazeBlocklistRoot,
                fields.inputNullifier0,
                fields.inputNullifier1,
                fields.outputCommitment0,
                fields.outputCommitment1,
                fields.publicAmount,
                fields.publicRecipient,
                fields.recipientCiphertextHash0,
                fields.recipientCiphertextHash1,
                fields.auditDataCommitment,
                fields.auditCiphertextHash,
                fields.tokenIn,
                fields.amountIn,
                fields.minUsdcOut,
                fields.routeHash,
                fields.deadline
            )
        );
    }

    struct AuthorizationFields {
        bytes32 applicationId;
        address user;
        address pool;
        bytes32 poolVersion;
        uint8 action;
        bytes32 intentHash;
        uint64 applicationPolicyVersion;
        uint64 hazePolicyVersion;
        uint256 auditDataCommitment;
        bytes32 auditCiphertextHash;
        bytes32 nonce;
        uint48 validAfter;
        uint48 validUntil;
    }

    function authorizationStructHash(AuthorizationFields memory fields) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                authorizationTypeHash(),
                fields.applicationId,
                fields.user,
                fields.pool,
                fields.poolVersion,
                fields.action,
                fields.intentHash,
                fields.applicationPolicyVersion,
                fields.hazePolicyVersion,
                fields.auditDataCommitment,
                fields.auditCiphertextHash,
                fields.nonce,
                fields.validAfter,
                fields.validUntil
            )
        );
    }
}
