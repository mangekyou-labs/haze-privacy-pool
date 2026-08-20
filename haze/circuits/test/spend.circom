pragma circom 2.2.2;

include "../src/spend.circom";

component main {public [protocolVersionTag, chainId, poolAddress, poolVersionHi, poolVersionLo, applicationIdHi, applicationIdLo, noteTreeRoot, applicationPolicyVersion, hazePolicyVersion, applicationMembershipRoot, hazeBlocklistRoot, inputNullifier0, inputNullifier1, outputCommitment0, outputCommitment1, action, publicAmount, publicRecipient, authorizedUser, intentHashHi, intentHashLo, recipientCiphertextHash0Hi, recipientCiphertextHash0Lo, recipientCiphertextHash1Hi, recipientCiphertextHash1Lo, auditDataCommitment, auditCiphertextHashHi, auditCiphertextHashLo]} = Spend();
