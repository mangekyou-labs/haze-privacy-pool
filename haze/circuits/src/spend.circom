pragma circom 2.2.2;

include "poseidon2/domains.circom";
include "poseidon2/poseidon2_sponge.circom";
include "gadgets/bits.circom";
include "gadgets/compare.circom";
include "gadgets/note.circom";
include "gadgets/policy.circom";
include "gadgets/merkle.circom";
include "gadgets/audit.circom";

// Versioned 2-in/2-out normal spend. Actions 1 DEPOSIT, 2 TRANSFER, 3 WITHDRAW,
// 4 SWAP_AND_SHIELD. Action 5 is a separate emergency circuit.
template Spend() {
    var DEPTH = 32;

    signal input protocolVersionTag;
    signal input chainId;
    signal input poolAddress;
    signal input poolVersionHi;
    signal input poolVersionLo;
    signal input applicationIdHi;
    signal input applicationIdLo;
    signal input noteTreeRoot;
    signal input applicationPolicyVersion;
    signal input hazePolicyVersion;
    signal input applicationMembershipRoot;
    signal input hazeBlocklistRoot;
    signal input inputNullifier0;
    signal input inputNullifier1;
    signal input outputCommitment0;
    signal input outputCommitment1;
    signal input action;
    signal input publicAmount;
    signal input publicRecipient;
    signal input authorizedUser;
    signal input intentHashHi;
    signal input intentHashLo;
    signal input recipientCiphertextHash0Hi;
    signal input recipientCiphertextHash0Lo;
    signal input recipientCiphertextHash1Hi;
    signal input recipientCiphertextHash1Lo;
    signal input auditDataCommitment;
    signal input auditCiphertextHashHi;
    signal input auditCiphertextHashLo;

    signal input usdcAddress;
    signal input actionReferenceHi;
    signal input actionReferenceLo;
    signal input auditSalt;

    signal input inValue[2];
    signal input inSpendingSecret[2];
    signal input inBlinding[2];
    signal input inX25519Hi[2];
    signal input inX25519Lo[2];
    signal input inLeafIndex[2];
    signal input inNoteSiblings[2][32];
    signal input inAppMemberIndex[2];
    signal input inAppMemberSiblings[2][32];
    signal input inBlockLowerIndex[2];
    signal input inBlockLowerLeaf[2];
    signal input inBlockUpperLeaf[2];
    signal input inBlockLowerSiblings[2][32];
    signal input inBlockUpperSiblings[2][32];

    signal input outValue[2];
    signal input outSpendingSecret[2];
    signal input outBlinding[2];
    signal input outX25519Hi[2];
    signal input outX25519Lo[2];
    signal input outAppMemberIndex[2];
    signal input outAppMemberSiblings[2][32];
    signal input outBlockLowerIndex[2];
    signal input outBlockLowerLeaf[2];
    signal input outBlockUpperLeaf[2];
    signal input outBlockLowerSiblings[2][32];
    signal input outBlockUpperSiblings[2][32];

    signal input addressLowerIndex;
    signal input addressLowerLeaf;
    signal input addressUpperLeaf;
    signal input addressLowerSiblings[32];
    signal input addressUpperSiblings[32];

    protocolVersionTag === DOMAIN_PROTOCOL();

    component chainBits = RangeBits(64);
    chainBits.in <== chainId;
    component poolBits = RangeBits(160);
    poolBits.in <== poolAddress;
    component versionHiBits = RangeBits(128);
    versionHiBits.in <== poolVersionHi;
    component versionLoBits = RangeBits(128);
    versionLoBits.in <== poolVersionLo;
    component appHiBits = RangeBits(128);
    appHiBits.in <== applicationIdHi;
    component appLoBits = RangeBits(128);
    appLoBits.in <== applicationIdLo;
    component appPolBits = RangeBits(64);
    appPolBits.in <== applicationPolicyVersion;
    component hazePolBits = RangeBits(64);
    hazePolBits.in <== hazePolicyVersion;
    component amountBits = RangeBits(64);
    amountBits.in <== publicAmount;
    component recipientBits = RangeBits(160);
    recipientBits.in <== publicRecipient;
    component userBits = RangeBits(160);
    userBits.in <== authorizedUser;
    component usdcBits = RangeBits(160);
    usdcBits.in <== usdcAddress;
    component intentHiBits = RangeBits(128);
    intentHiBits.in <== intentHashHi;
    component intentLoBits = RangeBits(128);
    intentLoBits.in <== intentHashLo;
    component rc0HiBits = RangeBits(128);
    rc0HiBits.in <== recipientCiphertextHash0Hi;
    component rc0LoBits = RangeBits(128);
    rc0LoBits.in <== recipientCiphertextHash0Lo;
    component rc1HiBits = RangeBits(128);
    rc1HiBits.in <== recipientCiphertextHash1Hi;
    component rc1LoBits = RangeBits(128);
    rc1LoBits.in <== recipientCiphertextHash1Lo;
    component auditHiBits = RangeBits(128);
    auditHiBits.in <== auditCiphertextHashHi;
    component auditLoBits = RangeBits(128);
    auditLoBits.in <== auditCiphertextHashLo;
    component refHiBits = RangeBits(128);
    refHiBits.in <== actionReferenceHi;
    component refLoBits = RangeBits(128);
    refLoBits.in <== actionReferenceLo;

    component userZero = IsZero();
    userZero.in <== authorizedUser;
    userZero.out === 0;

    component isDeposit = IsEqual();
    isDeposit.a <== action;
    isDeposit.b <== 1;
    component isTransfer = IsEqual();
    isTransfer.a <== action;
    isTransfer.b <== 2;
    component isWithdraw = IsEqual();
    isWithdraw.a <== action;
    isWithdraw.b <== 3;
    component isSwap = IsEqual();
    isSwap.a <== action;
    isSwap.b <== 4;
    isDeposit.out + isTransfer.out + isWithdraw.out + isSwap.out === 1;
    signal isDepositLike;
    isDepositLike <== isDeposit.out + isSwap.out;

    component poolDom = Poseidon2Sponge(5);
    poolDom.domain <== DOMAIN_POOL();
    poolDom.in[0] <== protocolVersionTag;
    poolDom.in[1] <== chainId;
    poolDom.in[2] <== poolAddress;
    poolDom.in[3] <== poolVersionHi;
    poolDom.in[4] <== poolVersionLo;

    component inEnable[2];
    component inValueBits[2];
    component inNpk[2];
    component inEnc[2];
    component inCommit[2];
    component inNull[2];
    component inIndexBits[2];
    component inNotePath[2];
    component inMember[2];
    component inMemberIndexBits[2];
    component inMemberPath[2];
    component inBlocked[2];
    component inNm[2];
    signal inDummySecret[2];
    signal inDummyBlinding[2];
    signal inPublicNf[2];
    signal inAuditNpk[2];
    signal inAuditEnc[2];

    for (var i = 0; i < 2; i++) {
        inEnable[i] = SlotEnable();
        inEnable[i].value <== inValue[i];
        inValueBits[i] = RangeBits(64);
        inValueBits[i].in <== inValue[i];
        isDepositLike * inValue[i] === 0;

        inDummySecret[i] <== inSpendingSecret[i] + (1 - inEnable[i].enabled);
        inDummyBlinding[i] <== inBlinding[i] + (1 - inEnable[i].enabled);
        (1 - inEnable[i].enabled) * inSpendingSecret[i] === 0;
        (1 - inEnable[i].enabled) * inBlinding[i] === 0;
        (1 - inEnable[i].enabled) * inX25519Hi[i] === 0;
        (1 - inEnable[i].enabled) * inX25519Lo[i] === 0;
        (1 - inEnable[i].enabled) * inLeafIndex[i] === 0;
        (1 - inEnable[i].enabled) * inAppMemberIndex[i] === 0;

        inNpk[i] = NotePublicKey();
        inNpk[i].domain <== DOMAIN_NOTE_KEY();
        inNpk[i].spendingSecret <== inDummySecret[i];

        inEnc[i] = EncryptionKeyHash();
        inEnc[i].domain <== DOMAIN_ENCRYPTION_KEY();
        inEnc[i].x25519Hi <== inX25519Hi[i];
        inEnc[i].x25519Lo <== inX25519Lo[i];

        inCommit[i] = NoteCommitment();
        inCommit[i].domain <== DOMAIN_NOTE();
        inCommit[i].poolDomain <== poolDom.out;
        inCommit[i].applicationIdHi <== applicationIdHi;
        inCommit[i].applicationIdLo <== applicationIdLo;
        inCommit[i].value <== inValue[i];
        inCommit[i].ownerNotePublicKey <== inNpk[i].out;
        inCommit[i].ownerEncryptionKeyHash <== inEnc[i].out;
        inCommit[i].blinding <== inDummyBlinding[i];

        inNull[i] = Nullifier();
        inNull[i].domain <== DOMAIN_NULLIFIER();
        inNull[i].poolDomain <== poolDom.out;
        inNull[i].applicationIdHi <== applicationIdHi;
        inNull[i].applicationIdLo <== applicationIdLo;
        inNull[i].commitment <== inCommit[i].out;
        inNull[i].leafIndex <== inLeafIndex[i];
        inNull[i].spendingSecret <== inDummySecret[i];

        inPublicNf[i] <== inNull[i].out * inEnable[i].enabled;
        inAuditNpk[i] <== inNpk[i].out * inEnable[i].enabled;
        inAuditEnc[i] <== inEnc[i].out * inEnable[i].enabled;

        inIndexBits[i] = Num2Bits(DEPTH);
        inIndexBits[i].in <== inLeafIndex[i];
        inNotePath[i] = MerklePath(DEPTH);
        inNotePath[i].domain <== DOMAIN_NOTE_TREE();
        inNotePath[i].leaf <== inCommit[i].out;
        for (var j = 0; j < DEPTH; j++) {
            (1 - inEnable[i].enabled) * inNoteSiblings[i][j] === 0;
            inNotePath[i].indexBits[j] <== inIndexBits[i].out[j];
            inNotePath[i].siblings[j] <== inNoteSiblings[i][j];
        }
        inEnable[i].enabled * (inNotePath[i].out - noteTreeRoot) === 0;

        inMember[i] = ApplicationMember();
        inMember[i].domain <== DOMAIN_APP_MEMBER();
        inMember[i].applicationIdHi <== applicationIdHi;
        inMember[i].applicationIdLo <== applicationIdLo;
        inMember[i].notePublicKey <== inNpk[i].out;
        inMember[i].encryptionKeyHash <== inEnc[i].out;
        inMemberIndexBits[i] = Num2Bits(DEPTH);
        inMemberIndexBits[i].in <== inAppMemberIndex[i];
        inMemberPath[i] = MerklePath(DEPTH);
        inMemberPath[i].domain <== DOMAIN_APP_TREE();
        inMemberPath[i].leaf <== inMember[i].out;
        for (var j = 0; j < DEPTH; j++) {
            (1 - inEnable[i].enabled) * inAppMemberSiblings[i][j] === 0;
            inMemberPath[i].indexBits[j] <== inMemberIndexBits[i].out[j];
            inMemberPath[i].siblings[j] <== inAppMemberSiblings[i][j];
        }
        inEnable[i].enabled * (inMemberPath[i].out - applicationMembershipRoot) === 0;

        inBlocked[i] = GlobalBlockedNote();
        inBlocked[i].domain <== DOMAIN_BLOCK_NOTE();
        inBlocked[i].chainId <== chainId;
        inBlocked[i].applicationIdHi <== applicationIdHi;
        inBlocked[i].applicationIdLo <== applicationIdLo;
        inBlocked[i].notePublicKey <== inNpk[i].out;
        inBlocked[i].encryptionKeyHash <== inEnc[i].out;
        inNm[i] = NonMembership(DEPTH);
        inNm[i].domain <== DOMAIN_BLOCK_TREE();
        inNm[i].queried <== inBlocked[i].out;
        inNm[i].enabled <== inEnable[i].enabled;
        inNm[i].lowerLeaf <== inBlockLowerLeaf[i];
        inNm[i].upperLeaf <== inBlockUpperLeaf[i];
        inNm[i].lowerIndex <== inBlockLowerIndex[i];
        for (var j = 0; j < DEPTH; j++) {
            inNm[i].lowerSiblings[j] <== inBlockLowerSiblings[i][j];
            inNm[i].upperSiblings[j] <== inBlockUpperSiblings[i][j];
        }
        inEnable[i].enabled * (inNm[i].root - hazeBlocklistRoot) === 0;
    }
    inPublicNf[0] === inputNullifier0;
    inPublicNf[1] === inputNullifier1;
    isDepositLike * inputNullifier0 === 0;
    isDepositLike * inputNullifier1 === 0;
    isDepositLike * noteTreeRoot === 0;

    component outEnable[2];
    component outValueBits[2];
    component outNpk[2];
    component outEnc[2];
    component outCommit[2];
    component outMember[2];
    component outMemberIndexBits[2];
    component outMemberPath[2];
    component outBlocked[2];
    component outNm[2];
    signal outDummySecret[2];
    signal outDummyBlinding[2];
    signal outPublicCm[2];
    signal outAuditNpk[2];
    signal outAuditEnc[2];

    for (var i = 0; i < 2; i++) {
        outEnable[i] = SlotEnable();
        outEnable[i].value <== outValue[i];
        outValueBits[i] = RangeBits(64);
        outValueBits[i].in <== outValue[i];

        outDummySecret[i] <== outSpendingSecret[i] + (1 - outEnable[i].enabled);
        outDummyBlinding[i] <== outBlinding[i] + (1 - outEnable[i].enabled);
        (1 - outEnable[i].enabled) * outSpendingSecret[i] === 0;
        (1 - outEnable[i].enabled) * outBlinding[i] === 0;
        (1 - outEnable[i].enabled) * outX25519Hi[i] === 0;
        (1 - outEnable[i].enabled) * outX25519Lo[i] === 0;
        (1 - outEnable[i].enabled) * outAppMemberIndex[i] === 0;

        outNpk[i] = NotePublicKey();
        outNpk[i].domain <== DOMAIN_NOTE_KEY();
        outNpk[i].spendingSecret <== outDummySecret[i];

        outEnc[i] = EncryptionKeyHash();
        outEnc[i].domain <== DOMAIN_ENCRYPTION_KEY();
        outEnc[i].x25519Hi <== outX25519Hi[i];
        outEnc[i].x25519Lo <== outX25519Lo[i];

        outCommit[i] = NoteCommitment();
        outCommit[i].domain <== DOMAIN_NOTE();
        outCommit[i].poolDomain <== poolDom.out;
        outCommit[i].applicationIdHi <== applicationIdHi;
        outCommit[i].applicationIdLo <== applicationIdLo;
        outCommit[i].value <== outValue[i];
        outCommit[i].ownerNotePublicKey <== outNpk[i].out;
        outCommit[i].ownerEncryptionKeyHash <== outEnc[i].out;
        outCommit[i].blinding <== outDummyBlinding[i];

        outPublicCm[i] <== outCommit[i].out * outEnable[i].enabled;
        outAuditNpk[i] <== outNpk[i].out * outEnable[i].enabled;
        outAuditEnc[i] <== outEnc[i].out * outEnable[i].enabled;

        outMember[i] = ApplicationMember();
        outMember[i].domain <== DOMAIN_APP_MEMBER();
        outMember[i].applicationIdHi <== applicationIdHi;
        outMember[i].applicationIdLo <== applicationIdLo;
        outMember[i].notePublicKey <== outNpk[i].out;
        outMember[i].encryptionKeyHash <== outEnc[i].out;
        outMemberIndexBits[i] = Num2Bits(DEPTH);
        outMemberIndexBits[i].in <== outAppMemberIndex[i];
        outMemberPath[i] = MerklePath(DEPTH);
        outMemberPath[i].domain <== DOMAIN_APP_TREE();
        outMemberPath[i].leaf <== outMember[i].out;
        for (var j = 0; j < DEPTH; j++) {
            (1 - outEnable[i].enabled) * outAppMemberSiblings[i][j] === 0;
            outMemberPath[i].indexBits[j] <== outMemberIndexBits[i].out[j];
            outMemberPath[i].siblings[j] <== outAppMemberSiblings[i][j];
        }
        outEnable[i].enabled * (outMemberPath[i].out - applicationMembershipRoot) === 0;

        outBlocked[i] = GlobalBlockedNote();
        outBlocked[i].domain <== DOMAIN_BLOCK_NOTE();
        outBlocked[i].chainId <== chainId;
        outBlocked[i].applicationIdHi <== applicationIdHi;
        outBlocked[i].applicationIdLo <== applicationIdLo;
        outBlocked[i].notePublicKey <== outNpk[i].out;
        outBlocked[i].encryptionKeyHash <== outEnc[i].out;
        outNm[i] = NonMembership(DEPTH);
        outNm[i].domain <== DOMAIN_BLOCK_TREE();
        outNm[i].queried <== outBlocked[i].out;
        outNm[i].enabled <== outEnable[i].enabled;
        outNm[i].lowerLeaf <== outBlockLowerLeaf[i];
        outNm[i].upperLeaf <== outBlockUpperLeaf[i];
        outNm[i].lowerIndex <== outBlockLowerIndex[i];
        for (var j = 0; j < DEPTH; j++) {
            outNm[i].lowerSiblings[j] <== outBlockLowerSiblings[i][j];
            outNm[i].upperSiblings[j] <== outBlockUpperSiblings[i][j];
        }
        outEnable[i].enabled * (outNm[i].root - hazeBlocklistRoot) === 0;
    }
    outPublicCm[0] === outputCommitment0;
    outPublicCm[1] === outputCommitment1;
    (1 - outEnable[0].enabled) * recipientCiphertextHash0Hi === 0;
    (1 - outEnable[0].enabled) * recipientCiphertextHash0Lo === 0;
    (1 - outEnable[1].enabled) * recipientCiphertextHash1Hi === 0;
    (1 - outEnable[1].enabled) * recipientCiphertextHash1Lo === 0;

    signal inSum;
    signal outSum;
    inSum <== inValue[0] + inValue[1];
    outSum <== outValue[0] + outValue[1];

    component amountZero = IsZero();
    amountZero.in <== publicAmount;
    isTransfer.out * (1 - amountZero.out) === 0;
    (isDepositLike + isWithdraw.out) * amountZero.out === 0;

    component recipientZero = IsZero();
    recipientZero.in <== publicRecipient;
    isWithdraw.out * recipientZero.out === 0;
    (isDepositLike + isTransfer.out) * publicRecipient === 0;

    isDepositLike * (outSum - publicAmount) === 0;
    isTransfer.out * (inSum - outSum) === 0;
    isWithdraw.out * (inSum - outSum - publicAmount) === 0;

    component inSumZero = IsZero();
    inSumZero.in <== inSum;
    (isTransfer.out + isWithdraw.out) * inSumZero.out === 0;

    component noteRootZero = IsZero();
    noteRootZero.in <== noteTreeRoot;
    (isTransfer.out + isWithdraw.out) * noteRootZero.out === 0;

    signal screenEnabled;
    screenEnabled <== isDepositLike + isWithdraw.out;
    signal depositUser;
    depositUser <== isDepositLike * authorizedUser;
    signal withdrawRecipient;
    withdrawRecipient <== isWithdraw.out * publicRecipient;
    signal screenedAddress;
    screenedAddress <== depositUser + withdrawRecipient;

    component addrSubject = GlobalBlockedAddress();
    addrSubject.domain <== DOMAIN_BLOCK_ADDRESS();
    addrSubject.chainId <== chainId;
    addrSubject.address <== screenedAddress;
    component addrNm = NonMembership(DEPTH);
    addrNm.domain <== DOMAIN_BLOCK_TREE();
    addrNm.queried <== addrSubject.out;
    addrNm.enabled <== screenEnabled;
    addrNm.lowerLeaf <== addressLowerLeaf;
    addrNm.upperLeaf <== addressUpperLeaf;
    addrNm.lowerIndex <== addressLowerIndex;
    for (var j = 0; j < DEPTH; j++) {
        addrNm.lowerSiblings[j] <== addressLowerSiblings[j];
        addrNm.upperSiblings[j] <== addressUpperSiblings[j];
    }
    screenEnabled * (addrNm.root - hazeBlocklistRoot) === 0;

    component audit = AuditDataCommitment();
    audit.domain <== DOMAIN_AUDIT();
    audit.in[0] <== chainId;
    audit.in[1] <== poolAddress;
    audit.in[2] <== poolVersionHi;
    audit.in[3] <== poolVersionLo;
    audit.in[4] <== applicationIdHi;
    audit.in[5] <== applicationIdLo;
    audit.in[6] <== action;
    audit.in[7] <== authorizedUser;
    audit.in[8] <== usdcAddress;
    audit.in[9] <== publicAmount;
    audit.in[10] <== publicRecipient;
    audit.in[11] <== applicationPolicyVersion;
    audit.in[12] <== hazePolicyVersion;
    audit.in[13] <== actionReferenceHi;
    audit.in[14] <== actionReferenceLo;
    audit.in[15] <== inEnable[0].enabled;
    audit.in[16] <== inEnable[1].enabled;
    audit.in[17] <== inValue[0];
    audit.in[18] <== inValue[1];
    audit.in[19] <== inAuditNpk[0];
    audit.in[20] <== inAuditNpk[1];
    audit.in[21] <== inAuditEnc[0];
    audit.in[22] <== inAuditEnc[1];
    audit.in[23] <== inputNullifier0;
    audit.in[24] <== inputNullifier1;
    audit.in[25] <== outEnable[0].enabled;
    audit.in[26] <== outEnable[1].enabled;
    audit.in[27] <== outValue[0];
    audit.in[28] <== outValue[1];
    audit.in[29] <== outAuditNpk[0];
    audit.in[30] <== outAuditNpk[1];
    audit.in[31] <== outAuditEnc[0];
    audit.in[32] <== outAuditEnc[1];
    audit.in[33] <== outputCommitment0;
    audit.in[34] <== outputCommitment1;
    audit.in[35] <== recipientCiphertextHash0Hi;
    audit.in[36] <== recipientCiphertextHash0Lo;
    audit.in[37] <== recipientCiphertextHash1Hi;
    audit.in[38] <== recipientCiphertextHash1Lo;
    audit.in[39] <== auditSalt;
    audit.out === auditDataCommitment;
}
