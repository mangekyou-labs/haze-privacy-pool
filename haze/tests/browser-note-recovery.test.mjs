import assert from "node:assert/strict";
import test from "node:test";
import { concatBytes, hexToBuf, toHex } from "../sdk/typescript/src/abi.ts";
import {
  decodeBrowserEnvelope,
  deriveBrowserX25519PublicKey,
  encodeBrowserEnvelope,
  openBrowserHpke,
  parseBrowserRecipientPlaintext,
  sealBrowserHpkeToPublicKey,
} from "../sdk/typescript/src/browser-crypto.ts";
import { generateBrowserSecrets } from "../sdk/typescript/src/browser-prover.ts";
import { buildSealedBrowserWitness } from "../sdk/typescript/src/browser-witness-flow.ts";
import { u64be } from "../sdk/typescript/src/field.ts";
import {
  PRIVATE_TRANSACTION_TOPIC,
  recoverSpendableNotesFromLogs,
} from "../sdk/typescript/src/fuji-reconciliation.ts";
import { unionMembershipLeaves } from "../sdk/typescript/src/fuji-membership-store.ts";
import { APP_TREE } from "../sdk/typescript/src/merkle.ts";
import { encodeRecipientPlaintext, encryptionKeyHash, noteCommitment, notePublicKey, nullifier } from "../sdk/typescript/src/note.ts";
import { applicationMember } from "../sdk/typescript/src/policy.ts";
import {
  SparseMerkleTree,
  buildLiveDepositWitness,
  buildLiveTransferWitness,
} from "../dev/operator-circuit-witness.mjs";

const POOL = "0x00BEB0A5D709d0F093952fD374Dbbf3d0d21d550";
const APP = `0x${"00".repeat(30)}0a11`;
const POOL_VERSION = `0x${"00".repeat(30)}b001`;
const USER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const AUDIT_PK = Uint8Array.from(
  "2a082bd0a097bda77158deadbecf043d15e5d09845bf8cfcd2d294d0b0a4ed04".match(/../g),
  (byte) => Number.parseInt(byte, 16),
);
const WALLET_IKM = Uint8Array.from({ length: 32 }, (_, i) => i + 1);

function word(value) {
  const hex = typeof value === "bigint" || typeof value === "number"
    ? BigInt(value).toString(16)
    : String(value).replace(/^0x/, "");
  return hex.padStart(64, "0");
}

function encodeDynamicBytes(bytes) {
  const hex = toHex(bytes).slice(2);
  const padded = hex.padEnd(Math.ceil(hex.length / 64) * 64, "0");
  return `${word(bytes.length)}${padded}`;
}

function privateTransactionLog({ action = 1, output0, envelope0Bytes, user = USER, inputNullifier0 = 0 }) {
  const empty = encodeDynamicBytes(new Uint8Array());
  const e0 = encodeDynamicBytes(envelope0Bytes);
  const headWords = 16;
  const headBytes = headWords * 32;
  const off0 = headBytes;
  const off1 = off0 + e0.length / 2;
  const off2 = off1 + empty.length / 2;
  const staticAndOffsets = [
    action, 2, 3, inputNullifier0, 0, output0, 0, 1_000_000, BigInt(user), 0, 0, 0, 0,
    off0, off1, off2,
  ].map(word).join("");
  return {
    address: POOL,
    topics: [
      PRIVATE_TRANSACTION_TOPIC,
      APP,
      `0x${word(action)}`,
      `0x${"0".repeat(24)}${user.slice(2).toLowerCase()}`,
    ],
    data: `0x${staticAndOffsets}${e0}${empty}${empty}`,
    transactionHash: `0x${"ab".repeat(32)}`,
  };
}

test("a Shield recipient envelope opens with the wallet x25519 key and carries the spending secret", () => {
  let random = 0;
  const result = buildSealedBrowserWitness({
    buildWitness: buildLiveDepositWitness,
    witnessInput: {
      pool: POOL,
      user: USER,
      applicationId: APP,
      poolVersion: POOL_VERSION,
      publicAmount: 1_000_000,
      applicationPolicyVersion: 8,
      hazePolicyVersion: 1,
    },
    chainId: 43113,
    pool: POOL,
    poolVersion: POOL_VERSION,
    applicationId: APP,
    auditPublicKey: AUDIT_PK,
    auditKeyVersion: 1n,
    caseTag: new TextEncoder().encode("OWN-DEPOSIT"),
    recipientPublicKey: deriveBrowserX25519PublicKey(WALLET_IKM),
    browserCrypto: { getRandomValues(bytes) { bytes.fill(++random); return bytes; } },
  });

  const envelope = decodeBrowserEnvelope(hexToBuf(result.recipientEnvelope.bytes));
  const opened = openBrowserHpke({
    recipientIkm: WALLET_IKM,
    encapsulatedKey: envelope.encapsulatedKey,
    ciphertext: envelope.ciphertext,
    info: new TextEncoder().encode("haze/avalanche/v1/recipient-note"),
    aad: concatBytes(
      u64be(43113),
      hexToBuf(POOL),
      hexToBuf(POOL_VERSION),
      hexToBuf(APP),
      Uint8Array.of(0),
      hexToBuf(result.witness.note.commitment),
      Uint8Array.of(1),
    ),
  });
  const plaintext = parseBrowserRecipientPlaintext(opened);
  assert.equal(plaintext.value, 1_000_000n);
  assert.ok(plaintext.spendingSecret, "depositor must be able to recover the spending secret");
  assert.equal(notePublicKey(plaintext.spendingSecret), plaintext.notePublicKey);
  assert.equal(
    noteCommitment({
      chainId: 43113,
      pool: POOL,
      poolVersion: POOL_VERSION,
      applicationId: APP,
      value: plaintext.value,
      ownerNotePublicKey: plaintext.notePublicKey,
      ownerEncryptionKeyHash: plaintext.encryptionKeyHash,
      blinding: plaintext.blinding,
    }),
    result.witness.note.commitment,
  );
});

test("log scan reconstructs a spendable Shield note for the connected wallet after a fresh session", () => {
  let random = 0;
  const sealed = buildSealedBrowserWitness({
    buildWitness: buildLiveDepositWitness,
    witnessInput: {
      pool: POOL,
      user: USER,
      applicationId: APP,
      poolVersion: POOL_VERSION,
      publicAmount: 1_000_000,
      applicationPolicyVersion: 8,
      hazePolicyVersion: 1,
    },
    chainId: 43113,
    pool: POOL,
    poolVersion: POOL_VERSION,
    applicationId: APP,
    auditPublicKey: AUDIT_PK,
    auditKeyVersion: 1n,
    caseTag: new TextEncoder().encode("OWN-DEPOSIT"),
    recipientPublicKey: deriveBrowserX25519PublicKey(WALLET_IKM),
    browserCrypto: { getRandomValues(bytes) { bytes.fill(++random); return bytes; } },
  });

  const notes = recoverSpendableNotesFromLogs({
    chainId: 43113,
    pool: POOL,
    poolVersion: POOL_VERSION,
    applicationId: APP,
    recipientIkm: WALLET_IKM,
    logs: [privateTransactionLog({
      output0: sealed.witness.note.commitment,
      envelope0Bytes: hexToBuf(sealed.recipientEnvelope.bytes),
    })],
  });

  assert.equal(notes.length, 1);
  assert.equal(notes[0].commitment, sealed.witness.note.commitment);
  assert.equal(notes[0].value, 1_000_000);
  assert.equal(notes[0].spendable, true);
  assert.equal(notes[0].action, 1);
  assert.equal(notes[0].secret, sealed.witness.note.secret);
  assert.equal(notes[0].x25519, toHex(deriveBrowserX25519PublicKey(WALLET_IKM)));
  assert.equal(sealed.witness.note.x25519, toHex(deriveBrowserX25519PublicKey(WALLET_IKM)));
  assert.equal(encryptionKeyHash(notes[0].x25519), notes[0].enc);
  assert.equal(encryptionKeyHash(sealed.witness.note.x25519), sealed.witness.note.enc);
  assert.equal(
    notes[0].nullifier,
    nullifier({
      chainId: 43113,
      pool: POOL,
      poolVersion: POOL_VERSION,
      applicationId: APP,
      commitment: notes[0].commitment,
      leafIndex: notes[0].leafIndex,
      spendingSecret: notes[0].secret,
    }),
  );
});

test("log scan preserves Swap provenance instead of relabeling its recovered output as Shield", () => {
  let random = 0;
  const sealed = buildSealedBrowserWitness({
    buildWitness: buildLiveDepositWitness,
    witnessInput: {
      pool: POOL,
      user: USER,
      applicationId: APP,
      poolVersion: POOL_VERSION,
      publicAmount: 1_000_000,
      applicationPolicyVersion: 8,
      hazePolicyVersion: 1,
    },
    chainId: 43113,
    pool: POOL,
    poolVersion: POOL_VERSION,
    applicationId: APP,
    auditPublicKey: AUDIT_PK,
    auditKeyVersion: 1n,
    caseTag: new TextEncoder().encode("SWAP-OUTPUT"),
    recipientPublicKey: deriveBrowserX25519PublicKey(WALLET_IKM),
    browserCrypto: { getRandomValues(bytes) { bytes.fill(++random); return bytes; } },
  });

  const notes = recoverSpendableNotesFromLogs({
    chainId: 43113,
    pool: POOL,
    poolVersion: POOL_VERSION,
    applicationId: APP,
    recipientIkm: WALLET_IKM,
    logs: [privateTransactionLog({
      action: 4,
      output0: sealed.witness.note.commitment,
      envelope0Bytes: hexToBuf(sealed.recipientEnvelope.bytes),
    })],
  });

  assert.equal(notes.length, 1);
  assert.equal(notes[0].action, 4);
});

test("log scan does not restore a note whose nullifier was already spent", () => {
  let random = 0;
  const sealed = buildSealedBrowserWitness({
    buildWitness: buildLiveDepositWitness,
    witnessInput: {
      pool: POOL,
      user: USER,
      applicationId: APP,
      poolVersion: POOL_VERSION,
      publicAmount: 1_000_000,
      applicationPolicyVersion: 8,
      hazePolicyVersion: 1,
    },
    chainId: 43113,
    pool: POOL,
    poolVersion: POOL_VERSION,
    applicationId: APP,
    auditPublicKey: AUDIT_PK,
    auditKeyVersion: 1n,
    caseTag: new TextEncoder().encode("OWN-DEPOSIT"),
    recipientPublicKey: deriveBrowserX25519PublicKey(WALLET_IKM),
    browserCrypto: { getRandomValues(bytes) { bytes.fill(++random); return bytes; } },
  });
  const shieldLog = privateTransactionLog({
    output0: sealed.witness.note.commitment,
    envelope0Bytes: hexToBuf(sealed.recipientEnvelope.bytes),
  });
  const recovered = recoverSpendableNotesFromLogs({
    chainId: 43113,
    pool: POOL,
    poolVersion: POOL_VERSION,
    applicationId: APP,
    recipientIkm: WALLET_IKM,
    logs: [shieldLog],
  });
  assert.equal(recovered.length, 1);
  const spendLog = privateTransactionLog({
    output0: `0x${"00".repeat(32)}`,
    envelope0Bytes: new Uint8Array(),
    inputNullifier0: recovered[0].nullifier,
  });
  const afterSpend = recoverSpendableNotesFromLogs({
    chainId: 43113,
    pool: POOL,
    poolVersion: POOL_VERSION,
    applicationId: APP,
    recipientIkm: WALLET_IKM,
    logs: [shieldLog, spendLog],
  });
  assert.equal(afterSpend.length, 0);
});

test("Send witness from a recovered sealed Shield matches stored envelope membership union", () => {
  let random = 0;
  const sealed = buildSealedBrowserWitness({
    buildWitness: buildLiveDepositWitness,
    witnessInput: {
      pool: POOL,
      user: USER,
      applicationId: APP,
      poolVersion: POOL_VERSION,
      publicAmount: 1_000_000,
      applicationPolicyVersion: 8,
      hazePolicyVersion: 1,
    },
    chainId: 43113,
    pool: POOL,
    poolVersion: POOL_VERSION,
    applicationId: APP,
    auditPublicKey: AUDIT_PK,
    auditKeyVersion: 1n,
    caseTag: new TextEncoder().encode("OWN-DEPOSIT"),
    recipientPublicKey: deriveBrowserX25519PublicKey(WALLET_IKM),
    browserCrypto: { getRandomValues(bytes) { bytes.fill(++random); return bytes; } },
  });
  const recovered = recoverSpendableNotesFromLogs({
    chainId: 43113,
    pool: POOL,
    poolVersion: POOL_VERSION,
    applicationId: APP,
    recipientIkm: WALLET_IKM,
    logs: [privateTransactionLog({
      output0: sealed.witness.note.commitment,
      envelope0Bytes: hexToBuf(sealed.recipientEnvelope.bytes),
    })],
  });
  assert.equal(recovered.length, 1);
  const stored = [{ npk: recovered[0].npk, enc: recovered[0].enc }];
  const transfer = buildLiveTransferWitness({
    pool: POOL,
    user: USER,
    applicationId: APP,
    poolVersion: POOL_VERSION,
    note: recovered[0],
    sendAmount: 400_000,
    recipientX25519: `0x${"22".repeat(32)}`,
    recipientSecret: `0x${"14".repeat(32)}`,
    recipientBlinding: `0x${"15".repeat(32)}`,
    changeSecret: `0x${"16".repeat(32)}`,
    changeBlinding: `0x${"17".repeat(32)}`,
    changeX25519: recovered[0].x25519,
    membershipLeaves: stored,
  });
  const union = unionMembershipLeaves(
    stored,
    [{ npk: recovered[0].npk, enc: recovered[0].enc }],
    [transfer.recipientNote, transfer.note],
  );
  const tree = new SparseMerkleTree(APP_TREE);
  union.forEach((leaf, index) => {
    tree.insert(index, applicationMember(APP, leaf.npk, leaf.enc));
  });
  assert.equal(transfer.circom.applicationMembershipRoot, tree.root());
});

test("recovered note is not spendable when envelope enc does not match owner x25519", () => {
  const deposit = buildLiveDepositWitness({
    pool: POOL,
    user: USER,
    applicationId: APP,
    poolVersion: POOL_VERSION,
    value: 1_000_000,
    secret: `0x${"14".repeat(32)}`,
    blinding: `0x${"15".repeat(32)}`,
    x25519: `0x${"33".repeat(32)}`,
  });
  const secrets = generateBrowserSecrets({
    getRandomValues(bytes) {
      bytes.fill(9);
      return bytes;
    },
  });
  const plaintext = encodeRecipientPlaintext({
    value: deposit.note.value,
    blinding: deposit.note.blinding,
    notePublicKey: deposit.note.npk,
    encryptionKeyHash: deposit.note.enc,
    applicationId: APP,
    poolVersion: POOL_VERSION,
    commitment: deposit.note.commitment,
    spendingSecret: deposit.note.secret,
  });
  const sealed = sealBrowserHpkeToPublicKey({
    recipientPublicKey: deriveBrowserX25519PublicKey(WALLET_IKM),
    ephemeralSeed: secrets.recipientHpkeSeed,
    plaintext,
    info: new TextEncoder().encode("haze/avalanche/v1/recipient-note"),
    aad: concatBytes(
      u64be(43113),
      hexToBuf(POOL),
      hexToBuf(POOL_VERSION),
      hexToBuf(APP),
      Uint8Array.of(0),
      hexToBuf(deposit.note.commitment),
      Uint8Array.of(1),
    ),
  });
  const notes = recoverSpendableNotesFromLogs({
    chainId: 43113,
    pool: POOL,
    poolVersion: POOL_VERSION,
    applicationId: APP,
    recipientIkm: WALLET_IKM,
    logs: [privateTransactionLog({
      output0: deposit.note.commitment,
      envelope0Bytes: encodeBrowserEnvelope({ purpose: "recipient", keyVersion: 0n, ...sealed }),
    })],
  });
  assert.equal(notes.length, 1);
  assert.equal(notes[0].spendable, false);
  assert.notEqual(encryptionKeyHash(notes[0].x25519), notes[0].enc);
});

test("old Shield envelopes sealed to an ephemeral note secret do not open with the wallet key", () => {
  let random = 0;
  const sealed = buildSealedBrowserWitness({
    buildWitness: buildLiveDepositWitness,
    witnessInput: {
      pool: POOL,
      user: USER,
      applicationId: APP,
      poolVersion: POOL_VERSION,
      publicAmount: 1_000_000,
      applicationPolicyVersion: 8,
      hazePolicyVersion: 1,
    },
    chainId: 43113,
    pool: POOL,
    poolVersion: POOL_VERSION,
    applicationId: APP,
    auditPublicKey: AUDIT_PK,
    auditKeyVersion: 1n,
    caseTag: new TextEncoder().encode("OWN-DEPOSIT"),
    browserCrypto: { getRandomValues(bytes) { bytes.fill(++random); return bytes; } },
  });
  const notes = recoverSpendableNotesFromLogs({
    chainId: 43113,
    pool: POOL,
    poolVersion: POOL_VERSION,
    applicationId: APP,
    recipientIkm: WALLET_IKM,
    logs: [privateTransactionLog({
      output0: sealed.witness.note.commitment,
      envelope0Bytes: hexToBuf(sealed.recipientEnvelope.bytes),
    })],
  });
  assert.equal(notes.length, 0);
});
