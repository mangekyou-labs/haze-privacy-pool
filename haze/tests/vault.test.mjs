import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  decodeHazeAddress,
  encodeHazeAddress,
  encodeHazeAddressBytes,
  requireAddressBinding,
} from "../sdk/typescript/src/address.ts";
import { PROTOCOL_ERROR_CODES, SdkError } from "../sdk/typescript/src/errors.ts";
import { encodeEnvelope, envelopeHash, parseEnvelope } from "../sdk/typescript/src/envelope.ts";
import {
  openRecipientNote,
  parseRecipientPlaintext,
  recipientAad,
  sealRecipientNote,
} from "../sdk/typescript/src/hpke.ts";
import {
  encryptionKeyHash,
  encodeRecipientPlaintext,
  noteCommitment,
  notePublicKey,
  nullifier,
} from "../sdk/typescript/src/note.ts";
import {
  createLocalVault,
  createMemoryStore,
  deriveVaultAccount,
} from "../sdk/typescript/src/vault.ts";
import { deriveShieldedAccount } from "../sdk/typescript/src/prover.ts";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PROTOCOL = join(HAZE_ROOT, "circuits/vectors/v1/haze-protocol-v1.json");
const PROVER = join(HAZE_ROOT, "circuits/vectors/v1/haze-prover-v1.json");

function loadJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function named(vectors, name) {
  return vectors.positive.find((vector) => vector.name === name);
}

function namedNegative(vectors, name) {
  return vectors.negative.find((vector) => vector.name === name);
}

function hex(bytes) {
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

function parseHex(value) {
  return Buffer.from(value.replace(/^0x/, ""), "hex");
}

function throwsCode(fn, code) {
  assert.throws(fn, (error) => {
    assert.equal(error instanceof SdkError, true);
    assert.equal(error.code, code);
    return true;
  });
}

function fixtureBinding() {
  return {
    chainId: 43113,
    pool: "0x1111111111111111111111111111111111111111",
    applicationId: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    poolVersion: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  };
}

function fixtureRequest() {
  return {
    ...fixtureBinding(),
    wallet: "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
    signingKey: "0x0000000000000000000000000000000000000000000000000000000000000001",
  };
}

function protocolAddressParts(file) {
  const address = named(file, "haze_address");
  return {
    chainId: file.primitives.fuji_chain_id,
    applicationId: fixtureBinding().applicationId,
    poolVersion: fixtureBinding().poolVersion,
    notePublicKey: named(file, "note_public_key").field,
    x25519PublicKey: "0x851fe1e88c633c75d58459b39cdd10b0ea81d42ef73d36cc46ea05eb2de45947",
    text: address.text,
    bytes: address.bytes,
  };
}

test("protocol error taxonomy includes commitment and recovery codes", () => {
  assert.equal(PROTOCOL_ERROR_CODES.includes("COMMITMENT_MISMATCH"), true);
  assert.equal(PROTOCOL_ERROR_CODES.includes("RECOVERY_UNSUPPORTED"), true);
});

test("TypeScript encodes and decodes the committed haze1 address", () => {
  const file = loadJson(PROTOCOL);
  const parts = protocolAddressParts(file);
  const decoded = decodeHazeAddress(parts.text);
  assert.equal(decoded.chainId, parts.chainId);
  assert.equal(decoded.applicationId, parts.applicationId);
  assert.equal(decoded.poolVersion, parts.poolVersion);
  assert.equal(decoded.notePublicKey, parts.notePublicKey);
  assert.equal(decoded.x25519PublicKey, parts.x25519PublicKey);
  assert.equal(encodeHazeAddress(decoded), parts.text);
  assert.equal(hex(encodeHazeAddressBytes(decoded)), parts.bytes);
  assert.doesNotThrow(() =>
    requireAddressBinding(decoded, {
      chainId: parts.chainId,
      applicationId: parts.applicationId,
      poolVersion: parts.poolVersion,
    }),
  );
});

test("Haze address codec rejects padding, low-order keys, and binding drift", () => {
  const file = loadJson(PROTOCOL);
  const padded = namedNegative(file, "padded_haze_address");
  throwsCode(() => decodeHazeAddress(padded.input), padded.reason);
  const parts = protocolAddressParts(file);
  const decoded = decodeHazeAddress(parts.text);
  throwsCode(
    () =>
      requireAddressBinding(decoded, {
        chainId: file.primitives.c_chain_id,
        applicationId: parts.applicationId,
        poolVersion: parts.poolVersion,
      }),
    "CHAIN_MISMATCH",
  );
  throwsCode(
    () =>
      requireAddressBinding(decoded, {
        chainId: parts.chainId,
        applicationId: `0x${"11".repeat(32)}`,
        poolVersion: parts.poolVersion,
      }),
    "APPLICATION_MISMATCH",
  );
  throwsCode(
    () =>
      requireAddressBinding(decoded, {
        chainId: parts.chainId,
        applicationId: parts.applicationId,
        poolVersion: `0x${"22".repeat(32)}`,
      }),
    "POOL_VERSION_MISMATCH",
  );
  const lowOrder = namedNegative(file, "low_order_x25519");
  throwsCode(
    () =>
      encodeHazeAddress({
        chainId: parts.chainId,
        applicationId: parts.applicationId,
        poolVersion: parts.poolVersion,
        notePublicKey: parts.notePublicKey,
        x25519PublicKey: lowOrder.input,
      }),
    lowOrder.reason,
  );
});

test("TypeScript opens the committed recipient HPKE envelope and hashes the dummy frame", () => {
  const file = loadJson(PROTOCOL);
  const sealed = named(file, "recipient_hpke_seal_open");
  const opened = openRecipientNote({
    recipientIkm: sealed.recipient_ikm,
    encapsulatedKey: sealed.encapsulated_key,
    ciphertext: sealed.ciphertext,
    info: sealed.info,
    aad: sealed.aad,
  });
  assert.equal(hex(opened), sealed.plaintext);
  const parsed = parseRecipientPlaintext(opened);
  assert.equal(parsed.value, 1_000_000n);
  assert.equal(parsed.notePublicKey, named(file, "note_public_key").field);
  assert.equal(parsed.encryptionKeyHash, named(file, "encryption_key_hash").field);
  assert.equal(parsed.commitment, named(file, "note_commitment").field);

  const dummy = {
    purpose: "recipient",
    keyVersion: 0n,
    encapsulatedKey: hex(Buffer.alloc(32, 0x11)),
    ciphertext: hex(Buffer.alloc(48, 0x22)),
  };
  assert.equal(envelopeHash(dummy), named(file, "recipient_envelope_hash").hash);
  const encoded = encodeEnvelope(dummy);
  const parsedEnvelope = parseEnvelope(encoded);
  assert.equal(parsedEnvelope.purpose, "recipient");
  assert.equal(parsedEnvelope.keyVersion, 0n);
  assert.equal(envelopeHash(parsedEnvelope), named(file, "recipient_envelope_hash").hash);
});

test("encodeRecipientPlaintext and parseRecipientPlaintext support 200-byte and 232-byte formats", () => {
  const base = {
    value: 500_000n,
    blinding: `0x${"11".repeat(32)}`,
    notePublicKey: `0x${"22".repeat(32)}`,
    encryptionKeyHash: `0x${"33".repeat(32)}`,
    applicationId: `0x${"44".repeat(32)}`,
    poolVersion: `0x${"55".repeat(32)}`,
    commitment: `0x${"66".repeat(32)}`,
  };
  const encoded200 = encodeRecipientPlaintext(base);
  assert.equal(encoded200.length, 200);
  const parsed200 = parseRecipientPlaintext(encoded200);
  assert.equal(parsed200.value, 500_000n);
  assert.equal(parsed200.spendingSecret, undefined);

  const secret = `0x${"77".repeat(32)}`;
  const encoded232 = encodeRecipientPlaintext({ ...base, spendingSecret: secret });
  assert.equal(encoded232.length, 232);
  const parsed232 = parseRecipientPlaintext(encoded232);
  assert.equal(parsed232.value, 500_000n);
  assert.equal(parsed232.spendingSecret, secret);

  throwsCode(() => parseRecipientPlaintext(new Uint8Array(201)), "ENCODING_INVALID");
  throwsCode(() => parseRecipientPlaintext(new Uint8Array(100)), "ENCODING_INVALID");
});

test("recipient HPKE open rejects a tampered AAD", () => {
  const file = loadJson(PROTOCOL);
  const sealed = named(file, "recipient_hpke_seal_open");
  const aad = Buffer.from(parseHex(sealed.aad));
  aad[aad.length - 1] ^= 0x01;
  throwsCode(
    () =>
      openRecipientNote({
        recipientIkm: sealed.recipient_ikm,
        encapsulatedKey: sealed.encapsulated_key,
        ciphertext: sealed.ciphertext,
        info: sealed.info,
        aad: hex(aad),
      }),
    "CIPHERTEXT_INVALID",
  );
});

test("TypeScript recomputes note keys and the committed note commitment", () => {
  const file = loadJson(PROTOCOL);
  const spendingSecret = `0x${"00".repeat(31)}01`;
  const blinding = `0x${"00".repeat(31)}02`;
  const x25519 = "0x851fe1e88c633c75d58459b39cdd10b0ea81d42ef73d36cc46ea05eb2de45947";
  assert.equal(notePublicKey(spendingSecret), named(file, "note_public_key").field);
  assert.equal(encryptionKeyHash(x25519), named(file, "encryption_key_hash").field);
  assert.equal(
    noteCommitment({
      ...fixtureBinding(),
      value: 1_000_000n,
      ownerNotePublicKey: named(file, "note_public_key").field,
      ownerEncryptionKeyHash: named(file, "encryption_key_hash").field,
      blinding,
    }),
    named(file, "note_commitment").field,
  );
  throwsCode(() => noteCommitment({
    ...fixtureBinding(),
    value: 1_000_000n,
    ownerNotePublicKey: named(file, "note_public_key").field,
    ownerEncryptionKeyHash: named(file, "encryption_key_hash").field,
    blinding: `0x${"00".repeat(32)}`,
  }), "FIELD_OUT_OF_RANGE");
});

test("wallet-derived vault account matches prover note and encryption keys", () => {
  const expected = loadJson(PROVER);
  const account = deriveVaultAccount(fixtureRequest());
  const fromProver = deriveShieldedAccount(fixtureRequest());
  assert.equal(account.spendingSecret, expected.spendingSecret);
  assert.equal(account.x25519PublicKey, expected.x25519PublicKey);
  assert.equal(account.localVaultKey, expected.localVaultKey);
  assert.equal(account.notePublicKey, expected.notePublicKey);
  assert.equal(account.encryptionKeyHash, expected.encryptionKeyHash);
  assert.equal(account.notePublicKey, notePublicKey(fromProver.spendingSecret));
  assert.equal(account.encryptionKeyHash, encryptionKeyHash(fromProver.x25519PublicKey));
  assert.equal(account.x25519Secret.length, 66);
  assert.notEqual(account.x25519Secret, account.spendingSecret);
});

test("smart-contract wallets fail closed with RECOVERY_UNSUPPORTED", () => {
  throwsCode(
    () => deriveVaultAccount({ ...fixtureRequest(), recoveryAdapter: "smart-wallet" }),
    "RECOVERY_UNSUPPORTED",
  );
});

function sampleNotePlaintext(account) {
  const binding = fixtureBinding();
  const blinding = `0x${"00".repeat(31)}02`;
  const value = 1_000_000n;
  const commitment = noteCommitment({
    ...binding,
    value,
    ownerNotePublicKey: account.notePublicKey,
    ownerEncryptionKeyHash: account.encryptionKeyHash,
    blinding,
  });
  return {
    value,
    blinding,
    notePublicKey: account.notePublicKey,
    encryptionKeyHash: account.encryptionKeyHash,
    applicationId: binding.applicationId,
    poolVersion: binding.poolVersion,
    commitment,
  };
}

function sealedEvent(account, overrides = {}) {
  const binding = fixtureBinding();
  const plaintext = sampleNotePlaintext(account);
  const aad = recipientAad({
    ...binding,
    outputIndex: 0,
    outputCommitment: plaintext.commitment,
    envelopeVersion: 1,
  });
  const sealed = sealRecipientNote({
    recipientIkm: account.x25519Secret,
    senderSeed: `0x${"61".repeat(32)}`,
    aad,
    plaintext,
  });
  return {
    chainId: binding.chainId,
    pool: binding.pool,
    poolVersion: binding.poolVersion,
    applicationId: binding.applicationId,
    outputIndex: 0,
    commitment: plaintext.commitment,
    envelope: hex(encodeEnvelope({
      purpose: "recipient",
      keyVersion: 0n,
      encapsulatedKey: sealed.encapsulatedKey,
      ciphertext: sealed.ciphertext,
    })),
    blockNumber: 42,
    finalized: true,
    txHash: `0x${"ab".repeat(32)}`,
    logIndex: 0,
    ...overrides,
  };
}

test("local vault encrypts notes and never persists spending or encryption secrets", async () => {
  const store = createMemoryStore();
  const account = deriveVaultAccount(fixtureRequest());
  const vault = createLocalVault({ store, account, binding: fixtureBinding() });
  const event = sealedEvent(account);
  const ingested = await vault.ingest(event);
  assert.equal(ingested.accepted, true);
  assert.equal(ingested.note.commitment, event.commitment);
  assert.equal(ingested.note.value, 1_000_000n);
  await vault.persist();
  const keys = store.keys();
  assert.ok(keys.length > 0);
  for (const key of keys) {
    const blob = hex(await store.get(key));
    assert.equal(blob.includes(account.spendingSecret.slice(2)), false);
    assert.equal(blob.includes(account.x25519Secret.slice(2)), false);
    assert.equal(blob.includes(account.localVaultKey.slice(2)), false);
    assert.equal(blob.includes(event.commitment.slice(2)), false);
  }
  const spending = parseHex(account.spendingSecret);
  const x25519 = parseHex(account.x25519Secret);
  vault.retainSecret(spending);
  vault.retainSecret(x25519);
  vault.clearSecrets();
  assert.ok(spending.every((byte) => byte === 0));
  assert.ok(x25519.every((byte) => byte === 0));
});

test("wiping the store and replaying events recovers the same spendable notes", async () => {
  const store = createMemoryStore();
  const account = deriveVaultAccount(fixtureRequest());
  const first = createLocalVault({ store, account, binding: fixtureBinding() });
  const event = sealedEvent(account);
  await first.ingest(event);
  await first.persist();
  assert.equal(first.listNotes().length, 1);

  await first.clearLocalState();
  assert.equal(first.listNotes().length, 0);
  assert.equal((await store.keys()).length, 0);

  const recoveredAccount = deriveVaultAccount(fixtureRequest());
  const recovered = createLocalVault({ store, account: recoveredAccount, binding: fixtureBinding() });
  const notes = await recovered.recover([event]);
  assert.equal(notes.length, 1);
  assert.equal(notes[0].commitment, event.commitment);
  assert.equal(notes[0].value, 1_000_000n);
  assert.equal(recoveredAccount.spendingSecret, account.spendingSecret);
  assert.equal(recoveredAccount.notePublicKey, account.notePublicKey);
});

test("duplicate events are ignored and a commitment mismatch is rejected", async () => {
  const store = createMemoryStore();
  const account = deriveVaultAccount(fixtureRequest());
  const vault = createLocalVault({ store, account, binding: fixtureBinding() });
  const event = sealedEvent(account);
  assert.equal((await vault.ingest(event)).accepted, true);
  assert.equal((await vault.ingest(event)).accepted, false);
  assert.equal(vault.listNotes().length, 1);

  const fakeCommitment = `0x${"11".repeat(32)}`;
  const mismatchPlain = { ...sampleNotePlaintext(account), commitment: fakeCommitment };
  const mismatchAad = recipientAad({
    ...fixtureBinding(),
    outputIndex: 0,
    outputCommitment: fakeCommitment,
    envelopeVersion: 1,
  });
  const mismatchSealed = sealRecipientNote({
    recipientIkm: account.x25519Secret,
    senderSeed: `0x${"62".repeat(32)}`,
    aad: mismatchAad,
    plaintext: mismatchPlain,
  });
  const tampered = {
    ...event,
    txHash: `0x${"cd".repeat(32)}`,
    commitment: fakeCommitment,
    envelope: hex(encodeEnvelope({
      purpose: "recipient",
      keyVersion: 0n,
      encapsulatedKey: mismatchSealed.encapsulatedKey,
      ciphertext: mismatchSealed.ciphertext,
    })),
  };
  await assert.rejects(() => vault.ingest(tampered), (error) => {
    assert.equal(error instanceof SdkError, true);
    assert.equal(error.code, "COMMITMENT_MISMATCH");
    return true;
  });
  assert.equal(vault.listNotes().length, 1);
});

test("a reorg drops unfinalized notes", async () => {
  const store = createMemoryStore();
  const account = deriveVaultAccount(fixtureRequest());
  const vault = createLocalVault({ store, account, binding: fixtureBinding() });
  const finalized = sealedEvent(account, {
    blockNumber: 10,
    finalized: true,
    txHash: `0x${"11".repeat(32)}`,
  });
  const pending = sealedEvent(account, {
    blockNumber: 20,
    finalized: false,
    txHash: `0x${"22".repeat(32)}`,
    logIndex: 1,
  });
  await vault.ingest(finalized);
  await vault.ingest(pending);
  assert.equal(vault.listNotes().length, 2);
  vault.applyReorg(10);
  const remaining = vault.listNotes();
  assert.equal(remaining.length, 1);
  assert.equal(remaining[0].commitment, finalized.commitment);
  assert.equal(remaining[0].finalized, true);
});
