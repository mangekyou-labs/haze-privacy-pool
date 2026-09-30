import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  DEVELOPMENT_AUDIT_IKM,
  DEVELOPMENT_AUDIT_SENDER_SEED,
  auditAad,
  auditDataCommitment,
  decodeAuditRecord,
  encodeAuditRecord,
  sealAuditRecord,
} from "../sdk/typescript/src/audit.ts";
import { openAuditEnvelope } from "../sdk/typescript/src/hpke.ts";
import { parseEnvelope } from "../sdk/typescript/src/envelope.ts";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const VECTOR_PATH = resolve(HAZE_ROOT, "circuits/vectors/v1/haze-protocol-v1.json");

function hex(bytes) {
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

function loadVectors() {
  return JSON.parse(readFileSync(VECTOR_PATH, "utf8"));
}

function named(vectors, name) {
  return vectors.positive.find((vector) => vector.name === name);
}

test("TypeScript audit CBOR and commitment match the Rust vector", () => {
  const vectors = loadVectors();
  const cbor = named(vectors, "audit_cbor_record");
  const hpke = named(vectors, "audit_hpke_seal_open");
  const record = decodeAuditRecord(cbor.bytes);

  assert.equal(hex(encodeAuditRecord(record)), cbor.bytes);
  assert.equal(auditDataCommitment(record.facts), named(vectors, "audit_data_commitment").field);
  assert.equal(record.caseTag, "0x636173652d31");
  assert.equal(record.facts.chainId, 43113);
  assert.equal(record.facts.publicAmount, 1_000_000);
  assert.equal(hex(openAuditEnvelope({
    recipientIkm: hpke.recipient_ikm,
    encapsulatedKey: hpke.encapsulated_key,
    ciphertext: hpke.ciphertext,
    aad: hpke.aad,
  })), hpke.plaintext);
  assert.equal(
    hex(auditAad({
      chainId: record.facts.chainId,
      pool: record.facts.poolAddress,
      poolVersion: record.facts.poolVersion,
      applicationId: record.facts.applicationId,
      auditKeyVersion: 1,
      auditDataCommitment: named(vectors, "audit_data_commitment").field,
      action: record.facts.action,
      actionReference: record.facts.actionReference,
    })),
    hpke.aad,
  );
});

test("audit HPKE seal/open uses AUDIT_INFO and the canonical envelope", () => {
  const vectors = loadVectors();
  const cbor = named(vectors, "audit_cbor_record");
  const commitment = named(vectors, "audit_data_commitment").field;
  const record = decodeAuditRecord(cbor.bytes);
  const aad = auditAad({
    chainId: record.facts.chainId,
    pool: record.facts.poolAddress,
    poolVersion: record.facts.poolVersion,
    applicationId: record.facts.applicationId,
    auditKeyVersion: 1,
    auditDataCommitment: commitment,
    action: record.facts.action,
    actionReference: record.facts.actionReference,
  });
  const sealed = sealAuditRecord({
    record,
    recipientIkm: DEVELOPMENT_AUDIT_IKM,
    senderSeed: DEVELOPMENT_AUDIT_SENDER_SEED,
    auditKeyVersion: 1,
  });
  assert.equal(hex(openAuditEnvelope({ ...sealed.envelope, recipientIkm: DEVELOPMENT_AUDIT_IKM, aad })), cbor.bytes);
  assert.equal(parseEnvelope(sealed.bytes).purpose, "audit");
  assert.equal(sealed.hash.length, 66);
});

test("audit record rejects non-canonical integers, unknown fields, and commitment drift", () => {
  const cbor = named(loadVectors(), "audit_cbor_record").bytes;
  const bytes = Buffer.from(cbor.slice(2), "hex");

  const nonCanonical = Buffer.from(bytes);
  // The chain id 43113 is encoded with a 16-bit argument at this offset.
  const chainOffset = nonCanonical.indexOf(Buffer.from([0x19, 0xa8, 0x69]));
  assert.notEqual(chainOffset, -1);
  nonCanonical[chainOffset] = 0x1a;
  assert.throws(() => decodeAuditRecord(hex(nonCanonical)), { code: "ENCODING_INVALID" });

  const unknown = Buffer.from(bytes);
  unknown[1] = 0xb9;
  assert.throws(() => decodeAuditRecord(hex(unknown)), { code: "ENCODING_INVALID" });

  const record = decodeAuditRecord(cbor);
  const changed = {
    ...record,
    facts: { ...record.facts, actionReference: `0x${"02".repeat(32)}` },
  };
  assert.notEqual(auditDataCommitment(changed.facts), auditDataCommitment(record.facts));
});

test("operator witness emits a decryptable audit envelope rather than a dummy ciphertext", async () => {
  const { buildFixtureDepositWitness } = await import("../dev/operator-circuit-witness.mjs");
  const witness = buildFixtureDepositWitness();
  const envelope = parseEnvelope(witness.envelopes.auditCiphertext);
  assert.equal(envelope.purpose, "audit");
  const record = decodeAuditRecord(witness.auditRecordBytes);
  assert.equal(auditDataCommitment(record.facts), witness.circom.auditDataCommitment);
  const aad = auditAad({
    chainId: record.facts.chainId,
    pool: record.facts.poolAddress,
    poolVersion: record.facts.poolVersion,
    applicationId: record.facts.applicationId,
    auditKeyVersion: envelope.keyVersion,
    auditDataCommitment: witness.circom.auditDataCommitment,
    action: record.facts.action,
    actionReference: record.facts.actionReference,
  });
  assert.equal(
    hex(openAuditEnvelope({
      recipientIkm: DEVELOPMENT_AUDIT_IKM,
      encapsulatedKey: envelope.encapsulatedKey,
      ciphertext: envelope.ciphertext,
      aad,
    })),
    witness.auditRecordBytes,
  );
});
