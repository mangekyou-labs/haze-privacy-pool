import { AUDIT_INFO, encodeEnvelope, envelopeHash, parseEnvelope, type Envelope } from "./envelope.ts";
import { SdkError } from "./errors.ts";
import { bytes32Limbs, fieldFromAddress, fieldFromHex, fieldFromU128, fieldToHex, parseAddress, parseHex, toHex, u64be } from "./field.ts";
import { domainField } from "./domain.ts";
import { poseidon2Hash } from "./poseidon2.ts";
import { openAuditEnvelope, sealAuditEnvelope } from "./hpke.ts";

/** Development-only deterministic material used by local operator fixtures. */
export const DEVELOPMENT_AUDIT_IKM = `0x${"52".repeat(32)}`;
export const DEVELOPMENT_AUDIT_SENDER_SEED = `0x${"62".repeat(32)}`;
export const DEVELOPMENT_AUDIT_KEY_VERSION = 1n;

export type AuditCommitmentInput = {
  chainId: number | bigint;
  poolAddress?: string;
  pool?: string;
  poolVersion: string;
  applicationId: string;
  action: number;
  authorizedUser: string;
  usdcAddress?: string;
  usdc?: string;
  publicAmount: number | bigint;
  publicRecipient: string;
  applicationPolicyVersion: number | bigint;
  hazePolicyVersion: number | bigint;
  actionReference: string;
  inputEnabled: [number, number];
  inputValues: [number | bigint, number | bigint];
  inputNotePublicKeys: [string, string];
  inputEncryptionKeyHashes: [string, string];
  inputNullifiers: [string, string];
  outputEnabled: [number, number];
  outputValues: [number | bigint, number | bigint];
  outputNotePublicKeys: [string, string];
  outputEncryptionKeyHashes: [string, string];
  outputCommitments: [string, string];
  recipientCiphertextHashes: [string, string];
  auditSalt: string;
};

export type AuditRecord = {
  facts: Required<Omit<AuditCommitmentInput, "poolAddress" | "pool" | "usdcAddress" | "usdc">> & {
    poolAddress: string;
    usdcAddress: string;
  };
  caseTag: string;
};

function fail(): never {
  throw new SdkError("ENCODING_INVALID");
}

function asU64(value: number | bigint): number | bigint {
  if (typeof value === "number" && !Number.isSafeInteger(value)) {
    throw new SdkError("FIELD_OUT_OF_RANGE");
  }
  const parsed = typeof value === "number" ? BigInt(value) : value;
  if (parsed < 0n || parsed > 0xffffffffffffffffn) throw new SdkError("FIELD_OUT_OF_RANGE");
  return parsed <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(parsed) : parsed;
}

function asAction(value: number): number {
  if (!Number.isInteger(value) || ![1, 2, 3, 4, 5].includes(value)) {
    throw new SdkError("ENCODING_INVALID");
  }
  return value;
}

function bytes(value: string | Uint8Array, length?: number): Buffer {
  const output = Buffer.from(typeof value === "string" ? parseHex(value) : value);
  if (length !== undefined && output.length !== length) {
    throw new SdkError("ENCODING_INVALID");
  }
  return output;
}

function requiredAddress(input: AuditCommitmentInput) {
  return input.poolAddress ?? input.pool ?? fail();
}

function requiredUsdc(input: AuditCommitmentInput) {
  return input.usdcAddress ?? input.usdc ?? fail();
}

function normalizeFacts(input: AuditCommitmentInput): AuditRecord["facts"] {
  const poolAddress = requiredAddress(input);
  const usdcAddress = requiredUsdc(input);
  bytes(poolAddress, 20);
  bytes(usdcAddress, 20);
  bytes(input.poolVersion, 32);
  bytes(input.applicationId, 32);
  bytes(input.actionReference, 32);
  bytes(input.auditSalt, 32);
  asAction(input.action);
  for (const value of [...input.inputEnabled, ...input.outputEnabled]) {
    if (!Number.isInteger(value) || value < 0 || value > 255) {
      throw new SdkError("ENCODING_INVALID");
    }
  }
  return {
    chainId: asU64(input.chainId),
    poolVersion: input.poolVersion.toLowerCase(),
    applicationId: input.applicationId.toLowerCase(),
    action: input.action,
    authorizedUser: toHex(parseAddress(input.authorizedUser)),
    usdcAddress: toHex(parseAddress(usdcAddress)),
    publicAmount: asU64(input.publicAmount),
    publicRecipient: toHex(parseAddress(input.publicRecipient)),
    applicationPolicyVersion: asU64(input.applicationPolicyVersion),
    hazePolicyVersion: asU64(input.hazePolicyVersion),
    actionReference: input.actionReference.toLowerCase(),
    inputEnabled: [...input.inputEnabled] as [number, number],
    inputValues: [asU64(input.inputValues[0]), asU64(input.inputValues[1])],
    inputNotePublicKeys: [input.inputNotePublicKeys[0].toLowerCase(), input.inputNotePublicKeys[1].toLowerCase()],
    inputEncryptionKeyHashes: [input.inputEncryptionKeyHashes[0].toLowerCase(), input.inputEncryptionKeyHashes[1].toLowerCase()],
    inputNullifiers: [input.inputNullifiers[0].toLowerCase(), input.inputNullifiers[1].toLowerCase()],
    outputEnabled: [...input.outputEnabled] as [number, number],
    outputValues: [asU64(input.outputValues[0]), asU64(input.outputValues[1])],
    outputNotePublicKeys: [input.outputNotePublicKeys[0].toLowerCase(), input.outputNotePublicKeys[1].toLowerCase()],
    outputEncryptionKeyHashes: [input.outputEncryptionKeyHashes[0].toLowerCase(), input.outputEncryptionKeyHashes[1].toLowerCase()],
    outputCommitments: [input.outputCommitments[0].toLowerCase(), input.outputCommitments[1].toLowerCase()],
    recipientCiphertextHashes: [input.recipientCiphertextHashes[0].toLowerCase(), input.recipientCiphertextHashes[1].toLowerCase()],
    auditSalt: input.auditSalt.toLowerCase(),
    poolAddress: toHex(parseAddress(poolAddress)),
  };
}

function encodeUint(out: Buffer[], major: number, value: number | bigint) {
  const n = BigInt(asU64(value));
  if (n < 24n) {
    out.push(Buffer.from([(major << 5) | Number(n)]));
  } else if (n < 256n) {
    out.push(Buffer.from([(major << 5) | 24, Number(n)]));
  } else if (n < 65_536n) {
    const part = Buffer.alloc(3);
    part[0] = (major << 5) | 25;
    part.writeUInt16BE(Number(n), 1);
    out.push(part);
  } else if (n < 4_294_967_296n) {
    const part = Buffer.alloc(5);
    part[0] = (major << 5) | 26;
    part.writeUInt32BE(Number(n), 1);
    out.push(part);
  } else {
    const part = Buffer.alloc(9);
    part[0] = (major << 5) | 27;
    const view = new DataView(part.buffer, part.byteOffset, part.byteLength);
    view.setBigUint64(1, n, false);
    out.push(part);
  }
}

function encodeBytes(out: Buffer[], value: string | Uint8Array, length?: number) {
  const data = bytes(value, length);
  encodeUint(out, 2, data.length);
  out.push(data);
}

function encodeArray(out: Buffer[], values: Array<number | bigint | string>, kind: "uint" | "bytes32") {
  encodeUint(out, 4, values.length);
  for (const value of values) {
    if (kind === "uint") {
      encodeUint(out, 0, value as number | bigint);
    } else {
      encodeBytes(out, value as string, 32);
    }
  }
}

/** Encode the frozen v1 RFC 8949 audit record. */
export function encodeAuditRecord(record: AuditRecord): Uint8Array {
  const facts = normalizeFacts({ ...record.facts, poolAddress: record.facts.poolAddress, usdcAddress: record.facts.usdcAddress });
  const out: Buffer[] = [];
  encodeUint(out, 5, 2);
  encodeUint(out, 0, 1);
  encodeUint(out, 5, 24);
  encodeUint(out, 0, 1); encodeUint(out, 0, facts.chainId);
  encodeUint(out, 0, 2); encodeBytes(out, facts.poolAddress, 20);
  encodeUint(out, 0, 3); encodeBytes(out, facts.poolVersion, 32);
  encodeUint(out, 0, 4); encodeBytes(out, facts.applicationId, 32);
  encodeUint(out, 0, 5); encodeUint(out, 0, facts.action);
  encodeUint(out, 0, 6); encodeBytes(out, facts.authorizedUser, 20);
  encodeUint(out, 0, 7); encodeBytes(out, facts.usdcAddress, 20);
  encodeUint(out, 0, 8); encodeUint(out, 0, facts.publicAmount);
  encodeUint(out, 0, 9); encodeBytes(out, facts.publicRecipient, 20);
  encodeUint(out, 0, 10); encodeUint(out, 0, facts.applicationPolicyVersion);
  encodeUint(out, 0, 11); encodeUint(out, 0, facts.hazePolicyVersion);
  encodeUint(out, 0, 12); encodeBytes(out, facts.actionReference, 32);
  encodeUint(out, 0, 13); encodeArray(out, facts.inputEnabled, "uint");
  encodeUint(out, 0, 14); encodeArray(out, facts.inputValues, "uint");
  encodeUint(out, 0, 15); encodeArray(out, facts.inputNotePublicKeys, "bytes32");
  encodeUint(out, 0, 16); encodeArray(out, facts.inputEncryptionKeyHashes, "bytes32");
  encodeUint(out, 0, 17); encodeArray(out, facts.inputNullifiers, "bytes32");
  encodeUint(out, 0, 18); encodeArray(out, facts.outputEnabled, "uint");
  encodeUint(out, 0, 19); encodeArray(out, facts.outputValues, "uint");
  encodeUint(out, 0, 20); encodeArray(out, facts.outputNotePublicKeys, "bytes32");
  encodeUint(out, 0, 21); encodeArray(out, facts.outputEncryptionKeyHashes, "bytes32");
  encodeUint(out, 0, 22); encodeArray(out, facts.outputCommitments, "bytes32");
  encodeUint(out, 0, 23); encodeArray(out, facts.recipientCiphertextHashes, "bytes32");
  encodeUint(out, 0, 24); encodeBytes(out, facts.auditSalt, 32);
  encodeUint(out, 0, 2);
  encodeUint(out, 5, 1);
  encodeUint(out, 0, 1);
  encodeBytes(out, record.caseTag, undefined);
  return Buffer.concat(out);
}

function readUint(bytesInput: Buffer, cursor: { value: number }, major: number): bigint {
  const first = bytesInput[cursor.value++];
  if (first === undefined || first >> 5 !== major) fail();
  const extra = first & 0x1f;
  if (extra <= 23) return BigInt(extra);
  if (extra === 24) {
    const value = bytesInput[cursor.value++];
    if (value === undefined || value < 24) fail();
    return BigInt(value);
  }
  if (extra === 25) {
    if (cursor.value + 2 > bytesInput.length) fail();
    const value = bytesInput.readUInt16BE(cursor.value); cursor.value += 2;
    if (value < 256) fail();
    return BigInt(value);
  }
  if (extra === 26) {
    if (cursor.value + 4 > bytesInput.length) fail();
    const value = bytesInput.readUInt32BE(cursor.value); cursor.value += 4;
    if (value < 65_536) fail();
    return BigInt(value);
  }
  if (extra === 27) {
    if (cursor.value + 8 > bytesInput.length) fail();
    const view = new DataView(bytesInput.buffer, bytesInput.byteOffset, bytesInput.byteLength);
    const value = view.getBigUint64(cursor.value, false);
    cursor.value += 8;
    if (value < 4_294_967_296n) fail();
    return value;
  }
  fail();
}

function numberIfSafe(value: bigint): number | bigint {
  return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value;
}

function readBytes(bytesInput: Buffer, cursor: { value: number }, length?: number): Buffer {
  const size = readUint(bytesInput, cursor, 2);
  if (size > BigInt(bytesInput.length - cursor.value)) fail();
  const end = cursor.value + Number(size);
  const value = bytesInput.subarray(cursor.value, end);
  cursor.value = end;
  if (length !== undefined && value.length !== length) fail();
  return value;
}

function expectKey(bytesInput: Buffer, cursor: { value: number }, expected: number) {
  if (readUint(bytesInput, cursor, 0) !== BigInt(expected)) fail();
}

function readUintPair(bytesInput: Buffer, cursor: { value: number }) {
  if (readUint(bytesInput, cursor, 4) !== 2n) fail();
  return [numberIfSafe(readUint(bytesInput, cursor, 0)), numberIfSafe(readUint(bytesInput, cursor, 0))] as [number | bigint, number | bigint];
}

function readBytes32Pair(bytesInput: Buffer, cursor: { value: number }) {
  if (readUint(bytesInput, cursor, 4) !== 2n) fail();
  return [toHex(readBytes(bytesInput, cursor, 32)), toHex(readBytes(bytesInput, cursor, 32))] as [string, string];
}

/** Decode the frozen v1 RFC 8949 audit record and reject unknown/trailing data. */
export function decodeAuditRecord(value: string | Uint8Array): AuditRecord {
  const input = Buffer.from(typeof value === "string" ? parseHex(value) : value);
  const cursor = { value: 0 };
  if (readUint(input, cursor, 5) !== 2n) fail();
  expectKey(input, cursor, 1);
  if (readUint(input, cursor, 5) !== 24n) fail();
  expectKey(input, cursor, 1);
  const chainId = numberIfSafe(readUint(input, cursor, 0));
  expectKey(input, cursor, 2); const poolAddress = toHex(readBytes(input, cursor, 20));
  expectKey(input, cursor, 3); const poolVersion = toHex(readBytes(input, cursor, 32));
  expectKey(input, cursor, 4); const applicationId = toHex(readBytes(input, cursor, 32));
  expectKey(input, cursor, 5); const actionValue = readUint(input, cursor, 0); if (actionValue > 255n) fail(); const action = Number(actionValue);
  expectKey(input, cursor, 6); const authorizedUser = toHex(readBytes(input, cursor, 20));
  expectKey(input, cursor, 7); const usdcAddress = toHex(readBytes(input, cursor, 20));
  expectKey(input, cursor, 8); const publicAmount = numberIfSafe(readUint(input, cursor, 0));
  expectKey(input, cursor, 9); const publicRecipient = toHex(readBytes(input, cursor, 20));
  expectKey(input, cursor, 10); const applicationPolicyVersion = numberIfSafe(readUint(input, cursor, 0));
  expectKey(input, cursor, 11); const hazePolicyVersion = numberIfSafe(readUint(input, cursor, 0));
  expectKey(input, cursor, 12); const actionReference = toHex(readBytes(input, cursor, 32));
  expectKey(input, cursor, 13); const inputEnabled = readUintPair(input, cursor).map(Number) as [number, number];
  expectKey(input, cursor, 14); const inputValues = readUintPair(input, cursor);
  expectKey(input, cursor, 15); const inputNotePublicKeys = readBytes32Pair(input, cursor);
  expectKey(input, cursor, 16); const inputEncryptionKeyHashes = readBytes32Pair(input, cursor);
  expectKey(input, cursor, 17); const inputNullifiers = readBytes32Pair(input, cursor);
  expectKey(input, cursor, 18); const outputEnabled = readUintPair(input, cursor).map(Number) as [number, number];
  expectKey(input, cursor, 19); const outputValues = readUintPair(input, cursor);
  expectKey(input, cursor, 20); const outputNotePublicKeys = readBytes32Pair(input, cursor);
  expectKey(input, cursor, 21); const outputEncryptionKeyHashes = readBytes32Pair(input, cursor);
  expectKey(input, cursor, 22); const outputCommitments = readBytes32Pair(input, cursor);
  expectKey(input, cursor, 23); const recipientCiphertextHashes = readBytes32Pair(input, cursor);
  expectKey(input, cursor, 24); const auditSalt = toHex(readBytes(input, cursor, 32));
  expectKey(input, cursor, 2);
  if (readUint(input, cursor, 5) !== 1n) fail();
  expectKey(input, cursor, 1);
  const caseTag = toHex(readBytes(input, cursor));
  if (cursor.value !== input.length) fail();
  const facts: AuditRecord["facts"] = {
    chainId,
    poolAddress,
    poolVersion,
    applicationId,
    action,
    authorizedUser,
    usdcAddress,
    publicAmount,
    publicRecipient,
    applicationPolicyVersion,
    hazePolicyVersion,
    actionReference,
    inputEnabled,
    inputValues,
    inputNotePublicKeys,
    inputEncryptionKeyHashes,
    inputNullifiers,
    outputEnabled,
    outputValues,
    outputNotePublicKeys,
    outputEncryptionKeyHashes,
    outputCommitments,
    recipientCiphertextHashes,
    auditSalt,
  };
  normalizeFacts(facts);
  return { facts, caseTag };
}

/** Recompute the Poseidon2 commitment in the exact Rust field order. */
export function auditDataCommitment(input: AuditCommitmentInput): string {
  const facts = normalizeFacts(input);
  const [poolHi, poolLo] = bytes32Limbs(facts.poolVersion);
  const [appHi, appLo] = bytes32Limbs(facts.applicationId);
  const [refHi, refLo] = bytes32Limbs(facts.actionReference);
  const [rc0Hi, rc0Lo] = bytes32Limbs(facts.recipientCiphertextHashes[0]);
  const [rc1Hi, rc1Lo] = bytes32Limbs(facts.recipientCiphertextHashes[1]);
  const fields = [
    fieldFromU128(facts.chainId), fieldFromAddress(facts.poolAddress), poolHi, poolLo, appHi, appLo,
    fieldFromU128(facts.action), fieldFromAddress(facts.authorizedUser), fieldFromAddress(facts.usdcAddress),
    fieldFromU128(facts.publicAmount), fieldFromAddress(facts.publicRecipient), fieldFromU128(facts.applicationPolicyVersion),
    fieldFromU128(facts.hazePolicyVersion), refHi, refLo,
    fieldFromU128(facts.inputEnabled[0]), fieldFromU128(facts.inputEnabled[1]), fieldFromU128(facts.inputValues[0]), fieldFromU128(facts.inputValues[1]),
    fieldFromHex(facts.inputNotePublicKeys[0]), fieldFromHex(facts.inputNotePublicKeys[1]), fieldFromHex(facts.inputEncryptionKeyHashes[0]), fieldFromHex(facts.inputEncryptionKeyHashes[1]),
    fieldFromHex(facts.inputNullifiers[0]), fieldFromHex(facts.inputNullifiers[1]), fieldFromU128(facts.outputEnabled[0]), fieldFromU128(facts.outputEnabled[1]),
    fieldFromU128(facts.outputValues[0]), fieldFromU128(facts.outputValues[1]), fieldFromHex(facts.outputNotePublicKeys[0]), fieldFromHex(facts.outputNotePublicKeys[1]),
    fieldFromHex(facts.outputEncryptionKeyHashes[0]), fieldFromHex(facts.outputEncryptionKeyHashes[1]), fieldFromHex(facts.outputCommitments[0]), fieldFromHex(facts.outputCommitments[1]),
    rc0Hi, rc0Lo, rc1Hi, rc1Lo, fieldFromHex(facts.auditSalt),
  ];
  return fieldToHex(poseidon2Hash(domainField("haze/avalanche/v1/audit-data"), fields));
}

/** Rust-compatible audit AAD. */
export function auditAad(input: {
  chainId: number | bigint;
  pool: string;
  poolVersion: string;
  applicationId: string;
  auditKeyVersion: number | bigint;
  auditDataCommitment: string;
  action: number;
  actionReference: string;
}): Uint8Array {
  if (!Number.isInteger(input.action) || input.action < 0 || input.action > 255) throw new SdkError("ENCODING_INVALID");
  return Buffer.concat([
    u64be(input.chainId), parseAddress(input.pool), bytes(input.poolVersion, 32), bytes(input.applicationId, 32),
    u64be(input.auditKeyVersion), bytes(input.auditDataCommitment, 32), Buffer.from([input.action]), bytes(input.actionReference, 32),
  ]);
}

export function sealAuditRecord(input: {
  record: AuditRecord;
  recipientIkm: string;
  senderSeed: string;
  auditKeyVersion?: number | bigint;
}) {
  const record = { ...input.record, facts: normalizeFacts(input.record.facts) };
  const commitment = auditDataCommitment(record.facts);
  const auditKeyVersion = input.auditKeyVersion ?? DEVELOPMENT_AUDIT_KEY_VERSION;
  const aad = auditAad({
    chainId: record.facts.chainId,
    pool: record.facts.poolAddress,
    poolVersion: record.facts.poolVersion,
    applicationId: record.facts.applicationId,
    auditKeyVersion,
    auditDataCommitment: commitment,
    action: record.facts.action,
    actionReference: record.facts.actionReference,
  });
  const sealed = sealAuditEnvelope({
    recipientIkm: input.recipientIkm,
    senderSeed: input.senderSeed,
    aad,
    plaintext: encodeAuditRecord(record),
  });
  const envelope: Envelope = {
    purpose: "audit",
    keyVersion: BigInt(auditKeyVersion),
    encapsulatedKey: sealed.encapsulatedKey,
    ciphertext: sealed.ciphertext,
  };
  return {
    record,
    commitment,
    aad,
    envelope,
    plaintext: toHex(encodeAuditRecord(record)),
    bytes: toHex(encodeEnvelope(envelope)),
    hash: envelopeHash(envelope),
  };
}

export function openAuditRecord(input: {
  recipientIkm: string;
  envelope: string | Uint8Array | Envelope;
  expectedCommitment?: string;
  aad?: string | Uint8Array;
}): AuditRecord {
  const envelope = input.envelope instanceof Uint8Array || typeof input.envelope === "string"
    ? parseEnvelope(input.envelope)
    : input.envelope;
  if (envelope.purpose !== "audit") throw new SdkError("ENCODING_INVALID");
  if (!input.aad) throw new SdkError("ENCODING_INVALID");
  const plaintext = openAuditEnvelope({
    recipientIkm: input.recipientIkm,
    encapsulatedKey: envelope.encapsulatedKey,
    ciphertext: envelope.ciphertext,
    aad: input.aad,
  });
  const record = decodeAuditRecord(plaintext);
  if (input.expectedCommitment && auditDataCommitment(record.facts) !== input.expectedCommitment.toLowerCase()) {
    throw new SdkError("COMMITMENT_MISMATCH");
  }
  return record;
}
