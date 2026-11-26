import { domainField, poolDomain } from "./domain.ts";
import { SdkError } from "./errors.ts";
import { bytes32Limbs, fieldFromHex, fieldFromU128, parseHex } from "./field.ts";
import { poseidon2HashHex } from "./poseidon2.ts";

export function notePublicKey(spendingSecret: string): string {
  const secret = fieldFromHex(spendingSecret);
  if (secret === 0n) {
    throw new SdkError("FIELD_OUT_OF_RANGE");
  }
  return poseidon2HashHex(domainField("haze/avalanche/v1/note-key"), [secret]);
}

export function encryptionKeyHash(x25519PublicKey: string): string {
  const key = parseHex(x25519PublicKey);
  const lowOrder = new Set([
    "0".repeat(64), `01${"0".repeat(62)}`,
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  ]);
  if (key.length !== 32) throw new SdkError("ENCODING_INVALID");
  const raw = Array.from(key, (byte) => byte.toString(16).padStart(2, "0")).join("");
  const canonical = Uint8Array.from(key); canonical[31] &= 0x7f;
  const canonicalHex = Array.from(canonical, (byte) => byte.toString(16).padStart(2, "0")).join("");
  if (lowOrder.has(raw) || lowOrder.has(canonicalHex)) throw new SdkError("FIELD_OUT_OF_RANGE");
  const [hi, lo] = bytes32Limbs(x25519PublicKey);
  return poseidon2HashHex(domainField("haze/avalanche/v1/encryption-key"), [hi, lo]);
}

export function noteCommitment(input: {
  chainId: number;
  pool: string;
  poolVersion: string;
  applicationId: string;
  value: bigint | number;
  ownerNotePublicKey: string;
  ownerEncryptionKeyHash: string;
  blinding: string;
}): string {
  const blinding = fieldFromHex(input.blinding);
  if (blinding === 0n) {
    throw new SdkError("FIELD_OUT_OF_RANGE");
  }
  const [appHi, appLo] = bytes32Limbs(input.applicationId);
  return poseidon2HashHex(domainField("haze/avalanche/v1/note"), [
    poolDomain(input.chainId, input.pool, input.poolVersion),
    appHi,
    appLo,
    fieldFromU128(input.value),
    fieldFromHex(input.ownerNotePublicKey),
    fieldFromHex(input.ownerEncryptionKeyHash),
    blinding,
  ]);
}

export function nullifier(input: {
  chainId: number;
  pool: string;
  poolVersion: string;
  applicationId: string;
  commitment: string;
  leafIndex: number;
  spendingSecret: string;
}): string {
  const [appHi, appLo] = bytes32Limbs(input.applicationId);
  return poseidon2HashHex(domainField("haze/avalanche/v1/nullifier"), [
    poolDomain(input.chainId, input.pool, input.poolVersion),
    appHi,
    appLo,
    fieldFromHex(input.commitment),
    fieldFromU128(input.leafIndex),
    fieldFromHex(input.spendingSecret),
  ]);
}

export function encodeRecipientPlaintext(plaintext: {
  value: bigint | number;
  blinding: string;
  notePublicKey: string;
  encryptionKeyHash: string;
  applicationId: string;
  poolVersion: string;
  commitment: string;
  spendingSecret?: string;
}): Uint8Array {
  const value = typeof plaintext.value === "number" ? BigInt(plaintext.value) : plaintext.value;
  const out = new Uint8Array(8);
  let cursor = value;
  for (let index = 7; index >= 0; index -= 1) { out[index] = Number(cursor & 255n); cursor >>= 8n; }
  if (cursor !== 0n) throw new SdkError("FIELD_OUT_OF_RANGE");
  const parts = [
    out,
    parseHex(plaintext.blinding),
    parseHex(plaintext.notePublicKey),
    parseHex(plaintext.encryptionKeyHash),
    parseHex(plaintext.applicationId),
    parseHex(plaintext.poolVersion),
    parseHex(plaintext.commitment),
  ];
  if (plaintext.spendingSecret !== undefined && plaintext.spendingSecret !== "") {
    parts.push(parseHex(plaintext.spendingSecret));
  }
  const encoded = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) { encoded.set(part, offset); offset += part.length; }
  return encoded;
}
