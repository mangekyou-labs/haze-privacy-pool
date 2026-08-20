import { rejectLowOrderX25519 } from "./address.ts";
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
  rejectLowOrderX25519(x25519PublicKey);
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
}): Buffer {
  const value = typeof plaintext.value === "number" ? BigInt(plaintext.value) : plaintext.value;
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(value);
  return Buffer.concat([
    out,
    parseHex(plaintext.blinding),
    parseHex(plaintext.notePublicKey),
    parseHex(plaintext.encryptionKeyHash),
    parseHex(plaintext.applicationId),
    parseHex(plaintext.poolVersion),
    parseHex(plaintext.commitment),
  ]);
}
