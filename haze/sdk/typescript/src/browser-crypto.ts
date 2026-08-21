import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { x25519 } from "@noble/curves/ed25519";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";

const text = new TextEncoder();
const KEM_SUITE = concat(text.encode("KEM"), Uint8Array.of(0, 0x20));
const HPKE_SUITE = concat(text.encode("HPKE"), Uint8Array.of(0, 0x20, 0, 1, 0, 3));
const MAGIC = text.encode("HZHP");

function fail(code: string): never { throw new Error(code); }
function concat(...parts: Uint8Array[]) {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}
function equal(a: Uint8Array, b: Uint8Array) {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}
function be(value: bigint, length: number) {
  const out = new Uint8Array(length);
  for (let index = length - 1; index >= 0; index -= 1) { out[index] = Number(value & 255n); value >>= 8n; }
  if (value !== 0n) fail("ENCODING_INVALID");
  return out;
}
function readBe(bytes: Uint8Array) { return bytes.reduce((value, byte) => (value << 8n) | BigInt(byte), 0n); }
function extract(salt: Uint8Array, ikm: Uint8Array) { return hmac(sha256, salt.length ? salt : new Uint8Array(32), ikm); }
function expand(prk: Uint8Array, info: Uint8Array, length: number) {
  let previous = new Uint8Array(); const output: Uint8Array[] = [];
  for (let index = 1; output.reduce((n, part) => n + part.length, 0) < length; index += 1) {
    previous = hmac(sha256, prk, concat(previous, info, Uint8Array.of(index)));
    output.push(previous);
  }
  return concat(...output).slice(0, length);
}
function labeledExtract(suite: Uint8Array, salt: Uint8Array, label: string, ikm: Uint8Array) {
  return extract(salt, concat(text.encode("HPKE-v1"), suite, text.encode(label), ikm));
}
function labeledExpand(suite: Uint8Array, prk: Uint8Array, label: string, info: Uint8Array, length: number) {
  return expand(prk, concat(be(BigInt(length), 2), text.encode("HPKE-v1"), suite, text.encode(label), info), length);
}
function keypair(ikm: Uint8Array) {
  if (ikm.length !== 32) fail("ENCODING_INVALID");
  const prk = labeledExtract(KEM_SUITE, new Uint8Array(), "dkp_prk", ikm);
  const secret = labeledExpand(KEM_SUITE, prk, "sk", new Uint8Array(), 32);
  return { secret, publicKey: x25519.getPublicKey(secret) };
}
function schedule(shared: Uint8Array, info: Uint8Array) {
  const empty = new Uint8Array();
  const psk = labeledExtract(HPKE_SUITE, empty, "psk_id_hash", empty);
  const infoHash = labeledExtract(HPKE_SUITE, empty, "info_hash", info);
  const context = concat(Uint8Array.of(0), psk, infoHash);
  const secret = labeledExtract(HPKE_SUITE, shared, "secret", empty);
  return { key: labeledExpand(HPKE_SUITE, secret, "key", context, 32), nonce: labeledExpand(HPKE_SUITE, secret, "base_nonce", context, 12) };
}
function sharedSecret(secret: Uint8Array, peerPublic: Uint8Array, encap: Uint8Array, recipientPublic: Uint8Array) {
  const dh = x25519.scalarMult(secret, peerPublic);
  const prk = labeledExtract(KEM_SUITE, new Uint8Array(), "eae_prk", dh);
  return labeledExpand(KEM_SUITE, prk, "shared_secret", concat(encap, recipientPublic), 32);
}

export function openBrowserHpke(input: { recipientIkm: Uint8Array; encapsulatedKey: Uint8Array; ciphertext: Uint8Array; info: Uint8Array; aad: Uint8Array }) {
  try {
    const recipient = keypair(input.recipientIkm);
    const context = schedule(sharedSecret(recipient.secret, input.encapsulatedKey, input.encapsulatedKey, recipient.publicKey), input.info);
    return chacha20poly1305(context.key, context.nonce, input.aad).decrypt(input.ciphertext);
  } catch { return fail("CIPHERTEXT_INVALID"); }
}

export function sealBrowserHpke(input: { recipientIkm: Uint8Array; ephemeralSeed: Uint8Array; plaintext: Uint8Array; info: Uint8Array; aad: Uint8Array }) {
  const recipient = keypair(input.recipientIkm);
  const ephemeral = keypair(input.ephemeralSeed);
  const context = schedule(sharedSecret(ephemeral.secret, recipient.publicKey, ephemeral.publicKey, recipient.publicKey), input.info);
  return { encapsulatedKey: ephemeral.publicKey, ciphertext: chacha20poly1305(context.key, context.nonce, input.aad).encrypt(input.plaintext) };
}

export type BrowserEnvelope = { purpose: "recipient" | "audit"; keyVersion: bigint; encapsulatedKey: Uint8Array; ciphertext: Uint8Array };
export function encodeBrowserEnvelope(value: BrowserEnvelope) {
  if (value.encapsulatedKey.length !== 32 || value.ciphertext.length < 16 || (value.purpose === "recipient" && value.keyVersion !== 0n)) fail("ENCODING_INVALID");
  return concat(MAGIC, Uint8Array.of(1, value.purpose === "recipient" ? 1 : 2, 0, 0x20, 0, 1, 0, 3), be(value.keyVersion, 8), be(32n, 2), value.encapsulatedKey, be(BigInt(value.ciphertext.length), 4), value.ciphertext);
}
export function decodeBrowserEnvelope(bytes: Uint8Array): BrowserEnvelope {
  if (bytes.length < 58 || !equal(bytes.slice(0, 4), MAGIC) || bytes[4] !== 1 || bytes[6] !== 0 || bytes[7] !== 0x20 || bytes[8] !== 0 || bytes[9] !== 1 || bytes[10] !== 0 || bytes[11] !== 3) fail("ENCODING_INVALID");
  const purpose = bytes[5] === 1 ? "recipient" : bytes[5] === 2 ? "audit" : fail("ENCODING_INVALID");
  const keyVersion = readBe(bytes.slice(12, 20)); const encapLength = Number(readBe(bytes.slice(20, 22)));
  const ctLengthOffset = 22 + encapLength; if (encapLength !== 32 || bytes.length < ctLengthOffset + 4) fail("ENCODING_INVALID");
  const ctLength = Number(readBe(bytes.slice(ctLengthOffset, ctLengthOffset + 4))); const end = ctLengthOffset + 4 + ctLength;
  if (ctLength < 16 || end !== bytes.length || (purpose === "recipient" && keyVersion !== 0n)) fail("ENCODING_INVALID");
  return { purpose, keyVersion, encapsulatedKey: bytes.slice(22, ctLengthOffset), ciphertext: bytes.slice(ctLengthOffset + 4, end) };
}
export function browserAuditAad(input: { chainId: bigint; pool: Uint8Array; poolVersion: Uint8Array; applicationId: Uint8Array; keyVersion: bigint; auditDataCommitment: Uint8Array; action: number; actionReference: Uint8Array }) {
  if (input.pool.length !== 20 || [input.poolVersion, input.applicationId, input.auditDataCommitment, input.actionReference].some((part) => part.length !== 32) || input.action < 0 || input.action > 255) fail("ENCODING_INVALID");
  return concat(be(input.chainId, 8), input.pool, input.poolVersion, input.applicationId, be(input.keyVersion, 8), input.auditDataCommitment, Uint8Array.of(input.action), input.actionReference);
}
