import { createCipheriv, createDecipheriv, createHmac } from "node:crypto";
import { x25519 } from "@noble/curves/ed25519";
import { RECIPIENT_INFO } from "./envelope.ts";
import { SdkError } from "./errors.ts";
import { parseAddress, parseHex, toHex, u64be } from "./field.ts";
import { encodeRecipientPlaintext } from "./note.ts";

export type RecipientPlaintext = {
  value: bigint;
  blinding: string;
  notePublicKey: string;
  encryptionKeyHash: string;
  applicationId: string;
  poolVersion: string;
  commitment: string;
};

const KEM_SUITE = Buffer.concat([Buffer.from("KEM"), Buffer.from([0x00, 0x20])]);
const HPKE_SUITE = Buffer.concat([Buffer.from("HPKE"), Buffer.from([0x00, 0x20, 0x00, 0x01, 0x00, 0x03])]);

function extract(salt: Buffer, ikm: Buffer) {
  return createHmac("sha256", salt.length === 0 ? Buffer.alloc(32) : salt).update(ikm).digest();
}

function expand(prk: Buffer, info: Buffer, length: number) {
  const blocks = Math.ceil(length / 32);
  let previous = Buffer.alloc(0);
  const out = [];
  for (let index = 1; index <= blocks; index += 1) {
    previous = createHmac("sha256", prk)
      .update(Buffer.concat([previous, info, Buffer.from([index])]))
      .digest();
    out.push(previous);
  }
  return Buffer.concat(out).subarray(0, length);
}

function labeledExtract(suiteId: Buffer, salt: Buffer, label: string, ikm: Buffer) {
  return extract(salt, Buffer.concat([Buffer.from("HPKE-v1"), suiteId, Buffer.from(label), ikm]));
}

function labeledExpand(suiteId: Buffer, prk: Buffer, label: string, info: Buffer, length: number) {
  return expand(
    prk,
    Buffer.concat([
      Buffer.from([(length >> 8) & 0xff, length & 0xff]),
      Buffer.from("HPKE-v1"),
      suiteId,
      Buffer.from(label),
      info,
    ]),
    length,
  );
}

export function deriveX25519KeyPair(ikm: string | Uint8Array): { secret: Buffer; publicKey: Buffer } {
  const bytes = typeof ikm === "string" ? parseHex(ikm) : Buffer.from(ikm);
  if (bytes.length !== 32) {
    throw new SdkError("ENCODING_INVALID");
  }
  const dkpPrk = labeledExtract(KEM_SUITE, Buffer.alloc(0), "dkp_prk", bytes);
  const secret = labeledExpand(KEM_SUITE, dkpPrk, "sk", Buffer.alloc(0), 32);
  return { secret, publicKey: Buffer.from(x25519.getPublicKey(secret)) };
}

function extractAndExpand(dh: Buffer, kemContext: Buffer) {
  const eaePrk = labeledExtract(KEM_SUITE, Buffer.alloc(0), "eae_prk", dh);
  return labeledExpand(KEM_SUITE, eaePrk, "shared_secret", kemContext, 32);
}

function keySchedule(sharedSecret: Buffer, info: Buffer) {
  const pskIdHash = labeledExtract(HPKE_SUITE, Buffer.alloc(0), "psk_id_hash", Buffer.alloc(0));
  const infoHash = labeledExtract(HPKE_SUITE, Buffer.alloc(0), "info_hash", info);
  const context = Buffer.concat([Buffer.from([0x00]), pskIdHash, infoHash]);
  const secret = labeledExtract(HPKE_SUITE, sharedSecret, "secret", Buffer.alloc(0));
  return {
    key: labeledExpand(HPKE_SUITE, secret, "key", context, 32),
    nonce: labeledExpand(HPKE_SUITE, secret, "base_nonce", context, 12),
  };
}

function requireRecipientInfo(info: string) {
  if (info !== RECIPIENT_INFO) {
    throw new SdkError("DOMAIN_MISMATCH");
  }
}

function asBytes(value: string | Uint8Array): Buffer {
  return typeof value === "string" ? parseHex(value) : Buffer.from(value);
}

function setupBaseR(recipientIkm: Buffer, encapsulatedKey: Buffer, info: Buffer) {
  const recipient = deriveX25519KeyPair(recipientIkm);
  const dh = Buffer.from(x25519.scalarMult(recipient.secret, encapsulatedKey));
  const shared = extractAndExpand(dh, Buffer.concat([encapsulatedKey, recipient.publicKey]));
  return keySchedule(shared, info);
}

function setupBaseS(recipientPublic: Buffer, senderSeed: Buffer, info: Buffer) {
  const ephemeral = deriveX25519KeyPair(senderSeed);
  const dh = Buffer.from(x25519.scalarMult(ephemeral.secret, recipientPublic));
  const shared = extractAndExpand(dh, Buffer.concat([ephemeral.publicKey, recipientPublic]));
  return { ...keySchedule(shared, info), encapsulatedKey: ephemeral.publicKey };
}

function aeadOpen(key: Buffer, nonce: Buffer, aad: Buffer, ciphertext: Buffer) {
  try {
    const decipher = createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
    decipher.setAAD(aad, { plaintextLength: ciphertext.length - 16 });
    decipher.setAuthTag(ciphertext.subarray(ciphertext.length - 16));
    return Buffer.concat([decipher.update(ciphertext.subarray(0, ciphertext.length - 16)), decipher.final()]);
  } catch {
    throw new SdkError("CIPHERTEXT_INVALID");
  }
}

function aeadSeal(key: Buffer, nonce: Buffer, aad: Buffer, plaintext: Buffer) {
  const cipher = createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  cipher.setAAD(aad, { plaintextLength: plaintext.length });
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([body, cipher.getAuthTag()]);
}

export function recipientAad(input: {
  chainId: number;
  pool: string;
  poolVersion: string;
  applicationId: string;
  outputIndex: number;
  outputCommitment: string;
  envelopeVersion: number;
}): Uint8Array {
  return Buffer.concat([
    u64be(input.chainId),
    parseAddress(input.pool),
    parseHex(input.poolVersion),
    parseHex(input.applicationId),
    Buffer.from([input.outputIndex]),
    parseHex(input.outputCommitment),
    Buffer.from([input.envelopeVersion]),
  ]);
}

export function parseRecipientPlaintext(bytes: Uint8Array): RecipientPlaintext {
  const buffer = Buffer.from(bytes);
  if (buffer.length !== 200) {
    throw new SdkError("ENCODING_INVALID");
  }
  return {
    value: buffer.readBigUInt64BE(0),
    blinding: toHex(buffer.subarray(8, 40)),
    notePublicKey: toHex(buffer.subarray(40, 72)),
    encryptionKeyHash: toHex(buffer.subarray(72, 104)),
    applicationId: toHex(buffer.subarray(104, 136)),
    poolVersion: toHex(buffer.subarray(136, 168)),
    commitment: toHex(buffer.subarray(168, 200)),
  };
}

export function openRecipientNote(input: {
  recipientIkm: string;
  encapsulatedKey: string;
  ciphertext: string;
  info: string;
  aad: string | Uint8Array;
}): Uint8Array {
  requireRecipientInfo(input.info);
  const ctx = setupBaseR(parseHex(input.recipientIkm), parseHex(input.encapsulatedKey), Buffer.from(input.info));
  return aeadOpen(ctx.key, ctx.nonce, asBytes(input.aad), parseHex(input.ciphertext));
}

export function sealRecipientNote(input: {
  recipientIkm: string;
  senderSeed: string;
  aad: string | Uint8Array;
  plaintext: RecipientPlaintext | Uint8Array;
}): { encapsulatedKey: string; ciphertext: string } {
  const recipient = deriveX25519KeyPair(input.recipientIkm);
  const ctx = setupBaseS(recipient.publicKey, parseHex(input.senderSeed), Buffer.from(RECIPIENT_INFO));
  const plaintext =
    input.plaintext instanceof Uint8Array
      ? Buffer.from(input.plaintext)
      : encodeRecipientPlaintext(input.plaintext);
  return {
    encapsulatedKey: toHex(ctx.encapsulatedKey),
    ciphertext: toHex(aeadSeal(ctx.key, ctx.nonce, asBytes(input.aad), plaintext)),
  };
}
