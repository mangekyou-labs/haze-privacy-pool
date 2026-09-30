import { SdkError } from "./errors.ts";
import { parseHex, toHex } from "./field.ts";
import { keccak256 } from "./keccak.ts";

export const RECIPIENT_INFO = "haze/avalanche/v1/recipient-note";
export const AUDIT_INFO = "haze/avalanche/v1/audit-record";

const MAGIC = Buffer.from("HZHP");
const ENVELOPE_VERSION = 1;
const KEM_ID = 0x0020;
const KDF_ID = 0x0001;
const AEAD_ID = 0x0003;
const X25519_ENCAP_LEN = 32;
const AEAD_TAG_LEN = 16;
const FIXED = 4 + 1 + 1 + 2 + 2 + 2 + 8 + 2;

export type EnvelopePurpose = "recipient" | "audit";

export type Envelope = {
  purpose: EnvelopePurpose;
  keyVersion: bigint;
  encapsulatedKey: string;
  ciphertext: string;
};

function purposeByte(purpose: EnvelopePurpose): number {
  if (purpose === "recipient") {
    return 1;
  }
  if (purpose === "audit") {
    return 2;
  }
  throw new SdkError("ENCODING_INVALID");
}

function validate(envelope: Envelope) {
  if (envelope.purpose === "recipient" && envelope.keyVersion !== 0n) {
    throw new SdkError("ENCODING_INVALID");
  }
  const encap = parseHex(envelope.encapsulatedKey);
  const ciphertext = parseHex(envelope.ciphertext);
  if (encap.length !== X25519_ENCAP_LEN) {
    throw new SdkError("ENCODING_INVALID");
  }
  if (ciphertext.length < AEAD_TAG_LEN) {
    throw new SdkError("ENCODING_INVALID");
  }
  return { encap, ciphertext };
}

export function encodeEnvelope(envelope: Envelope): Uint8Array {
  const { encap, ciphertext } = validate(envelope);
  return Buffer.concat([
    MAGIC,
    Buffer.from([ENVELOPE_VERSION, purposeByte(envelope.purpose)]),
    Buffer.from([KEM_ID >> 8, KEM_ID & 0xff, KDF_ID >> 8, KDF_ID & 0xff, AEAD_ID >> 8, AEAD_ID & 0xff]),
    Buffer.from([
      Number((envelope.keyVersion >> 56n) & 0xffn),
      Number((envelope.keyVersion >> 48n) & 0xffn),
      Number((envelope.keyVersion >> 40n) & 0xffn),
      Number((envelope.keyVersion >> 32n) & 0xffn),
      Number((envelope.keyVersion >> 24n) & 0xffn),
      Number((envelope.keyVersion >> 16n) & 0xffn),
      Number((envelope.keyVersion >> 8n) & 0xffn),
      Number(envelope.keyVersion & 0xffn),
    ]),
    Buffer.from([encap.length >> 8, encap.length & 0xff]),
    encap,
    Buffer.from([
      (ciphertext.length >>> 24) & 0xff,
      (ciphertext.length >>> 16) & 0xff,
      (ciphertext.length >>> 8) & 0xff,
      ciphertext.length & 0xff,
    ]),
    ciphertext,
  ]);
}

export function parseEnvelope(bytes: Uint8Array | string): Envelope {
  const buffer = typeof bytes === "string" ? parseHex(bytes) : Buffer.from(bytes);
  if (buffer.length < FIXED + 4) {
    throw new SdkError("ENCODING_INVALID");
  }
  if (!buffer.subarray(0, 4).equals(MAGIC)) {
    throw new SdkError("ENCODING_INVALID");
  }
  if (buffer[4] !== ENVELOPE_VERSION) {
    throw new SdkError("VERSION_UNSUPPORTED");
  }
  const purpose = buffer[5] === 1 ? "recipient" : buffer[5] === 2 ? "audit" : undefined;
  if (!purpose) {
    throw new SdkError("ENCODING_INVALID");
  }
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  const kem = view.getUint16(6, false);
  const kdf = view.getUint16(8, false);
  const aead = view.getUint16(10, false);
  if (kem !== KEM_ID || kdf !== KDF_ID || aead !== AEAD_ID) {
    throw new SdkError("ENCODING_INVALID");
  }
  const keyVersion = view.getBigUint64(12, false);
  const encapLen = view.getUint16(20, false);
  const encapEnd = FIXED + encapLen;
  const ctLenEnd = encapEnd + 4;
  if (buffer.length < ctLenEnd) {
    throw new SdkError("ENCODING_INVALID");
  }
  const ciphertextLen = view.getUint32(encapEnd, false);
  const end = ctLenEnd + ciphertextLen;
  if (buffer.length !== end) {
    throw new SdkError("ENCODING_INVALID");
  }
  const envelope: Envelope = {
    purpose,
    keyVersion,
    encapsulatedKey: toHex(buffer.subarray(FIXED, encapEnd)),
    ciphertext: toHex(buffer.subarray(ctLenEnd, end)),
  };
  validate(envelope);
  return envelope;
}

export function envelopeHash(envelope: Envelope): string {
  return toHex(keccak256(encodeEnvelope(envelope)));
}
