import { decodeBrowserEnvelope, encodeBrowserEnvelope } from "./browser-crypto.ts";
import { SdkError } from "./errors.ts";
import { parseHex, toHex } from "./field.ts";
import { keccak256 } from "./keccak.ts";

export const RECIPIENT_INFO = "haze/avalanche/v1/recipient-note";
export const AUDIT_INFO = "haze/avalanche/v1/audit-record";
export type EnvelopePurpose = "recipient" | "audit";
export type Envelope = { purpose: EnvelopePurpose; keyVersion: bigint; encapsulatedKey: string; ciphertext: string };

export function encodeEnvelope(envelope: Envelope): Uint8Array {
  try {
    return encodeBrowserEnvelope({ ...envelope, encapsulatedKey: parseHex(envelope.encapsulatedKey), ciphertext: parseHex(envelope.ciphertext) });
  } catch (error) {
    throw new SdkError(error instanceof Error && error.message === "FIELD_OUT_OF_RANGE" ? "FIELD_OUT_OF_RANGE" : "ENCODING_INVALID");
  }
}
export function parseEnvelope(input: Uint8Array | string): Envelope {
  const bytes = typeof input === "string" ? parseHex(input) : input;
  try {
    const envelope = decodeBrowserEnvelope(bytes);
    return { ...envelope, encapsulatedKey: toHex(envelope.encapsulatedKey), ciphertext: toHex(envelope.ciphertext) };
  } catch { throw new SdkError("ENCODING_INVALID"); }
}
export function envelopeHash(envelope: Envelope): string { return toHex(keccak256(encodeEnvelope(envelope))); }
