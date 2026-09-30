import { keccak256 } from "./keccak.ts";

/** Decode a `0x`-prefixed hex string. */
export function hexToBuf(value: string): Buffer {
  const hex = value.replace(/^0x/i, "");
  if (hex.length % 2 !== 0) {
    throw new Error("ENCODING_INVALID");
  }
  return Buffer.from(hex, "hex");
}

/** Encode bytes as lowercase `0x` hex. */
export function toHex(bytes: Uint8Array): string {
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

/** Concatenate multiple byte arrays. */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** Left-pad a value to 32 bytes. */
export function pad32(bytes: Uint8Array): Buffer {
  if (bytes.length > 32) throw new Error("ENCODING_INVALID");
  const out = new Uint8Array(32);
  out.set(bytes, 32 - bytes.length);
  return Buffer.from(out);
}

/** ABI word for an EVM address. */
export function addressWord(address: string): Buffer {
  return pad32(hexToBuf(address));
}

/** ABI word for a `bytes32`. */
export function bytes32Word(value: string): Buffer {
  const raw = hexToBuf(value);
  if (raw.length !== 32) {
    throw new Error("ENCODING_INVALID");
  }
  return Buffer.from(raw);
}

/** ABI word for an unsigned integer. */
export function uintWord(value: number | bigint | string): Buffer {
  if (typeof value === "string" && /^0x/i.test(value)) {
    return pad32(hexToBuf(value));
  }
  const hex = BigInt(value).toString(16).padStart(64, "0");
  return Buffer.from(hex, "hex");
}

/** Keccak-256 as lowercase hex. */
export function keccakHex(data: Uint8Array): string {
  return toHex(keccak256(data));
}

/** First four bytes of `keccak256(signature)`. */
export function functionSelector(signature: string): string {
  return toHex(keccak256(Buffer.from(signature))).slice(0, 10);
}

/** Concatenate 32-byte ABI words. */
export function encodeWords(words: Uint8Array[]): Buffer {
  return Buffer.concat(words.map((word) => Buffer.from(word)));
}
