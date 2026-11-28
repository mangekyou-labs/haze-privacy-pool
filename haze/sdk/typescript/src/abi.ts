import { keccak256 } from "./keccak.ts";

export function hexToBuf(value: string): Uint8Array {
  const hex = value.replace(/^0x/i, "");
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) throw new Error("ENCODING_INVALID");
  return Uint8Array.from(hex.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));
}
export function toHex(bytes: Uint8Array): string {
  return `0x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0; for (const part of parts) { out.set(part, offset); offset += part.length; } return out;
}
export function pad32(bytes: Uint8Array): Uint8Array {
  if (bytes.length > 32) throw new Error("ENCODING_INVALID");
  const out = new Uint8Array(32); out.set(bytes, 32 - bytes.length); return out;
}
export function addressWord(address: string): Uint8Array {
  const bytes = hexToBuf(address); if (bytes.length !== 20) throw new Error("ENCODING_INVALID"); return pad32(bytes);
}
export function bytes32Word(value: string): Uint8Array {
  const raw = hexToBuf(value); if (raw.length !== 32) throw new Error("ENCODING_INVALID"); return raw;
}
export function uintWord(value: number | bigint | string): Uint8Array {
  const n = typeof value === "string" && value.startsWith("0x") ? BigInt(value) : BigInt(value);
  if (n < 0n || n >= 1n << 256n) throw new Error("ENCODING_INVALID");
  return hexToBuf(`0x${n.toString(16).padStart(64, "0")}`);
}
export function canonicalUint256(value: string | number | bigint): string {
  let parsed: bigint;
  try {
    if (typeof value === "number") {
      if (!Number.isSafeInteger(value) || value < 0) throw new Error("ENCODING_INVALID");
      parsed = BigInt(value);
    } else if (typeof value === "bigint") {
      parsed = value;
    } else if (/^0x[0-9a-fA-F]{64}$/.test(value) || /^(0|[1-9][0-9]*)$/.test(value)) {
      parsed = BigInt(value);
    } else {
      throw new Error("ENCODING_INVALID");
    }
  } catch {
    throw new Error("ENCODING_INVALID");
  }
  if (parsed < 0n || parsed >= 1n << 256n) throw new Error("ENCODING_INVALID");
  return `0x${parsed.toString(16).padStart(64, "0")}`;
}
export function keccakHex(data: Uint8Array): string { return toHex(keccak256(data)); }
export function functionSelector(signature: string): string { return toHex(keccak256(new TextEncoder().encode(signature))).slice(0, 10); }
export function encodeWords(words: Uint8Array[]): Uint8Array {
  if (words.some((word) => word.length !== 32)) throw new Error("ENCODING_INVALID"); return concatBytes(...words);
}
