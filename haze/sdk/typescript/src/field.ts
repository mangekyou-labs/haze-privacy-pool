import { SdkError } from "./errors.ts";

export const BN254_R = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;
const textHex = (value: string) => Uint8Array.from(value.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));
const BN254_R_BYTES = textHex("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
function compare(left: Uint8Array, right: Uint8Array) {
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return left[index] < right[index] ? -1 : 1;
  }
  return 0;
}

export function parseHex(value: string): Uint8Array {
  if (!/^0x[0-9a-fA-F]*$/.test(value) || value.length % 2 !== 0) {
    throw new SdkError("ENCODING_INVALID");
  }
  return textHex(value.slice(2));
}

export function toHex(bytes: Uint8Array): string {
  return `0x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

export function fieldToHex(value: bigint): string {
  if (value < 0n || value >= BN254_R) {
    throw new SdkError("FIELD_OUT_OF_RANGE");
  }
  return `0x${value.toString(16).padStart(64, "0")}`;
}

export function parseField(value: string | Uint8Array): Uint8Array {
  const bytes = typeof value === "string" ? parseHex(value) : Uint8Array.from(value);
  if (bytes.length !== 32) {
    throw new SdkError("ENCODING_INVALID");
  }
  if (compare(bytes, BN254_R_BYTES) >= 0) {
    throw new SdkError("FIELD_OUT_OF_RANGE");
  }
  return bytes;
}

export function fieldFromBytes(bytes: Uint8Array): bigint {
  return BigInt(toHex(parseField(bytes)));
}

export function fieldFromHex(value: string): bigint {
  return BigInt(toHex(parseField(value)));
}

export function reduceModR(digest: Uint8Array): bigint {
  return BigInt(toHex(digest)) % BN254_R;
}

export function fieldFromU128(value: bigint | number): bigint {
  const n = typeof value === "number" ? BigInt(value) : value;
  if (n < 0n || n >= 1n << 128n) {
    throw new SdkError("FIELD_OUT_OF_RANGE");
  }
  return n;
}

export function fieldFromAddress(address: string): bigint {
  const bytes = parseHex(address);
  if (bytes.length !== 20) {
    throw new SdkError("ENCODING_INVALID");
  }
  return BigInt(toHex(bytes));
}

export function bytes32Limbs(value: string | Uint8Array): [bigint, bigint] {
  const bytes = typeof value === "string" ? parseHex(value) : Uint8Array.from(value);
  if (bytes.length !== 32) {
    throw new SdkError("ENCODING_INVALID");
  }
  return [BigInt(toHex(bytes.subarray(0, 16))), BigInt(toHex(bytes.subarray(16)))];
}

export function u64be(value: number | bigint): Uint8Array {
  const n = typeof value === "number" ? BigInt(value) : value;
  if (n < 0n || n > 0xffffffffffffffffn) {
    throw new SdkError("FIELD_OUT_OF_RANGE");
  }
  const out = new Uint8Array(8);
  let cursor = n;
  for (let index = 7; index >= 0; index -= 1) { out[index] = Number(cursor & 255n); cursor >>= 8n; }
  return out;
}

export function parseAddress(address: string): Uint8Array {
  const bytes = parseHex(address);
  if (bytes.length !== 20) {
    throw new SdkError("ENCODING_INVALID");
  }
  return bytes;
}
