import { SdkError } from "./errors.ts";

export const BN254_R = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;
const BN254_R_BYTES = Buffer.from("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", "hex");

export function parseHex(value: string): Buffer {
  if (!/^0x[0-9a-fA-F]*$/.test(value) || value.length % 2 !== 0) {
    throw new SdkError("ENCODING_INVALID");
  }
  return Buffer.from(value.slice(2), "hex");
}

export function toHex(bytes: Uint8Array): string {
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

export function fieldToHex(value: bigint): string {
  if (value < 0n || value >= BN254_R) {
    throw new SdkError("FIELD_OUT_OF_RANGE");
  }
  return `0x${value.toString(16).padStart(64, "0")}`;
}

export function parseField(value: string | Uint8Array): Buffer {
  const bytes = typeof value === "string" ? parseHex(value) : Buffer.from(value);
  if (bytes.length !== 32) {
    throw new SdkError("ENCODING_INVALID");
  }
  if (bytes.compare(BN254_R_BYTES) >= 0) {
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
  const bytes = typeof value === "string" ? parseHex(value) : Buffer.from(value);
  if (bytes.length !== 32) {
    throw new SdkError("ENCODING_INVALID");
  }
  return [BigInt(toHex(bytes.subarray(0, 16))), BigInt(toHex(bytes.subarray(16)))];
}

export function u64be(value: number | bigint): Buffer {
  const n = typeof value === "number" ? BigInt(value) : value;
  if (n < 0n || n > 0xffffffffffffffffn) {
    throw new SdkError("FIELD_OUT_OF_RANGE");
  }
  const out = Buffer.alloc(8);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  view.setBigUint64(0, n, false);
  return out;
}

export function parseAddress(address: string): Buffer {
  const bytes = parseHex(address);
  if (bytes.length !== 20) {
    throw new SdkError("ENCODING_INVALID");
  }
  return bytes;
}
