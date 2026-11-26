import { SdkError } from "./errors.ts";
import { parseField, parseHex, readU64Be, toHex, u64be } from "./field.ts";
import { keccak256 } from "./keccak.ts";

const MAGIC = Buffer.from("HZAV");
const CODEC_VERSION = 1;
const ADDRESS_BYTES_LEN = 145;
const CHECKSUM_LABEL = Buffer.from("haze/avalanche/v1/address");

const LOW_ORDER_X25519 = [
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
  "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
];

export type HazeAddress = {
  chainId: number;
  applicationId: string;
  poolVersion: string;
  notePublicKey: string;
  x25519PublicKey: string;
};

function normalizeHex(bytes: Uint8Array): string {
  return toHex(bytes);
}

export function rejectLowOrderX25519(key: string | Uint8Array): Uint8Array {
  const bytes = typeof key === "string" ? Buffer.from(parseHex(key)) : Buffer.from(key);
  if (bytes.length !== 32) {
    throw new SdkError("ENCODING_INVALID");
  }
  const canonical = Buffer.from(bytes);
  canonical[31] &= 0x7f;
  const hex = bytes.toString("hex");
  const canonicalHex = canonical.toString("hex");
  if (LOW_ORDER_X25519.includes(hex) || LOW_ORDER_X25519.includes(canonicalHex)) {
    throw new SdkError("FIELD_OUT_OF_RANGE");
  }
  return bytes;
}

export function encodeHazeAddressBytes(address: HazeAddress): Uint8Array {
  parseField(address.notePublicKey);
  rejectLowOrderX25519(address.x25519PublicKey);
  const payload = Buffer.concat([
    MAGIC,
    Buffer.from([CODEC_VERSION]),
    u64be(address.chainId),
    parseHex(address.applicationId),
    parseHex(address.poolVersion),
    parseHex(address.notePublicKey),
    parseHex(address.x25519PublicKey),
  ]);
  if (payload.length !== 141) {
    throw new SdkError("ENCODING_INVALID");
  }
  const checksum = keccak256(Buffer.concat([CHECKSUM_LABEL, payload])).subarray(0, 4);
  return Buffer.concat([payload, Buffer.from(checksum)]);
}

function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function fromBase64Url(str: string): Buffer {
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = base64.length % 4;
  const padded = pad ? base64 + "=".repeat(4 - pad) : base64;
  return Buffer.from(padded, "base64");
}

export function encodeHazeAddress(address: HazeAddress): string {
  return `haze1:${toBase64Url(encodeHazeAddressBytes(address))}`;
}

export function parseHazeAddressBytes(bytes: Uint8Array): HazeAddress {
  const buffer = Buffer.from(bytes);
  if (buffer.length !== ADDRESS_BYTES_LEN) {
    throw new SdkError("ENCODING_INVALID");
  }
  if (!buffer.subarray(0, 4).equals(MAGIC)) {
    throw new SdkError("ENCODING_INVALID");
  }
  if (buffer[4] !== CODEC_VERSION) {
    throw new SdkError("VERSION_UNSUPPORTED");
  }
  const body = buffer.subarray(0, 141);
  const checksum = keccak256(Buffer.concat([CHECKSUM_LABEL, body])).subarray(0, 4);
  if (!buffer.subarray(141).equals(Buffer.from(checksum))) {
    throw new SdkError("ENCODING_INVALID");
  }
  const notePublicKey = parseField(buffer.subarray(77, 109));
  const x25519PublicKey = rejectLowOrderX25519(buffer.subarray(109, 141));
  return {
    chainId: Number(readU64Be(buffer, 5)),
    applicationId: normalizeHex(buffer.subarray(13, 45)),
    poolVersion: normalizeHex(buffer.subarray(45, 77)),
    notePublicKey: normalizeHex(notePublicKey),
    x25519PublicKey: normalizeHex(x25519PublicKey),
  };
}

export function decodeHazeAddress(text: string): HazeAddress {
  if (!text.startsWith("haze1:")) {
    throw new SdkError("ENCODING_INVALID");
  }
  const encoded = text.slice("haze1:".length);
  if (encoded.includes("=")) {
    throw new SdkError("ENCODING_INVALID");
  }
  let bytes: Buffer;
  try {
    bytes = fromBase64Url(encoded);
  } catch {
    throw new SdkError("ENCODING_INVALID");
  }
  return parseHazeAddressBytes(bytes);
}

export function requireAddressBinding(
  address: HazeAddress,
  expected: { chainId: number; applicationId: string; poolVersion: string },
): void {
  if (address.chainId !== expected.chainId) {
    throw new SdkError("CHAIN_MISMATCH");
  }
  if (address.applicationId.toLowerCase() !== expected.applicationId.toLowerCase()) {
    throw new SdkError("APPLICATION_MISMATCH");
  }
  if (address.poolVersion.toLowerCase() !== expected.poolVersion.toLowerCase()) {
    throw new SdkError("POOL_VERSION_MISMATCH");
  }
}
