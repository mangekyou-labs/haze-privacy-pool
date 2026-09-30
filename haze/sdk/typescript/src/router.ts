import { keccak256 } from "./keccak.ts";

/** Swap-and-shield action accepted only through the router. */
export const SWAP_AND_SHIELD_ACTION = 4 as const;

/** Provider-neutral route bound into the signed intent. */
export interface SwapRoute {
  adapter: string;
  data: Uint8Array | string;
  expectedRouteHash: string;
}

function hexToBuf(value: string): Buffer {
  return Buffer.from(value.replace(/^0x/i, ""), "hex");
}

function toHex(bytes: Uint8Array): string {
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

function addressWord(address: string): Buffer {
  const raw = hexToBuf(address);
  const out = new Uint8Array(32);
  out.set(raw, 32 - raw.length);
  return Buffer.from(out);
}

function word(value: number | bigint): Buffer {
  const hex = BigInt(value).toString(16).padStart(64, "0");
  return Buffer.from(hex, "hex");
}

/** ABI-encode `(address adapter, bytes data)` for `routeHash`. */
export function encodeRoute(adapter: string, data: Uint8Array | string): Uint8Array {
  const payload = typeof data === "string" ? hexToBuf(data) : Buffer.from(data);
  const paddedLen = Math.ceil(payload.length / 32) * 32;
  const padded = new Uint8Array(paddedLen);
  padded.set(payload);
  return Buffer.concat([addressWord(adapter), word(0x40), word(payload.length), Buffer.from(padded)]);
}

/** `keccak256(abi.encode(adapter, data))` bound to the swap intent. */
export function routeHash(adapter: string, data: Uint8Array | string): string {
  return toHex(keccak256(encodeRoute(adapter, data)));
}

export function swapRoute(adapter: string, data: Uint8Array | string): SwapRoute {
  return { adapter, data, expectedRouteHash: routeHash(adapter, data) };
}
