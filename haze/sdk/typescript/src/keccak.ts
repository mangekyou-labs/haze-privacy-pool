import { keccak_256 } from "@noble/hashes/sha3";

/** Ethereum Keccak-256, implemented by the audited browser-safe noble hash. */
export function keccak256(data: Uint8Array): Uint8Array {
  return keccak_256(data);
}
