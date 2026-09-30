/**
 * Leaf secp256k1 recovery helpers (keccak + @noble/curves only).
 *
 * No snarkjs / prover imports here so serverless BFF bundles can verify
 * `personal_sign` signatures without dragging the Groth16 prover graph.
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak256 } from "./keccak.ts";
import { toHex } from "./field.ts";

/** Recover the Ethereum address that produced a 65-byte recoverable secp256k1 signature. */
export function recoverWallet(digest: Uint8Array, normalized: Uint8Array): string {
  const recovered = secp256k1.Signature.fromCompact(normalized.subarray(0, 64))
    .addRecoveryBit(normalized[64])
    .recoverPublicKey(digest)
    .toRawBytes(false);
  const address = keccak256(recovered.subarray(1)).subarray(12);
  return toHex(address);
}

/** Recover the signer of an EIP-191 `personal_sign` message. */
export function recoverPersonalSign(message: string, signature: string): string {
  if (!signature || !/^0x[0-9a-fA-F]{130}$/.test(signature)) {
    throw new Error("UNAUTHORIZED");
  }
  const prefixed = `\x19Ethereum Signed Message:\n${message.length}${message}`;
  const digest = keccak256(Buffer.from(prefixed, "utf8"));
  const normalized = Buffer.from(signature.slice(2), "hex");
  return recoverWallet(digest, normalized);
}
