import { SdkError } from "./errors.ts";
import { bytes32Limbs, fieldFromAddress, fieldFromU128, reduceModR } from "./field.ts";
import { keccak256 } from "./keccak.ts";
import { poseidon2Hash } from "./poseidon2.ts";

export const DOMAIN_LABELS = [
  "haze/avalanche/v1/protocol",
  "haze/avalanche/v1/pool",
  "haze/avalanche/v1/note-key",
  "haze/avalanche/v1/encryption-key",
  "haze/avalanche/v1/note",
  "haze/avalanche/v1/nullifier",
  "haze/avalanche/v1/note-tree-node",
  "haze/avalanche/v1/app-tree-node",
  "haze/avalanche/v1/block-tree-node",
  "haze/avalanche/v1/app-member",
  "haze/avalanche/v1/block-note",
  "haze/avalanche/v1/block-evm-address",
  "haze/avalanche/v1/audit-data",
] as const;

export function domainField(label: string): bigint {
  if (!(DOMAIN_LABELS as readonly string[]).includes(label)) {
    throw new SdkError("DOMAIN_MISMATCH");
  }
  return reduceModR(keccak256(new TextEncoder().encode(label)));
}

export function protocolVersionTag(): bigint {
  return domainField("haze/avalanche/v1/protocol");
}

export function poolDomain(chainId: number, pool: string, poolVersion: string): bigint {
  const [versionHi, versionLo] = bytes32Limbs(poolVersion);
  return poseidon2Hash(domainField("haze/avalanche/v1/pool"), [
    protocolVersionTag(),
    fieldFromU128(chainId),
    fieldFromAddress(pool),
    versionHi,
    versionLo,
  ]);
}
