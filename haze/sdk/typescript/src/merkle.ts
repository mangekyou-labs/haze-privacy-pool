import { domainField } from "./domain.ts";
import { SdkError } from "./errors.ts";
import { BN254_R, fieldFromHex, fieldFromU128, fieldToHex } from "./field.ts";
import { poseidon2HashHex } from "./poseidon2.ts";

export const APP_TREE = "haze/avalanche/v1/app-tree-node";
export const BLOCK_TREE = "haze/avalanche/v1/block-tree-node";
export const TREE_DEPTH = 32;
export const BLOCKLIST_LOWER_SENTINEL =
  "0x0000000000000000000000000000000000000000000000000000000000000000";

export function blocklistUpperSentinel(): string {
  return fieldToHex(BN254_R - 1n);
}

export function parentNode(domain: string, level: number, left: string, right: string): string {
  return poseidon2HashHex(domainField(domain), [
    fieldFromU128(level),
    fieldFromHex(left),
    fieldFromHex(right),
  ]);
}

export function rootFromPath(
  domain: string,
  leaf: string,
  index: number,
  siblings: string[],
): string {
  if (siblings.length !== TREE_DEPTH) {
    throw new SdkError("ENCODING_INVALID");
  }
  let node = leaf;
  let cursor = index;
  for (let level = 0; level < TREE_DEPTH; level += 1) {
    node =
      (cursor & 1) === 0
        ? parentNode(domain, level, node, siblings[level])
        : parentNode(domain, level, siblings[level], node);
    cursor >>= 1;
  }
  return node;
}
