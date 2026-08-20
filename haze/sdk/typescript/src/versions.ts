import { HAZE_CHAIN_FAMILY, HAZE_PRODUCT_ID } from "./identity.ts";
import { SdkError } from "./errors.ts";

/** Canonical Fuji client/runtime compatibility pin. */
export const FUJI_COMPATIBILITY = {
  productId: HAZE_PRODUCT_ID,
  chainFamily: HAZE_CHAIN_FAMILY,
  chainId: 43113,
  schemaVersion: 1,
  apiVersion: 1,
  contractDomainVersion: "1",
  protocolVersionTag: "0x2afe8a5679df289719eae23ad89b300434b9dfbb8194dad0b50dee97f91a3868",
  circuitArtifactHash: "0xac2082ecb2129c571d2ddeb170f261a0da074491773102fa4f1544e97eb19281",
  manifestVersion: 1,
} as const;

export type CompatibilityView = {
  productId: string;
  chainFamily: string;
  chainId: number;
  schemaVersion: number;
  apiVersion: number;
  contractDomainVersion: string;
  protocolVersionTag: string;
  circuitArtifactHash: string;
  manifestVersion: number;
};

function sameHex(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

/** Accept only matching chain, contract, manifest, circuit, and API versions. */
export function checkCompatibility(
  observed: CompatibilityView,
  expected: CompatibilityView = FUJI_COMPATIBILITY,
): { ok: true } {
  if (observed.chainId !== expected.chainId) {
    throw new SdkError("CHAIN_MISMATCH");
  }
  if (
    observed.productId !== expected.productId ||
    observed.chainFamily !== expected.chainFamily ||
    observed.schemaVersion !== expected.schemaVersion ||
    observed.apiVersion !== expected.apiVersion ||
    observed.contractDomainVersion !== expected.contractDomainVersion ||
    observed.manifestVersion !== expected.manifestVersion ||
    !sameHex(observed.protocolVersionTag, expected.protocolVersionTag) ||
    !sameHex(observed.circuitArtifactHash, expected.circuitArtifactHash)
  ) {
    throw new SdkError("VERSION_UNSUPPORTED");
  }
  return { ok: true };
}
