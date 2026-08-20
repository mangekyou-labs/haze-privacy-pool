import { domainField } from "./domain.ts";
import { SdkError } from "./errors.ts";
import { bytes32Limbs, fieldFromAddress, fieldFromHex, fieldFromU128 } from "./field.ts";
import { poseidon2HashHex } from "./poseidon2.ts";
import { policyIsLive } from "./registry.ts";

export function applicationMember(
  applicationId: string,
  notePublicKey: string,
  encryptionKeyHash: string,
): string {
  const [hi, lo] = bytes32Limbs(applicationId);
  return poseidon2HashHex(domainField("haze/avalanche/v1/app-member"), [
    hi,
    lo,
    fieldFromHex(notePublicKey),
    fieldFromHex(encryptionKeyHash),
  ]);
}

export function globalBlockedNote(input: {
  chainId: number;
  applicationId: string;
  notePublicKey: string;
  encryptionKeyHash: string;
}): string {
  const [hi, lo] = bytes32Limbs(input.applicationId);
  return poseidon2HashHex(domainField("haze/avalanche/v1/block-note"), [
    fieldFromU128(input.chainId),
    hi,
    lo,
    fieldFromHex(input.notePublicKey),
    fieldFromHex(input.encryptionKeyHash),
  ]);
}

export function globalBlockedAddress(chainId: number, address: string): string {
  return poseidon2HashHex(domainField("haze/avalanche/v1/block-evm-address"), [
    fieldFromU128(chainId),
    fieldFromAddress(address),
  ]);
}

export function requireLivePolicy(
  activeVersion: bigint | number,
  activeRoot: string,
  version: bigint | number,
  root: string,
): void {
  if (!policyIsLive(activeVersion, activeRoot, version, root)) {
    throw new SdkError("VERSION_UNSUPPORTED");
  }
}
