import { readFile } from "node:fs/promises";
import { keccak256 } from "./keccak.ts";
import type { ArtifactSet } from "./prover-session.ts";

export {
  ProverError,
  SPEND_PUBLIC_CAMEL,
  checkSpendPublicInputs,
  createProverSession,
  deriveShieldedAccount,
  deriveShieldedAccountFromSignature,
  developmentProofDigest,
  encodeOperatorGroth16Proof,
  handleProverWorkerMessage,
  keyDerivationDigest,
  spendPublicInputs,
  verifyDevelopmentSpend,
  verifyProductionSpend,
} from "./prover-session.ts";
export type {
  ArtifactSet,
  DevelopmentProof,
  OperatorGroth16Proof,
  ProverErrorCode,
  ProverSession,
  ShieldedAccount,
  ShieldedAccountRequest,
  ShieldedAccountSignatureRequest,
  WorkerInbound,
  WorkerOutbound,
} from "./prover-session.ts";

function toHex(bytes: Uint8Array) {
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

/** Hash committed proving-bundle files. Host/Node only — not imported by the worker graph. */
export async function hashArtifactSet(set: ArtifactSet) {
  const digests = await Promise.all(
    [set.circuit, set.fixture, set.manifest].map(async (path) => keccak256(await readFile(path))),
  );
  return toHex(keccak256(Buffer.concat(digests.map((digest) => Buffer.from(digest)))));
}
