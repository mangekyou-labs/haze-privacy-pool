import { CIRCOM_VERSION, SPEND_CIRCUIT_ID, SPEND_N_CONSTRAINTS, activationBlocked } from "./lib.mjs";
import { versionError } from "./ptau.mjs";

export const PINNED_SPEND = {
  circuit_id: SPEND_CIRCUIT_ID,
  circom_version: CIRCOM_VERSION,
  n_constraints: SPEND_N_CONSTRAINTS,
  source_hash: "0xddab1e2d4aca797058f3e3aca49c99a1bd5a396f3c3bf8dd1bc3c47a8e1fd9b1",
  r1cs_hash: "0x98cc762ccc18a9a3b0aba3b6be3dba217c928629cf8f330a09779ffa5e23f02d",
  fixture_hash: "0x7b55ab0190cbe83541e9763c1bf314776cf378af3b3018a060c836c53c7979df",
  build_hash: "0x533f1d9d172c8395b4849bd7b90901b5314b7fc4735b878385e22b5a19d3cd41",
};

export function assertSpendCircuitPin(manifest) {
  const checks = [
    ["circuit_id", PINNED_SPEND.circuit_id],
    ["circom_version", PINNED_SPEND.circom_version],
    ["n_constraints", PINNED_SPEND.n_constraints],
    ["source_hash", PINNED_SPEND.source_hash],
    ["r1cs_hash", PINNED_SPEND.r1cs_hash],
    ["fixture_hash", PINNED_SPEND.fixture_hash],
    ["build_hash", PINNED_SPEND.build_hash],
  ];
  for (const [key, expected] of checks) {
    if (manifest?.[key] !== expected) {
      throw versionError("VERSION_UNSUPPORTED");
    }
  }
  return { ...PINNED_SPEND };
}

export function assertCommittedFujiUnchanged(fuji) {
  if (fuji?.broadcast !== false || fuji?.spend_prove !== "KEYS_MISSING") {
    throw versionError("VERSION_UNSUPPORTED");
  }
  return true;
}

export function productionActivationAllowed({ attestation, provenance } = {}) {
  if (!attestation || activationBlocked(provenance)) {
    return false;
  }
  return Boolean(provenance?.sc09?.production_ceremony?.approved);
}

export { refuseRehearsalAsSpendZkey } from "./phase2.mjs";
export { ptauSpec, requiredPtauPower } from "./ptau.mjs";
export { publicTranscript } from "./export.mjs";
