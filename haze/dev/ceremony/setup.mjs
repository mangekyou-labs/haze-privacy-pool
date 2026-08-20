#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { resolveCircom } from "../../circuits/witness.mjs";
import {
  CIRCOM_VERSION,
  HAZE_ROOT,
  SPEND_CIRCUIT_ID,
  SPEND_N_CONSTRAINTS,
  computeBuildHash,
  fileKeccak,
  toHex,
} from "./lib.mjs";

const artifacts = join(HAZE_ROOT, "dev/artifacts");
mkdirSync(artifacts, { recursive: true });

const circom = resolveCircom(HAZE_ROOT);
const version = execFileSync(circom, ["--version"], { encoding: "utf8" });
if (!version.includes(CIRCOM_VERSION)) {
  throw new Error(`expected Circom ${CIRCOM_VERSION}, got ${version.trim()}`);
}

const sourceHash = toHex(fileKeccak(join(HAZE_ROOT, "circuits/src/spend.circom")));
const r1csHash = toHex(fileKeccak(join(HAZE_ROOT, "circuits/build/spend/spend.r1cs")));
const fixtureHash = toHex(fileKeccak(join(HAZE_ROOT, "circuits/vectors/v1/haze-spend-v1.json")));
const manifest = {
  schema_version: 1,
  circuit_id: SPEND_CIRCUIT_ID,
  profile: "development",
  not_for_production: true,
  circom_version: CIRCOM_VERSION,
  n_constraints: SPEND_N_CONSTRAINTS,
  source_hash: sourceHash,
  r1cs_hash: r1csHash,
  fixture_hash: fixtureHash,
  build_hash: computeBuildHash(sourceHash, r1csHash, fixtureHash, SPEND_N_CONSTRAINTS),
};

writeFileSync(join(artifacts, "circuit-build-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);

const provenance = {
  product_id: "haze-avalanche-compliant-pool",
  chain_family: "avalanche-c-chain",
  profile: "development",
  not_for_production: true,
  circuit_id: SPEND_CIRCUIT_ID,
  n_constraints: SPEND_N_CONSTRAINTS,
  circom_version: CIRCOM_VERSION,
  spend_prove: "KEYS_MISSING",
  sc09: {
    fuji_pilot: { approved: false, artifact_hash: null },
    independent_audit: { approved: false, artifact_hash: null },
    production_ceremony: { approved: false, artifact_hash: null },
    incident_review: { approved: false, artifact_hash: null },
  },
};

writeFileSync(join(artifacts, "provenance.json"), `${JSON.stringify(provenance, null, 2)}\n`);
process.stdout.write("haze ceremony setup wrote circuit-build-manifest.json and provenance.json\n");
