#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { assembleAudit } from "./audit.mjs";
import { verifyTranscript } from "./ceremony/lib.mjs";
import { assembleReview } from "./security-review.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const EVIDENCE = [
  "dev/artifacts/circuit-build-manifest.json",
  "dev/artifacts/rehearsal-ceremony.json",
  "dev/artifacts/rehearsal-signed-manifest.json",
  "dev/artifacts/DevelopmentEqualityVerifier.sol",
  "dev/artifacts/provenance.json",
  "dev/runbooks/production-ceremony.md",
  "dev/fixtures/audit.json",
];

const REMAINING = [
  {
    id: "M-01",
    title: "Production spend Groth16 keys are not generated",
    owner: "protocol",
    disposition: "approved-deferral",
    until: "T7.5",
    reason: "KEYS_MISSING",
  },
  {
    id: "M-03",
    title: "Fuji gas remeasure is required before mainnet budgets",
    owner: "protocol",
    disposition: "approved-deferral",
    until: "T7.5",
    reason: "FUJI_GAS",
  },
];

function hazePath(relative) {
  return join(HAZE_ROOT, relative);
}

function readHaze(relative) {
  return readFileSync(hazePath(relative), "utf8");
}

function loadJson(relative) {
  return JSON.parse(readHaze(relative));
}

function requireExists(relative) {
  if (!existsSync(hazePath(relative))) {
    throw new Error(`missing ceremony-release evidence: ${relative}`);
  }
}

function requireContains(relative, needles, label) {
  const text = readHaze(relative);
  for (const needle of needles) {
    if (!text.includes(needle)) {
      throw new Error(`${label}: ${relative} missing ${needle}`);
    }
  }
}

function hashCanonical(value) {
  return `0x${createHash("sha256").update(JSON.stringify(value)).digest("hex")}`;
}

function requireFindingUntil(findings, id, until, reason, label) {
  const finding = findings.find((item) => item.id === id);
  if (!finding) {
    throw new Error(`${label} missing ${id}`);
  }
  if (finding.until !== until || finding.reason !== reason) {
    throw new Error(`${label} ${id} must remain ${reason} until ${until}`);
  }
}

function circuitFreeze() {
  const manifest = loadJson("dev/artifacts/circuit-build-manifest.json");
  if (manifest.circuit_id !== "haze-spend-v1") {
    throw new Error("ceremony freeze selected the wrong circuit");
  }
  if (manifest.n_constraints !== 588459) {
    throw new Error("ceremony freeze constraint count drifted");
  }
  if (manifest.circom_version !== "2.2.3") {
    throw new Error("ceremony freeze Circom version drifted");
  }
  if (manifest.not_for_production !== true || manifest.profile !== "development") {
    throw new Error("ceremony freeze must remain a development spend circuit");
  }
  return {
    circuitId: manifest.circuit_id,
    nConstraints: manifest.n_constraints,
    circomVersion: manifest.circom_version,
    sourceHash: manifest.source_hash,
    r1csHash: manifest.r1cs_hash,
    buildHash: manifest.build_hash,
    notForProduction: true,
  };
}

function inspectEvidence() {
  for (const relative of EVIDENCE) {
    requireExists(relative);
  }
  requireContains(
    "dev/runbooks/production-ceremony.md",
    ["T7.3", "KEYS_MISSING", "588459", "documented-rehearsed"],
    "ceremony-process",
  );
  requireContains(
    "dev/artifacts/DevelopmentEqualityVerifier.sol",
    ["NOT_FOR_PRODUCTION", "DevelopmentEqualityVerifier"],
    "generated-verifier",
  );
}

export function assembleCeremonyRelease() {
  inspectEvidence();
  const audit = assembleAudit();
  const review = assembleReview();
  const provenance = loadJson("dev/artifacts/provenance.json");
  if (provenance.sc09?.production_ceremony?.approved === true) {
    throw new Error("T7.4 must not flip SC-09 production_ceremony.approved");
  }
  if (provenance.spend_prove !== "KEYS_MISSING") {
    throw new Error("T7.4 must keep production spend keys missing");
  }
  const keys = review.findings.medium.find((finding) => finding.id === "M-01");
  if (keys && (keys.until !== "T7.5" || keys.reason !== "KEYS_MISSING")) {
    throw new Error("security-review M-01 must remain KEYS_MISSING until remediating");
  }
  const auditKeys = audit.findings.medium.find((finding) => finding.id === "M-01");
  if (auditKeys && (auditKeys.until !== "T7.5" || auditKeys.reason !== "KEYS_MISSING")) {
    throw new Error("audit M-01 must remain KEYS_MISSING until remediating");
  }
  const auditGas = audit.findings.medium.find((finding) => finding.id === "M-03");
  if (auditGas && (auditGas.until !== "T7.5" || auditGas.reason !== "FUJI_GAS")) {
    throw new Error("audit M-03 must remain FUJI_GAS until remediating");
  }
  const transcript = loadJson("dev/artifacts/rehearsal-ceremony.json");
  if (transcript.not_for_production !== true) {
    throw new Error("rehearsal transcript must stay not_for_production");
  }
  if (transcript.circuit_id !== "haze-development-equality-v1") {
    throw new Error("T7.4 must verify the development equality transcript, not a live spend MPC");
  }
  verifyTranscript(transcript);
  const signed = loadJson("dev/artifacts/rehearsal-signed-manifest.json");
  if (signed.not_for_production !== true) {
    throw new Error("signed rehearsal manifest must stay not_for_production");
  }
  const freeze = circuitFreeze();
  const canonical = {
    notForProduction: true,
    kind: "library-production-ceremony",
    contributionProcess: "documented-rehearsed",
    liveMpc: false,
    transcriptVerified: true,
    transcript: {
      circuitId: transcript.circuit_id,
      contributions: transcript.contributions.length,
      finalTranscript: transcript.final_transcript,
    },
    auditHash: audit.hash,
    circuitFreeze: freeze,
    verifier: {
      file: "dev/artifacts/DevelopmentEqualityVerifier.sol",
      notForProduction: true,
    },
    signedManifest: {
      file: "dev/artifacts/rehearsal-signed-manifest.json",
      notForProduction: true,
      signer: signed.signer,
    },
    spendProve: "KEYS_MISSING",
    findings: {
      medium: REMAINING,
    },
    remediations: ["M-01"],
    coverage: ["SC-09"],
    sc09: { productionCeremonyApproved: false },
    verdict: "pass-library-ceremony",
  };
  return {
    ...canonical,
    hash: hashCanonical(canonical),
  };
}

export function verifyCeremonyRelease() {
  const report = assembleCeremonyRelease();
  const published = loadJson("dev/fixtures/ceremony-release.json");
  if (published.fixtureHash !== report.hash) {
    throw new Error("published ceremony-release fixture hash mismatch");
  }
  if (published.not_for_production !== true) {
    throw new Error("ceremony-release is not labeled development");
  }
  if (published.kind !== "library-production-ceremony") {
    throw new Error("published ceremony-release kind drifted");
  }
  if (published.sc09_production_ceremony_approved !== false) {
    throw new Error("published ceremony-release must keep SC-09 closed");
  }
  if (published.spend_prove !== "KEYS_MISSING") {
    throw new Error("published ceremony-release must keep spend keys missing");
  }
  if (published.verdict !== report.verdict) {
    throw new Error("published ceremony-release verdict drifted");
  }
  return { fixtureHash: report.hash, notForProduction: true };
}

function main(argv) {
  const command = argv[0] ?? "verify";
  if (command === "verify") {
    const verified = verifyCeremonyRelease();
    process.stdout.write(`ceremony-release-verify ok ${verified.fixtureHash}\n`);
    return;
  }
  if (command === "assemble") {
    process.stdout.write(`${JSON.stringify(assembleCeremonyRelease(), null, 2)}\n`);
    return;
  }
  throw new Error(`unknown ceremony-release command: ${command}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2));
}
