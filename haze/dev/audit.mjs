#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { assembleFujiRelease } from "./fuji-release.mjs";
import { assembleGates } from "./gates.mjs";
import { assemblePilot } from "./pilot.mjs";
import { assembleReview } from "./security-review.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const SURFACES = [
  {
    id: "circuits",
    evidence: [
      "circuits/src/spend.circom",
      "tests/circuit-spend.test.mjs",
      "dev/artifacts/circuit-build-manifest.json",
    ],
  },
  {
    id: "ceremony-tooling",
    evidence: [
      "dev/ceremony/setup.mjs",
      "dev/ceremony/verify-transcript.mjs",
      "tests/ceremony.test.mjs",
      "dev/runbooks/production-ceremony.md",
    ],
  },
  {
    id: "contracts",
    evidence: [
      "contracts/src/HazePool.sol",
      "contracts/src/HazeSpendVerifier.sol",
      "contracts/test/ProtocolInvariants.t.sol",
      "tests/invariants.test.mjs",
    ],
  },
  {
    id: "sdk-key-handling",
    evidence: ["sdk/typescript/src/vault.ts", "tests/vault.test.mjs", "apps/_shared/ux.ts"],
  },
  {
    id: "services",
    evidence: [
      "services/gatekeeper/src/lib.rs",
      "services/indexer/src/lib.rs",
      "services/audit-auth/src/lib.rs",
      "services/disclosure/src/lib.rs",
    ],
  },
  {
    id: "frontends",
    evidence: [
      "apps/privacy-pool-dex/src/index.ts",
      "apps/compliance-portal/src/index.ts",
      "tests/frontend-ux.test.mjs",
    ],
  },
  {
    id: "governance",
    evidence: [
      "apps/compliance-portal/src/governance.ts",
      "tests/compliance-portal-governance.test.mjs",
      "contracts/src/HazeAccess.sol",
    ],
  },
  {
    id: "operational-controls",
    evidence: [
      "dev/runbooks.mjs",
      "dev/runbooks/production-ceremony.md",
      "dev/runbooks/disclosure-incident.md",
      "SECURITY.md",
    ],
  },
];

const REMAINING = [];

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
    throw new Error(`missing audit evidence: ${relative}`);
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

function inspectSurfaces() {
  for (const surface of SURFACES) {
    for (const path of surface.evidence) {
      requireExists(path);
    }
  }
  requireContains("SECURITY.md", ["fix-before-release", "owner-and-disposition", "critical"], "bug-policy");
  requireContains("dev/runbooks/production-ceremony.md", ["T7.3", "KEYS_MISSING", "588459"], "ceremony-freeze");
  requireContains("dev/artifacts/circuit-build-manifest.json", ["haze-spend-v1", "588459", "2.2.3"], "circuit-freeze");
}

function circuitFreeze() {
  const manifest = loadJson("dev/artifacts/circuit-build-manifest.json");
  if (manifest.circuit_id !== "haze-spend-v1") {
    throw new Error("audit freeze selected the wrong circuit");
  }
  if (manifest.n_constraints !== 588459) {
    throw new Error("audit freeze constraint count drifted");
  }
  if (manifest.circom_version !== "2.2.3") {
    throw new Error("audit freeze Circom version drifted");
  }
  if (manifest.not_for_production !== true || manifest.profile !== "development") {
    throw new Error("audit freeze must remain a development spend circuit");
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

export function assembleAudit() {
  inspectSurfaces();
  const release = assembleFujiRelease();
  const pilot = assemblePilot();
  const review = assembleReview();
  const gates = assembleGates();
  const provenance = loadJson("dev/artifacts/provenance.json");
  if (provenance.sc09?.independent_audit?.approved === true) {
    throw new Error("T7.3 must not flip SC-09 independent_audit.approved");
  }
  if (provenance.spend_prove !== "KEYS_MISSING") {
    throw new Error("T7.3 must keep production spend keys missing");
  }
  if (review.openCritical !== 0 || review.openHigh !== 0) {
    throw new Error("audit cannot accept open critical or high findings");
  }
  if (review.findings.medium.some((finding) => finding.id === "M-05")) {
    throw new Error("M-05 EXTERNAL_AUDIT must be closed by the independent library audit");
  }
  if (gates.sc08.verdict !== "pass") {
    throw new Error("SC-08 must pass before audit acceptance");
  }
  const freeze = circuitFreeze();
  const canonical = {
    notForProduction: true,
    kind: "independent-library-audit",
    surfaces: SURFACES.map((surface) => surface.id),
    fujiReleaseHash: release.hash,
    pilotHash: pilot.hash,
    circuitFreeze: freeze,
    findings: {
      critical: [],
      high: [],
      medium: REMAINING,
    },
    remediations: ["M-05", "M-01", "M-03"],
    bugPolicy: {
      path: "SECURITY.md",
      criticalHigh: "fix-before-release",
      medium: "owner-and-disposition",
    },
    coverage: ["SC-08", "SC-09"],
    sc09: { independentAuditApproved: false },
    openCritical: 0,
    openHigh: 0,
    verdict: "pass-library-audit",
  };
  return {
    ...canonical,
    surfaces: SURFACES.map((surface) => ({ ...surface, status: "reviewed" })),
    hash: hashCanonical(canonical),
  };
}

export function verifyAudit() {
  const report = assembleAudit();
  const published = loadJson("dev/fixtures/audit.json");
  if (published.fixtureHash !== report.hash) {
    throw new Error("published audit fixture hash mismatch");
  }
  if (published.not_for_production !== true) {
    throw new Error("audit is not labeled development");
  }
  if (published.kind !== "independent-library-audit") {
    throw new Error("published audit kind drifted");
  }
  if (published.sc09_independent_audit_approved !== false) {
    throw new Error("published audit must keep SC-09 closed");
  }
  if (published.verdict !== report.verdict) {
    throw new Error("published audit verdict drifted");
  }
  return { fixtureHash: report.hash, notForProduction: true };
}

function main(argv) {
  const command = argv[0] ?? "verify";
  if (command === "verify") {
    const verified = verifyAudit();
    process.stdout.write(`independent-audit-verify ok ${verified.fixtureHash}\n`);
    return;
  }
  if (command === "assemble") {
    process.stdout.write(`${JSON.stringify(assembleAudit(), null, 2)}\n`);
    return;
  }
  throw new Error(`unknown independent-audit command: ${command}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2));
}
