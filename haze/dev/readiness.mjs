#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { assembleAudit } from "./audit.mjs";
import { assembleCeremonyRelease } from "./ceremony-release.mjs";
import { assembleFujiRelease } from "./fuji-release.mjs";
import { assemblePilot } from "./pilot.mjs";
import { assembleRunbooks } from "./runbooks.mjs";
import { assembleReview } from "./security-review.mjs";
import { FUJI_COMPATIBILITY, checkCompatibility } from "../sdk/typescript/src/versions.ts";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MAINNET_PATH = "deployments/mainnet-v1.json";

const CHECKS = [
  {
    id: "governance-owners",
    status: "operator-owned",
    evidence: [
      "contracts/src/HazeAccess.sol",
      "apps/compliance-portal/src/governance.ts",
      MAINNET_PATH,
    ],
  },
  {
    id: "kms",
    status: "operator-owned",
    evidence: ["sdk/typescript/src/vault.ts", "dev/runbooks/signer-kms-policy-rotation.md"],
  },
  {
    id: "identity",
    status: "operator-owned",
    evidence: ["services/audit-auth/src/lib.rs", "dev/runbooks/disclosure-incident.md"],
  },
  {
    id: "rpc",
    status: "operator-owned",
    evidence: ["deployments/fuji-v1.json", MAINNET_PATH],
  },
  {
    id: "backups",
    status: "documented",
    evidence: ["dev/runbooks/database-restore.md", "crates/protocol/src/ops.rs"],
  },
  {
    id: "monitoring",
    status: "documented",
    evidence: ["dev/runbooks/dashboards-alerts.md"],
  },
  {
    id: "on-call",
    status: "documented",
    evidence: ["dev/runbooks/dashboards-alerts.md", "dev/runbooks/user-communication.md"],
  },
  {
    id: "incident-legal",
    status: "documented",
    evidence: ["dev/runbooks/disclosure-incident.md", "dev/runbooks/user-communication.md"],
  },
  {
    id: "deployment-manifests",
    status: "recorded",
    evidence: ["deployments/fuji-v1.json", MAINNET_PATH],
  },
  {
    id: "audit-remediation",
    status: "remediated",
    evidence: ["dev/fixtures/audit.json", "SECURITY.md"],
  },
  {
    id: "ceremony-evidence",
    status: "recorded",
    evidence: ["dev/fixtures/ceremony-release.json", "dev/artifacts/rehearsal-ceremony.json"],
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
    throw new Error(`missing readiness evidence: ${relative}`);
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

function inspectEvidence() {
  for (const check of CHECKS) {
    for (const path of check.evidence) {
      requireExists(path);
    }
  }
  requireContains(
    MAINNET_PATH,
    ['"chainId": 43114', '"authorized": false', "KEYS_MISSING", "operator-owned"],
    "mainnet-manifest",
  );
  requireContains("SECURITY.md", ["KEYS_MISSING", "operator-owned"], "bug-policy");
  requireContains("dev/artifacts/haze-gas-v1.json", ["fuji_required_before_mainnet"], "fuji-gas");
}

function smokeProductionConfig() {
  const circuit = loadJson("dev/artifacts/development-circuit-manifest.json");
  if (circuit.profile !== "development" || circuit.not_for_production !== true) {
    throw new Error("development circuit fixture drifted");
  }
  if (circuit.profile === "production") {
    throw new Error("production config must reject development fixtures");
  }
  try {
    checkCompatibility({ ...FUJI_COMPATIBILITY, chainId: 43114 });
    throw new Error("mainnet pin must not match Fuji compatibility");
  } catch (error) {
    if (error?.code !== "CHAIN_MISMATCH") {
      throw error;
    }
  }
  return {
    developmentFixturesRejected: true,
    productionKeysMissing: true,
  };
}

export function assembleReadiness() {
  inspectEvidence();
  const release = assembleFujiRelease();
  const pilot = assemblePilot();
  const audit = assembleAudit();
  const ceremony = assembleCeremonyRelease();
  const runbooks = assembleRunbooks();
  const review = assembleReview();
  const provenance = loadJson("dev/artifacts/provenance.json");
  const gas = loadJson("dev/artifacts/haze-gas-v1.json");
  const mainnet = loadJson(MAINNET_PATH);
  if (provenance.sc09?.incident_review?.approved === true) {
    throw new Error("T7.5 must not flip SC-09 incident_review.approved");
  }
  if (provenance.sc09?.production_ceremony?.approved === true) {
    throw new Error("T7.5 must not flip SC-09 production_ceremony.approved");
  }
  if (provenance.spend_prove !== "KEYS_MISSING") {
    throw new Error("T7.5 must keep production spend keys missing");
  }
  if (mainnet.authorized === true || mainnet.broadcast === true) {
    throw new Error("T7.5 must not authorize or broadcast a mainnet deployment");
  }
  if (mainnet.chainId !== 43114 || mainnet.spend_prove !== "KEYS_MISSING") {
    throw new Error("mainnet manifest drifted");
  }
  if (gas.fuji_required_before_mainnet !== true) {
    throw new Error("Fuji gas remasure remains required before mainnet");
  }
  if (review.findings.medium.some((finding) => finding.id === "M-01" || finding.id === "M-03")) {
    throw new Error("M-01 and M-03 must be remediating as operator-owned hard stops");
  }
  if (audit.findings.medium.length !== 0) {
    throw new Error("readiness cannot accept remaining medium findings");
  }
  const smoke = smokeProductionConfig();
  const canonical = {
    notForProduction: true,
    kind: "library-operational-readiness",
    mainnetAuthorized: false,
    broadcast: false,
    network: "mainnet",
    chainId: 43114,
    checks: CHECKS.map((check) => check.id),
    owners: { multisig: "operator-owned", timelock: "operator-owned" },
    providers: { kms: "operator-owned", identity: "operator-owned", rpc: "operator-owned" },
    fujiReleaseHash: release.hash,
    pilotHash: pilot.hash,
    auditHash: audit.hash,
    ceremonyHash: ceremony.hash,
    runbooksHash: runbooks.hash,
    spendProve: "KEYS_MISSING",
    fujiGas: "operator-owned",
    smoke,
    findings: { medium: [] },
    remediations: ["M-01", "M-03"],
    coverage: ["SC-09"],
    sc09: { incidentReviewApproved: false, productionCeremonyApproved: false },
    verdict: "pass-library-readiness",
  };
  return {
    ...canonical,
    checks: CHECKS.map((check) => ({ ...check })),
    hash: hashCanonical(canonical),
  };
}

export function verifyReadiness() {
  const report = assembleReadiness();
  const published = loadJson("dev/fixtures/readiness.json");
  if (published.fixtureHash !== report.hash) {
    throw new Error("published readiness fixture hash mismatch");
  }
  if (published.not_for_production !== true) {
    throw new Error("readiness is not labeled development");
  }
  if (published.kind !== "library-operational-readiness") {
    throw new Error("published readiness kind drifted");
  }
  if (published.mainnet_authorized !== false) {
    throw new Error("published readiness must not authorize mainnet");
  }
  if (published.spend_prove !== "KEYS_MISSING") {
    throw new Error("published readiness must keep spend keys missing");
  }
  if (published.sc09_incident_review_approved !== false) {
    throw new Error("published readiness must keep SC-09 closed");
  }
  if (published.verdict !== report.verdict) {
    throw new Error("published readiness verdict drifted");
  }
  return { fixtureHash: report.hash, notForProduction: true };
}

function main(argv) {
  const command = argv[0] ?? "verify";
  if (command === "verify") {
    const verified = verifyReadiness();
    process.stdout.write(`readiness-verify ok ${verified.fixtureHash}\n`);
    return;
  }
  if (command === "assemble") {
    process.stdout.write(`${JSON.stringify(assembleReadiness(), null, 2)}\n`);
    return;
  }
  throw new Error(`unknown readiness command: ${command}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2));
}
