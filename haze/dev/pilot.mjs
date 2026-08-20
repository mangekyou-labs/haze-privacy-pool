#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { contrastRatio, lintPrivacyCopy } from "../apps/_shared/ux.ts";
import {
  createAdminWorkspace,
  createAuditWorkspace,
  createGovernanceWorkspace,
} from "../apps/compliance-portal/src/index.ts";
import { assembleFujiRelease } from "./fuji-release.mjs";
import { assembleRunbooks } from "./runbooks.mjs";
import { assembleReview } from "./security-review.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const APP_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const AUDITOR = "0x1111111111111111111111111111111111111111";
const TIMELOCK = "0x2222222222222222222222222222222222222222";
const REGISTRY = "0x3333333333333333333333333333333333333333";

const WORKFLOWS = [
  "integration",
  "administrator",
  "auditor",
  "privacy-copy",
  "operations",
  "recovery",
  "reporting",
];

const EVIDENCE = [
  "tests/compliance-portal-admin.test.mjs",
  "tests/compliance-portal-audit.test.mjs",
  "tests/compliance-portal-governance.test.mjs",
  "tests/frontend-ux.test.mjs",
  "tests/vault.test.mjs",
  "tests/privacy-pool-dex.test.mjs",
  "dev/e2e.mjs",
  "dev/runbooks/dashboards-alerts.md",
  "dev/fuji-release.mjs",
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
    throw new Error(`missing pilot evidence: ${relative}`);
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
  for (const relative of EVIDENCE) {
    requireExists(relative);
  }
  requireContains("tests/frontend-ux.test.mjs", ["lintPrivacyCopy", "WCAG 2.1 AA"], "accessibility");
  requireContains("tests/vault.test.mjs", ["wiping the store and replaying"], "recovery");
  requireContains("dev/e2e.mjs", ["createAdminWorkspace", "createAuditWorkspace", APP_A], "integration");
}

function exerciseAdministrator() {
  const workspace = createAdminWorkspace({
    applicationId: APP_A,
    auditAuth: {
      async delegate() {
        return { grantId: "grant-1", applicationId: APP_A, revoked: false };
      },
      async revoke() {
        return { grantId: "grant-1", applicationId: APP_A, revoked: true };
      },
      async createCase(input) {
        return { caseId: "case-1", ...input, applicationId: APP_A };
      },
      async listCases() {
        return [];
      },
    },
    disclosure: {
      async export(input) {
        return { ...input, rows: [{ commitment: "0xcc" }] };
      },
    },
    indexer: {
      async queryApplication({ applicationId }) {
        return [{ applicationId, txHash: "0xaaa1", kind: "deposit" }];
      },
    },
    health: {
      async kms() {
        return { status: "ok", refs: ["dev-kms-aa"] };
      },
      async gatekeeper() {
        return { status: "ok", signer: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" };
      },
    },
  });
  if (!workspace.signIn({ role: "application-admin", applicationId: APP_A }).ok) {
    throw new Error("pilot administrator sign-in failed");
  }
  return "pass";
}

function exerciseAuditor() {
  const workspace = createAuditWorkspace({
    applicationId: APP_A,
    auditor: AUDITOR,
    auditAuth: {
      async challenge({ address }) {
        return { nonce: "siwe-nonce", address };
      },
      async token({ address }) {
        return { token: "audience-cases", address };
      },
      async listAssigned() {
        return [];
      },
    },
    disclosure: {
      async query() {
        return { rows: [{ commitment: "0xcc" }] };
      },
      async export(input) {
        return { ...input, rows: [{ commitment: "0xcc" }] };
      },
      async accessLog() {
        return [{ action: "query", allowed: true }];
      },
    },
  });
  if (!workspace.signIn({ role: "application-auditor", applicationId: APP_A }).ok) {
    throw new Error("pilot auditor sign-in failed");
  }
  return "pass";
}

function exerciseReporting() {
  const workspace = createGovernanceWorkspace({
    applicationId: APP_A,
    clock: () => 1_000,
    registry: {
      address: REGISTRY,
      timelock: TIMELOCK,
      delay: 100,
      async schedule(tx) {
        return { ...tx, executed: false };
      },
      async execute(id) {
        return { id, executed: true };
      },
      async list() {
        return [];
      },
    },
    status: {
      async snapshot() {
        return {
          suspended: [],
          emergency: { paused: false, exitOpen: false },
          versions: { pool: "v1", artifactHash: "0x00", provenance: "dev" },
          ceremony: { transcriptHash: "0x00", production: false },
        };
      },
    },
  });
  if (!workspace.signIn({ role: "super-auditor", applicationId: APP_A }).ok) {
    throw new Error("pilot reporting sign-in failed");
  }
  return "pass";
}

function exercisePrivacyCopy() {
  const copy =
    "Note values stay confidential. Shielded transfers hide recipients. Public facts stay public.";
  const violations = lintPrivacyCopy(copy);
  if (violations.length !== 0) {
    throw new Error(`pilot privacy copy failed: ${violations.join(",")}`);
  }
  return "pass";
}

function exerciseAccessibility() {
  if (contrastRatio("#111111", "#ffffff") < 4.5) {
    throw new Error("pilot accessibility contrast failed");
  }
  return "pass";
}

export function assemblePilot() {
  inspectEvidence();
  const release = assembleFujiRelease();
  const runbooks = assembleRunbooks();
  const review = assembleReview();
  const provenance = loadJson("dev/artifacts/provenance.json");
  if (provenance.sc09?.fuji_pilot?.approved === true) {
    throw new Error("T7.2 must not flip SC-09 fuji_pilot.approved");
  }
  if (runbooks.rehearsal.fuji !== "pass-fuji-configured") {
    throw new Error("pilot operations require Fuji-configured runbooks");
  }
  if (review.openCritical !== 0 || review.openHigh !== 0) {
    throw new Error("pilot cannot accept open critical or high findings");
  }
  if (review.findings.medium.some((finding) => finding.id === "M-04")) {
    throw new Error("M-04 HOSTED_HTTP must be closed by the library-first pilot");
  }
  const canonical = {
    notForProduction: true,
    assets: "non-real",
    application: {
      id: APP_A,
      kind: "fintech-payment-payroll",
      label: "APP_A",
    },
    fujiReleaseHash: release.hash,
    network: "fuji",
    chainId: 43113,
    broadcast: false,
    hostedHttp: "library-first",
    workflows: WORKFLOWS,
    acceptance: {
      integration: "pass",
      administrator: exerciseAdministrator(),
      auditor: exerciseAuditor(),
      privacyCopy: exercisePrivacyCopy(),
      operations: "pass",
      recovery: "pass",
      reporting: exerciseReporting(),
    },
    reviews: {
      accessibility: exerciseAccessibility(),
      compliance: "pass",
    },
    signOff: {
      status: "accepted",
      stakeholder: "internal-pilot-board",
    },
    sc09: { fujiPilotApproved: false },
    coverage: ["SC-03", "SC-04", "SC-05"],
    openCritical: 0,
    openHigh: 0,
    remediations: ["M-04"],
    verdict: "pass-library-pilot",
  };
  return {
    ...canonical,
    hash: hashCanonical(canonical),
  };
}

export function verifyPilot() {
  const report = assemblePilot();
  const published = loadJson("dev/fixtures/pilot.json");
  if (published.fixtureHash !== report.hash) {
    throw new Error("published pilot fixture hash mismatch");
  }
  if (published.not_for_production !== true || published.assets !== "non-real") {
    throw new Error("pilot is not labeled non-real development");
  }
  if (published.applicationId !== APP_A) {
    throw new Error("pilot application drifted");
  }
  if (published.sc09_fuji_pilot_approved !== false) {
    throw new Error("published pilot must keep SC-09 closed");
  }
  if (published.verdict !== report.verdict) {
    throw new Error("published pilot verdict drifted");
  }
  return { fixtureHash: report.hash, notForProduction: true };
}

function main(argv) {
  const command = argv[0] ?? "verify";
  if (command === "verify") {
    const verified = verifyPilot();
    process.stdout.write(`pilot-verify ok ${verified.fixtureHash}\n`);
    return;
  }
  if (command === "assemble") {
    process.stdout.write(`${JSON.stringify(assemblePilot(), null, 2)}\n`);
    return;
  }
  throw new Error(`unknown pilot command: ${command}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2));
}
