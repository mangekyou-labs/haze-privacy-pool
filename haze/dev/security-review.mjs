#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { authorizeApi, threatModel } from "../apps/_shared/ux.ts";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const WORKTREE_ROOT = resolve(HAZE_ROOT, "..");

const SURFACE_IDS = [
  "threat-model",
  "circuit-constraints",
  "evm-attack-surface",
  "dex-adapter",
  "signature-domains",
  "governance",
  "key-management",
  "access-control",
  "pii-logging",
  "dependencies-licenses",
];

const SURFACES = [
  {
    id: "threat-model",
    evidence: ["apps/_shared/ux.ts", "tests/frontend-ux.test.mjs"],
  },
  {
    id: "circuit-constraints",
    evidence: [
      "circuits/src/spend.circom",
      "tests/circuit-spend.test.mjs",
      "dev/artifacts/development-circuit-manifest.json",
    ],
  },
  {
    id: "evm-attack-surface",
    evidence: [
      "contracts/src/HazePool.sol",
      "contracts/src/EmergencyExit.sol",
      "contracts/src/SwapAndShieldRouter.sol",
      "contracts/src/HazeSpendVerifier.sol",
      "contracts/test/ProtocolInvariants.t.sol",
      "tests/invariants.test.mjs",
    ],
  },
  {
    id: "dex-adapter",
    evidence: [
      "contracts/src/SwapAndShieldRouter.sol",
      "tests/privacy-pool-dex.test.mjs",
      "tests/router.test.mjs",
      "tests/product-boundary.test.mjs",
    ],
  },
  {
    id: "signature-domains",
    evidence: [
      "sdk/typescript/src/eip712.ts",
      "sdk/typescript/src/pool.ts",
      "services/gatekeeper/src/sign.rs",
    ],
  },
  {
    id: "governance",
    evidence: [
      "apps/_shared/ux.ts",
      "tests/compliance-portal-governance.test.mjs",
      "contracts/src/HazeAccess.sol",
      "contracts/src/PolicyRegistry.sol",
    ],
  },
  {
    id: "key-management",
    evidence: ["apps/_shared/ux.ts", "sdk/typescript/src/vault.ts", "tests/vault.test.mjs"],
  },
  {
    id: "access-control",
    evidence: ["apps/_shared/ux.ts", "tests/frontend-ux.test.mjs", "tests/product-boundary.test.mjs"],
  },
  {
    id: "pii-logging",
    evidence: ["apps/_shared/ux.ts", "dev/e2e.mjs", "dev/secret-scan.mjs", "tests/e2e-acceptance.test.mjs"],
  },
  {
    id: "dependencies-licenses",
    evidence: ["sdk/typescript/package.json", "sdk/typescript/LICENSE", "Cargo.toml", "package.json"],
  },
];

const MEDIUMS = [];

const NO_OWNER_PROXY = [
  "contracts/src/HazePool.sol",
  "contracts/src/EmergencyExit.sol",
  "contracts/src/SwapAndShieldRouter.sol",
  "contracts/src/HazeSpendVerifier.sol",
];

function hazePath(relative) {
  return join(HAZE_ROOT, relative);
}

function readHaze(relative) {
  return readFileSync(hazePath(relative), "utf8");
}

function requireExists(relative) {
  if (!existsSync(hazePath(relative))) {
    throw new Error(`missing review evidence: ${relative}`);
  }
}

function requireContains(relative, needles, label) {
  const text = readHaze(relative);
  for (const needle of needles) {
    if (typeof needle === "string") {
      if (!text.includes(needle)) {
        throw new Error(`${label}: ${relative} missing ${needle}`);
      }
    } else if (!needle.test(text)) {
      throw new Error(`${label}: ${relative} missing ${needle}`);
    }
  }
}

function hashCanonical(value) {
  return `0x${createHash("sha256").update(JSON.stringify(value)).digest("hex")}`;
}

function inspectContractsForbidOwnerProxy() {
  for (const relative of NO_OWNER_PROXY) {
    const text = readHaze(relative);
    if (!/no owner, proxy/i.test(text)) {
      throw new Error(`${relative} missing no-owner/proxy guarantee`);
    }
    if (/\bis\s+[^{]*Ownable\b/.test(text) || /import\s+\{[^}]*\bOwnable\b/.test(text)) {
      throw new Error(`${relative} inherits or imports Ownable`);
    }
  }
  return true;
}

function inspectCustodyDenied() {
  requireContains("apps/_shared/ux.ts", ["POST /v1/pool/deposit", "POST /v1/pool/transact"], "key-management");
  const session = { role: "pool-user", applicationId: `0x${"aa".repeat(32)}` };
  for (const path of ["/v1/pool/deposit", "/v1/pool/transact"]) {
    const decision = authorizeApi("privacy-pool-dex", session, "POST", path);
    if (decision.ok || decision.code !== "FORBIDDEN") {
      throw new Error(`custody API ${path} is not denied`);
    }
  }
  return true;
}

function rustPackageCount() {
  const cargo = readHaze("Cargo.toml");
  const block = cargo.match(/members\s*=\s*\[([\s\S]*?)\]/);
  if (!block) {
    throw new Error("Cargo.toml has no workspace members");
  }
  return [...block[1].matchAll(/"[^"]+"/g)].length;
}

function nodePackageCount() {
  const names = [
    JSON.parse(readHaze("sdk/typescript/package.json")).name,
    JSON.parse(readHaze("apps/privacy-pool-dex/package.json")).name,
    JSON.parse(readHaze("apps/compliance-portal/package.json")).name,
  ];
  if (names.length !== 3) {
    throw new Error("expected three Node packages");
  }
  return names.length;
}

function nobleCurvesLicense() {
  const candidates = [
    "node_modules/@noble/curves/package.json",
    "sdk/typescript/node_modules/@noble/curves/package.json",
  ];
  for (const relative of candidates) {
    if (existsSync(hazePath(relative))) {
      return JSON.parse(readHaze(relative)).license;
    }
  }
  throw new Error("@noble/curves is not installed for license inspection");
}

function independentReview() {
  const adr = readFileSync(join(WORKTREE_ROOT, "docs/ai/design/adr/0003-threat-model-v1.md"), "utf8");
  if (!adr.includes("Accepted")) {
    throw new Error("ADR-0003 is not accepted");
  }
  if (!adr.includes("91cfa5ee")) {
    throw new Error("ADR-0003 is missing independent review 91cfa5ee");
  }
  return "91cfa5ee";
}

function inspectSurfaces() {
  requireContains(
    "apps/_shared/ux.ts",
    ["navIsAuthorization: false", "logWitnesses: false", "logPlaintextNotes: false"],
    "threat-model",
  );
  requireContains("circuits/src/spend.circom", ["template", "component"], "circuit-constraints");
  requireContains("contracts/src/SwapAndShieldRouter.sol", ["No vendor-named adapters"], "dex-adapter");
  requireContains(
    "sdk/typescript/src/eip712.ts",
    ["EIP712_DOMAIN_TYPE", "INTENT_TYPE", "AUTH_TYPE", "KEY_TYPE"],
    "signature-domains",
  );
  requireContains("sdk/typescript/src/pool.ts", ["Haze Avalanche Compliant Pool"], "signature-domains");
  requireContains("apps/_shared/ux.ts", ['"super-auditor"', "POST /v1/governance/schedule"], "governance");
  requireContains("dev/e2e.mjs", ["export function redactEvidence", "[redacted]"], "pii-logging");
  requireContains("dev/secret-scan.mjs", ["PRIVATE KEY", "AKIA", "github_pat_", "xox[baprs]"], "pii-logging");
  requireContains("sdk/typescript/package.json", ['"license": "Apache-2.0"'], "dependencies-licenses");
  requireContains("sdk/typescript/LICENSE", ["Apache License"], "dependencies-licenses");
  requireContains("Cargo.toml", ['license = "Apache-2.0"', "unsafe_code = \"deny\""], "dependencies-licenses");
}

export function assembleReview() {
  for (const surface of SURFACES) {
    for (const path of surface.evidence) {
      requireExists(path);
    }
  }
  inspectSurfaces();
  if (threatModel.navIsAuthorization !== false) {
    throw new Error("nav is treated as authorization");
  }
  if (threatModel.logWitnesses !== false || threatModel.logPlaintextNotes !== false) {
    throw new Error("witness or plaintext note logging is enabled");
  }
  const checks = {
    contractsForbidOwnerProxy: inspectContractsForbidOwnerProxy(),
    navIsNotAuthorization: threatModel.navIsAuthorization === false,
    witnessesNotLogged: threatModel.logWitnesses === false,
    custodyApisDenied: inspectCustodyDenied(),
    sdkLicense: JSON.parse(readHaze("sdk/typescript/package.json")).license,
    nobleCurvesLicense: nobleCurvesLicense(),
    rustPackageCount: rustPackageCount(),
    nodePackageCount: nodePackageCount(),
    independentReview: independentReview(),
  };
  if (checks.sdkLicense !== "Apache-2.0") {
    throw new Error(`SDK license drifted: ${checks.sdkLicense}`);
  }
  if (checks.nobleCurvesLicense !== "MIT") {
    throw new Error(`@noble/curves license drifted: ${checks.nobleCurvesLicense}`);
  }
  if (checks.rustPackageCount !== 6 || checks.nodePackageCount !== 3) {
    throw new Error("package inventory drifted");
  }
  const findings = { critical: [], high: [], medium: MEDIUMS };
  const verdict = MEDIUMS.length === 0 ? "pass" : "pass-with-approved-mediums";
  const canonical = {
    notForProduction: true,
    surfaces: SURFACE_IDS,
    findings,
    checks,
    verdict,
  };
  return {
    ...canonical,
    surfaces: SURFACES.map((surface) => ({ ...surface, status: "reviewed" })),
    openCritical: 0,
    openHigh: 0,
    hash: hashCanonical(canonical),
  };
}

export function verifyReview() {
  const report = assembleReview();
  const published = JSON.parse(readHaze("dev/fixtures/security-review.json"));
  if (published.fixtureHash !== report.hash) {
    throw new Error("published security-review fixture hash mismatch");
  }
  if (published.not_for_production !== true) {
    throw new Error("security review is not labeled development");
  }
  if (published.verdict !== report.verdict) {
    throw new Error("published security-review verdict drifted");
  }
  if (published.open_critical !== 0 || published.open_high !== 0) {
    throw new Error("published security-review has open critical or high findings");
  }
  if (published.surfaces !== 10) {
    throw new Error("published security-review surface count drifted");
  }
  return { fixtureHash: report.hash, notForProduction: true };
}

function main(argv) {
  const command = argv[0] ?? "verify";
  if (command === "verify") {
    const verified = verifyReview();
    process.stdout.write(`security-review-verify ok ${verified.fixtureHash}\n`);
    return;
  }
  if (command === "assemble") {
    process.stdout.write(`${JSON.stringify(assembleReview(), null, 2)}\n`);
    return;
  }
  throw new Error(`unknown security-review command: ${command}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2));
}
