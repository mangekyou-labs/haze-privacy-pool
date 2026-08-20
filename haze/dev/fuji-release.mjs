#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { FUJI_COMPATIBILITY, checkCompatibility } from "../sdk/typescript/src/versions.ts";
import { SCENARIO_IDS } from "./e2e.mjs";
import { assembleRunbooks } from "./runbooks.mjs";
import { assembleStack } from "./stack.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const USDC_FUJI = "0x5425890298aed601595a70AB815c96711a31Bc65";
const PROVENANCE_PATH = "deployments/fuji-v1.json";

const CONTRACTS = [
  "HazePool",
  "HazeSpendVerifier",
  "SwapAndShieldRouter",
  "EmergencyExit",
  "HazeAccess",
  "ApplicationRegistry",
  "PolicyRegistry",
  "VersionRegistry",
];

const SERVICES = [
  "haze-gatekeeper",
  "haze-indexer",
  "haze-prover",
  "haze-disclosure",
  "haze-audit-auth",
];

const FRONTENDS = ["privacy-pool-dex", "compliance-portal"];
const COVERAGE = ["SC-01", "SC-06", "SC-07"];

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

function loadJson(relative) {
  return JSON.parse(readHaze(relative));
}

function requireExists(relative) {
  if (!existsSync(hazePath(relative))) {
    throw new Error(`missing ${relative}`);
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

function inspectImmutable() {
  for (const relative of NO_OWNER_PROXY) {
    const text = readHaze(relative);
    if (!/no owner, proxy/i.test(text)) {
      throw new Error(`${relative} missing no-owner/proxy guarantee`);
    }
    if (/\bis\s+[^{]*Ownable\b/.test(text) || /import\s+\{[^}]*\bOwnable\b/.test(text)) {
      throw new Error(`${relative} inherits or imports Ownable`);
    }
  }
  requireContains("contracts/src/VersionRegistry.sol", ["does not upgrade deployed code"], "version-registry");
  return true;
}

function inspectPins() {
  requireContains("sdk/typescript/src/versions.ts", ["chainId: 43113"], "fuji-pin");
  requireContains("dev/e2e.mjs", ["0x5425890298aed601595a70ab815c96711a31bc65"], "fuji-usdc");
  requireExists(PROVENANCE_PATH);
  requireExists("dev/artifacts/development-circuit-manifest.json");
  requireExists("dev/artifacts/provenance.json");
  requireExists("dev/artifacts/rehearsal-signed-manifest.json");
  requireExists("dev/artifacts/haze-gas-v1.json");
  requireExists("dev/runbooks/dashboards-alerts.md");
}

export function assembleFujiRelease() {
  inspectPins();
  inspectImmutable();
  checkCompatibility({ ...FUJI_COMPATIBILITY });
  const stack = assembleStack("ci");
  const circuit = loadJson("dev/artifacts/development-circuit-manifest.json");
  const provenanceDoc = loadJson("dev/artifacts/provenance.json");
  const signed = loadJson("dev/artifacts/rehearsal-signed-manifest.json");
  const gas = loadJson("dev/artifacts/haze-gas-v1.json");
  const publishedProvenance = loadJson(PROVENANCE_PATH);
  const runbooks = assembleRunbooks();
  if (circuit.profile !== "development" || circuit.not_for_production !== true) {
    throw new Error("Fuji release selected a non-development circuit");
  }
  if (provenanceDoc.spend_prove !== "KEYS_MISSING") {
    throw new Error("Fuji release must keep production spend keys missing");
  }
  if (gas.fuji_required_before_mainnet !== true) {
    throw new Error("Fuji gas report must remain required before mainnet");
  }
  if (runbooks.rehearsal.fuji !== "pass-fuji-configured") {
    throw new Error("Fuji runbook rehearsal is not configured");
  }
  if (publishedProvenance.chainId !== 43113 || publishedProvenance.broadcast !== false) {
    throw new Error("public Fuji provenance drifted");
  }
  if (publishedProvenance.not_for_production !== true) {
    throw new Error("public Fuji provenance is not labeled development");
  }
  const compatibility = { ...FUJI_COMPATIBILITY };
  const ceremony = {
    profile: circuit.profile,
    notForProduction: true,
    spendProve: provenanceDoc.spend_prove,
  };
  const policyRoots = {
    protocolVersionTag: FUJI_COMPATIBILITY.protocolVersionTag,
    circuitArtifactHash: FUJI_COMPATIBILITY.circuitArtifactHash,
    developmentArtifactHash: circuit.artifact_hash,
    rehearsalDigest: signed.digest,
  };
  const actions = Object.keys(gas.actions);
  const verdict = "pass-fuji-configured";
  const canonical = {
    notForProduction: true,
    network: "fuji",
    chainId: 43113,
    usdc: USDC_FUJI,
    broadcast: false,
    liveRpc: "operator-owned",
    compatibility,
    ceremony,
    immutable: true,
    contracts: CONTRACTS,
    services: SERVICES,
    frontends: FRONTENDS,
    policyRoots,
    provenancePath: PROVENANCE_PATH,
    smoke: { stackHash: stack.hash, compatibility: "pass" },
    e2e: { scenarios: SCENARIO_IDS, count: SCENARIO_IDS.length },
    gas: {
      fujiRequiredBeforeMainnet: true,
      network: gas.network,
      actions,
    },
    observability: "dashboards-alerts",
    rehearsal: { fuji: "pass-fuji-configured" },
    coverage: COVERAGE,
    verdict,
  };
  return {
    ...canonical,
    hash: hashCanonical(canonical),
  };
}

export function verifyFujiRelease() {
  const report = assembleFujiRelease();
  const published = loadJson("dev/fixtures/fuji-release.json");
  if (published.fixtureHash !== report.hash) {
    throw new Error("published Fuji release fixture hash mismatch");
  }
  if (published.not_for_production !== true) {
    throw new Error("Fuji release is not labeled development");
  }
  if (published.network !== "fuji" || published.chainId !== 43113) {
    throw new Error("published Fuji release network pin drifted");
  }
  if (published.broadcast !== false) {
    throw new Error("published Fuji release must not broadcast");
  }
  if (published.verdict !== report.verdict) {
    throw new Error("published Fuji release verdict drifted");
  }
  return { fixtureHash: report.hash, notForProduction: true };
}

function main(argv) {
  const command = argv[0] ?? "verify";
  if (command === "verify") {
    const verified = verifyFujiRelease();
    process.stdout.write(`fuji-release-verify ok ${verified.fixtureHash}\n`);
    return;
  }
  if (command === "assemble") {
    process.stdout.write(`${JSON.stringify(assembleFujiRelease(), null, 2)}\n`);
    return;
  }
  throw new Error(`unknown fuji-release command: ${command}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2));
}
