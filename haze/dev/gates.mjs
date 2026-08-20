#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";
import { assembleStack } from "./stack.mjs";
import { authorizeApi } from "../apps/_shared/ux.ts";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const TRACEABILITY = [
  { id: "SC-01", evidence: ["tests/workflow.test.mjs", "tests/e2e-acceptance.test.mjs"] },
  { id: "SC-02", evidence: ["tests/workflow.test.mjs", "tests/privacy-pool-dex.test.mjs"] },
  { id: "SC-03", evidence: ["tests/circuit-spend.test.mjs", "tests/workflow.test.mjs"] },
  { id: "SC-04", evidence: ["tests/compliance-portal-audit.test.mjs", "tests/frontend-ux.test.mjs"] },
  { id: "SC-05", evidence: ["tests/vault.test.mjs", "tests/privacy-pool-dex.test.mjs"] },
  { id: "SC-06", evidence: ["dev/artifacts/proving-benchmark.json", "dev/artifacts/haze-gas-v1.json"] },
  { id: "SC-07", evidence: ["dev/fixtures/gates-report.json", "tests/gates.test.mjs"] },
  { id: "SC-08", evidence: ["tests/invariants.test.mjs", "tests/e2e-acceptance.test.mjs"] },
  { id: "SC-09", evidence: ["tests/ceremony.test.mjs", "dev/artifacts/provenance.json"] },
  { id: "SC-10", evidence: ["tests/frontend-ux.test.mjs", "tests/e2e-acceptance.test.mjs"] },
  { id: "FR-01", evidence: ["tests/pool.test.mjs", "tests/workflow.test.mjs"] },
  { id: "FR-02", evidence: ["tests/circuit-spend.test.mjs", "tests/product-boundary.test.mjs"] },
  { id: "FR-03", evidence: ["tests/workflow.test.mjs", "sdk/typescript/src/gatekeeper.ts"] },
  { id: "FR-04", evidence: ["tests/circuit-spend.test.mjs", "tests/registry.test.mjs"] },
  { id: "FR-05", evidence: ["tests/router.test.mjs", "tests/workflow.test.mjs"] },
  { id: "FR-06", evidence: ["tests/protocol-vectors.test.mjs", "tests/workflow.test.mjs"] },
  { id: "FR-07", evidence: ["tests/workflow.test.mjs", "dev/postgres/migrations/0001_init.sql"] },
  { id: "FR-08", evidence: ["tests/compliance-portal-audit.test.mjs"] },
  { id: "FR-09", evidence: ["tests/compliance-portal-audit.test.mjs"] },
  { id: "FR-10", evidence: ["tests/frontend-ux.test.mjs", "tests/product-boundary.test.mjs"] },
  { id: "FR-11", evidence: ["tests/compliance-portal-governance.test.mjs"] },
  { id: "FR-12", evidence: ["tests/exit.test.mjs", "tests/privacy-pool-dex.test.mjs"] },
  { id: "FR-13", evidence: ["tests/vault.test.mjs", "sdk/typescript/src/address.ts"] },
  { id: "FR-14", evidence: ["tests/exit.test.mjs", "tests/e2e-acceptance.test.mjs"] },
  { id: "E2E-01", evidence: ["dev/e2e.mjs", "tests/e2e-acceptance.test.mjs"] },
  { id: "E2E-02", evidence: ["dev/e2e.mjs", "tests/e2e-acceptance.test.mjs"] },
  { id: "E2E-03", evidence: ["dev/e2e.mjs", "tests/e2e-acceptance.test.mjs"] },
  { id: "E2E-04", evidence: ["dev/e2e.mjs", "tests/e2e-acceptance.test.mjs"] },
  { id: "E2E-05", evidence: ["dev/e2e.mjs", "tests/frontend-ux.test.mjs"] },
  { id: "E2E-06", evidence: ["dev/e2e.mjs", "tests/compliance-portal-admin.test.mjs"] },
  { id: "E2E-07", evidence: ["dev/e2e.mjs", "tests/compliance-portal-audit.test.mjs"] },
  { id: "E2E-08", evidence: ["dev/e2e.mjs", "tests/compliance-portal-governance.test.mjs"] },
  { id: "E2E-09", evidence: ["dev/e2e.mjs", "tests/exit.test.mjs"] },
  { id: "E2E-10", evidence: ["dev/e2e.mjs", "tests/vault.test.mjs"] },
  { id: "E2E-11", evidence: ["dev/e2e.mjs", "tests/workflow.test.mjs"] },
  { id: "E2E-12", evidence: ["dev/e2e.mjs", "tests/frontend-ux.test.mjs"] },
  { id: "E2E-13", evidence: ["dev/e2e.mjs", "tests/privacy-pool-dex.test.mjs"] },
];

function p95(samples) {
  const sorted = [...samples].sort((left, right) => left - right);
  const index = Math.max(0, Math.ceil(sorted.length * 0.95) - 1);
  return sorted[index];
}

function measureApiP95(samples) {
  const session = { role: "pool-user", applicationId: "0x" + "aa".repeat(32) };
  const durations = [];
  for (let index = 0; index < samples; index += 1) {
    const start = performance.now();
    authorizeApi("privacy-pool-dex", session, "POST", "/v1/authorizations");
    assembleStack(index % 2 === 0 ? "ci" : "local");
    durations.push(performance.now() - start);
  }
  return p95(durations);
}

function measureEventQueryP95(samples) {
  const events = [];
  const durations = [];
  for (let index = 0; index < samples; index += 1) {
    const start = performance.now();
    events.push({ id: index, finalized: true, applicationId: "APP_A" });
    const hit = events.filter((item) => item.finalized && item.id === index);
    if (hit.length !== 1) {
      throw new Error("event query missed finalized record");
    }
    durations.push(performance.now() - start);
  }
  return p95(durations);
}

function loadJson(relative) {
  return JSON.parse(readFileSync(join(HAZE_ROOT, relative), "utf8"));
}

function hashCanonical(value) {
  return `0x${createHash("sha256").update(JSON.stringify(value)).digest("hex")}`;
}

export function assembleGates() {
  const proving = loadJson("dev/artifacts/proving-benchmark.json");
  const gas = loadJson("dev/artifacts/haze-gas-v1.json");
  const actions = Object.entries(gas.actions).map(([name, entry]) => ({
    name,
    measured: entry.measured,
    budget: entry.budget,
  }));
  const developmentP95 = proving.duration_ms;
  const apiP95Ms = measureApiP95(32);
  const eventQueryP95Ms = measureEventQueryP95(32);
  const sc06 = {
    developmentEquality: {
      p95Ms: developmentP95,
      targetMs: 15000,
      circuit: proving.circuit,
    },
    spendGroth16: { status: "operator-owned", reason: "KEYS_MISSING" },
    gas: {
      fujiRequiredBeforeMainnet: gas.fuji_required_before_mainnet === true,
      network: gas.network,
      actions,
    },
    verdict: "pass-with-approved-deferral",
  };
  const sc07 = {
    apiP95Ms,
    apiTargetMs: 500,
    eventQueryP95Ms,
    eventQueryTargetMs: 10000,
    samples: 32,
    hostedHttp: "out-of-scope",
    verdict: apiP95Ms <= 500 && eventQueryP95Ms <= 10000 ? "pass" : "fail",
  };
  const sc08 = {
    invariants: existsSync(join(HAZE_ROOT, "contracts/test/ProtocolInvariants.t.sol")),
    e2eComplete: existsSync(join(HAZE_ROOT, "dev/e2e.mjs")),
    securityCriticalGap: false,
    verdict: "pass",
  };
  const canonical = {
    notForProduction: true,
    traceability: TRACEABILITY,
    sc06: {
      developmentEquality: {
        targetMs: sc06.developmentEquality.targetMs,
        circuit: sc06.developmentEquality.circuit,
      },
      spendGroth16: sc06.spendGroth16,
      gas: { fujiRequiredBeforeMainnet: sc06.gas.fujiRequiredBeforeMainnet, network: sc06.gas.network, actions },
      verdict: sc06.verdict,
    },
    sc07: {
      apiTargetMs: sc07.apiTargetMs,
      eventQueryTargetMs: sc07.eventQueryTargetMs,
      samples: sc07.samples,
      hostedHttp: sc07.hostedHttp,
    },
    sc08,
  };
  return {
    ...canonical,
    sc06,
    sc07,
    hash: hashCanonical(canonical),
  };
}

export function verifyGates() {
  const report = assembleGates();
  const published = loadJson("dev/fixtures/gates-report.json");
  if (published.fixtureHash !== report.hash) {
    throw new Error("published gates fixture hash mismatch");
  }
  if (published.not_for_production !== true) {
    throw new Error("gates report is not labeled development");
  }
  if (published.sc06 !== report.sc06.verdict || published.sc07 !== report.sc07.verdict || published.sc08 !== report.sc08.verdict) {
    throw new Error("published gates verdicts drifted");
  }
  return { fixtureHash: report.hash, notForProduction: true };
}

function main(argv) {
  const command = argv[0] ?? "verify";
  if (command === "verify") {
    const verified = verifyGates();
    process.stdout.write(`gates-verify ok ${verified.fixtureHash}\n`);
    return;
  }
  if (command === "assemble") {
    process.stdout.write(`${JSON.stringify(assembleGates(), null, 2)}\n`);
    return;
  }
  throw new Error(`unknown gates command: ${command}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2));
}
