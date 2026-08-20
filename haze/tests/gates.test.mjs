import assert from "node:assert/strict";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { assembleGates, verifyGates } from "../dev/gates.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function ids(prefix, count) {
  return Array.from({ length: count }, (_, index) => `${prefix}-${String(index + 1).padStart(2, "0")}`);
}

test("gates report traces SC, FR, and E2E ids to existing evidence", () => {
  const report = assembleGates();
  assert.equal(report.notForProduction, true);
  for (const id of [...ids("SC", 10), ...ids("FR", 14), ...ids("E2E", 13)]) {
    const row = report.traceability.find((item) => item.id === id);
    assert.ok(row, `missing ${id}`);
    assert.ok(row.evidence.length > 0, `empty evidence for ${id}`);
    for (const path of row.evidence) {
      assert.equal(existsSync(join(HAZE_ROOT, path)), true, path);
    }
  }
});

test("SC-06 records development P95, gas budgets, and operator-owned spend keys", () => {
  const report = assembleGates();
  assert.ok(report.sc06.developmentEquality.p95Ms <= 15000);
  assert.equal(report.sc06.developmentEquality.targetMs, 15000);
  assert.equal(report.sc06.spendGroth16.status, "operator-owned");
  assert.equal(report.sc06.spendGroth16.reason, "KEYS_MISSING");
  assert.equal("until" in report.sc06.spendGroth16, false);
  assert.equal(report.sc06.gas.fujiRequiredBeforeMainnet, true);
  assert.ok(report.sc06.gas.actions.every((action) => action.measured <= action.budget));
  assert.equal(report.sc06.verdict, "pass-with-approved-deferral");
});

test("SC-07 records in-process API and event-query P95 under targets", () => {
  const report = assembleGates();
  assert.ok(report.sc07.apiP95Ms <= 500);
  assert.equal(report.sc07.apiTargetMs, 500);
  assert.ok(report.sc07.eventQueryP95Ms <= 10000);
  assert.equal(report.sc07.eventQueryTargetMs, 10000);
  assert.ok(report.sc07.samples >= 32);
  assert.equal(report.sc07.verdict, "pass");
});

test("SC-08 requires invariants, e2e suite, and no security-critical gap", () => {
  const report = assembleGates();
  assert.equal(report.sc08.invariants, true);
  assert.equal(report.sc08.e2eComplete, true);
  assert.equal(report.sc08.securityCriticalGap, false);
  assert.equal(report.sc08.verdict, "pass");
});

test("gates fixture hash ignores live proving duration", () => {
  const benchmarkPath = join(HAZE_ROOT, "dev/artifacts/proving-benchmark.json");
  const original = readFileSync(benchmarkPath, "utf8");
  const before = assembleGates().hash;
  const mutated = JSON.parse(original);
  mutated.duration_ms = (mutated.duration_ms ?? 0) + 1;
  writeFileSync(benchmarkPath, `${JSON.stringify(mutated, null, 2)}\n`);
  try {
    assert.equal(assembleGates().hash, before);
  } finally {
    writeFileSync(benchmarkPath, original);
  }
});

test("published gates fixture hashes match verifyGates", () => {
  const verified = verifyGates();
  const assembled = assembleGates();
  assert.match(verified.fixtureHash, /^0x[0-9a-f]{64}$/);
  assert.equal(verified.fixtureHash, assembled.hash);
  const published = JSON.parse(readFileSync(join(HAZE_ROOT, "dev/fixtures/gates-report.json"), "utf8"));
  assert.equal(published.fixtureHash, verified.fixtureHash);
  assert.equal(published.not_for_production, true);
  assert.equal(published.sc06, assembled.sc06.verdict);
  assert.equal(published.sc07, assembled.sc07.verdict);
  assert.equal(published.sc08, assembled.sc08.verdict);
});

test("npm gates script verifies the published report", () => {
  const pkg = JSON.parse(readFileSync(join(HAZE_ROOT, "package.json"), "utf8"));
  assert.equal(pkg.scripts.gates, "node --experimental-strip-types dev/gates.mjs");
  const output = execFileSync(process.execPath, ["--experimental-strip-types", "dev/gates.mjs", "verify"], {
    cwd: HAZE_ROOT,
    encoding: "utf8",
  });
  assert.match(output, /gates-verify ok/);
  assert.match(output, /0x[0-9a-f]{64}/);
});
