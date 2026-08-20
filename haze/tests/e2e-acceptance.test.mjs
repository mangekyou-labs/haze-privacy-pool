import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { assembleStack } from "../dev/stack.mjs";
import { SCENARIO_IDS, redactEvidence, runE2eSuite } from "../dev/e2e.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

test("acceptance suite covers E2E-01 through E2E-13 on the T6.1 stack", async () => {
  const stack = assembleStack("ci");
  assert.equal(SCENARIO_IDS.length, 13);
  assert.deepEqual(SCENARIO_IDS, [
    "E2E-01",
    "E2E-02",
    "E2E-03",
    "E2E-04",
    "E2E-05",
    "E2E-06",
    "E2E-07",
    "E2E-08",
    "E2E-09",
    "E2E-10",
    "E2E-11",
    "E2E-12",
    "E2E-13",
  ]);
  const report = await runE2eSuite({ profile: "ci" });
  assert.equal(report.ok, true);
  assert.equal(report.results.length, 13);
  assert.equal(report.results.every((item) => item.ok), true);
  assert.equal(report.stackHash, stack.hash);
  assert.equal(report.notForProduction, true);
  assert.doesNotMatch(JSON.stringify(report), /alchemy|infura|auth0|okta|vercel/i);
});

test("a failed scenario yields diagnosable redacted evidence", async () => {
  const report = await runE2eSuite({ profile: "local", injectFailure: "E2E-11" });
  assert.equal(report.ok, false);
  const failed = report.results.find((item) => item.id === "E2E-11");
  assert.equal(failed.ok, false);
  assert.ok(failed.evidence);
  assert.match(failed.evidence.scenario, /E2E-11/);
  assert.ok(failed.evidence.code);
  const blob = JSON.stringify(failed.evidence);
  assert.match(blob, /\[redacted\]/);
  assert.doesNotMatch(blob, /x25519Secret|0x0000000000000000000000000000000000000000000000000000000000000001/);
  const redacted = redactEvidence({
    scenario: "E2E-01",
    signingKey: "0x0000000000000000000000000000000000000000000000000000000000000001",
    note: "secret material",
  });
  assert.equal(redacted.signingKey, "[redacted]");
});

test("the suite is repeatable without leftover runtime state", async () => {
  const first = await runE2eSuite({ profile: "ci" });
  const second = await runE2eSuite({ profile: "ci" });
  assert.equal(first.ok, true);
  assert.equal(second.ok, true);
  assert.deepEqual(
    first.results.map((item) => item.id),
    second.results.map((item) => item.id),
  );
});

test("npm e2e script runs the acceptance suite", () => {
  const pkg = JSON.parse(readFileSync(join(HAZE_ROOT, "package.json"), "utf8"));
  assert.equal(pkg.scripts.e2e, "node --experimental-strip-types dev/e2e.mjs");
  const output = execFileSync(process.execPath, ["--experimental-strip-types", "dev/e2e.mjs"], {
    cwd: HAZE_ROOT,
    encoding: "utf8",
  });
  assert.match(output, /e2e-suite ok/);
  assert.match(output, /E2E-13/);
});
