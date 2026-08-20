import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { assemblePilot, verifyPilot } from "../dev/pilot.mjs";
import { assembleFujiRelease } from "../dev/fuji-release.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const APP_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

const WORKFLOWS = [
  "integration",
  "administrator",
  "auditor",
  "privacy-copy",
  "operations",
  "recovery",
  "reporting",
];

test("Fuji pilot accepts one representative fintech application against T7.1 pins", () => {
  const pilot = assemblePilot();
  const release = assembleFujiRelease();
  assert.equal(pilot.notForProduction, true);
  assert.equal(pilot.assets, "non-real");
  assert.equal(pilot.application.id, APP_A);
  assert.equal(pilot.application.kind, "fintech-payment-payroll");
  assert.equal(pilot.application.label, "APP_A");
  assert.equal(pilot.fujiReleaseHash, release.hash);
  assert.equal(pilot.network, "fuji");
  assert.equal(pilot.chainId, 43113);
  assert.equal(pilot.broadcast, false);
  assert.equal(pilot.hostedHttp, "library-first");
  assert.doesNotMatch(JSON.stringify(pilot), /alchemy|infura|quicknode|auth0|okta|aws-sdk|vercel/i);
});

test("Fuji pilot exercises admin, auditor, privacy copy, ops, recovery, and reporting", () => {
  const pilot = assemblePilot();
  assert.deepEqual(pilot.workflows, WORKFLOWS);
  assert.equal(pilot.acceptance.integration, "pass");
  assert.equal(pilot.acceptance.administrator, "pass");
  assert.equal(pilot.acceptance.auditor, "pass");
  assert.equal(pilot.acceptance.privacyCopy, "pass");
  assert.equal(pilot.acceptance.operations, "pass");
  assert.equal(pilot.acceptance.recovery, "pass");
  assert.equal(pilot.acceptance.reporting, "pass");
  assert.equal(pilot.reviews.accessibility, "pass");
  assert.equal(pilot.reviews.compliance, "pass");
  assert.equal(pilot.signOff.status, "accepted");
  assert.equal(pilot.signOff.stakeholder, "internal-pilot-board");
  assert.equal(pilot.sc09.fujiPilotApproved, false);
  assert.deepEqual(pilot.coverage, ["SC-03", "SC-04", "SC-05"]);
  assert.equal(pilot.openCritical, 0);
  assert.equal(pilot.openHigh, 0);
  assert.equal(pilot.remediations.includes("M-04"), true);
  assert.match(pilot.verdict, /^pass/);
});

test("published pilot fixture hashes match verifyPilot and keep SC-09 closed", () => {
  const verified = verifyPilot();
  const assembled = assemblePilot();
  assert.match(verified.fixtureHash, /^0x[0-9a-f]{64}$/);
  assert.equal(verified.fixtureHash, assembled.hash);
  const published = JSON.parse(readFileSync(join(HAZE_ROOT, "dev/fixtures/pilot.json"), "utf8"));
  assert.equal(published.fixtureHash, verified.fixtureHash);
  assert.equal(published.not_for_production, true);
  assert.equal(published.assets, "non-real");
  assert.equal(published.applicationId, APP_A);
  assert.equal(published.sc09_fuji_pilot_approved, false);
  assert.equal(published.verdict, assembled.verdict);
  const provenance = JSON.parse(readFileSync(join(HAZE_ROOT, "dev/artifacts/provenance.json"), "utf8"));
  assert.equal(provenance.sc09.fuji_pilot.approved, false);
  assert.equal(existsSync(join(HAZE_ROOT, "dev/fixtures/pilot.json")), true);
});

test("npm pilot script verifies the published acceptance report", () => {
  const pkg = JSON.parse(readFileSync(join(HAZE_ROOT, "package.json"), "utf8"));
  assert.equal(pkg.scripts.pilot, "node --experimental-strip-types dev/pilot.mjs");
  const output = execFileSync(process.execPath, ["--experimental-strip-types", "dev/pilot.mjs", "verify"], {
    cwd: HAZE_ROOT,
    encoding: "utf8",
  });
  assert.match(output, /pilot-verify ok/);
  assert.match(output, /0x[0-9a-f]{64}/);
});
