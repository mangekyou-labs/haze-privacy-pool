import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { assembleRunbooks, verifyRunbooks } from "../dev/runbooks.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const PROCEDURES = [
  "deploy-rollback-by-version",
  "pause",
  "signer-kms-policy-rotation",
  "rpc-indexer-recovery",
  "database-restore",
  "app-suspension",
  "emergency-exit",
  "disclosure-incident",
  "user-communication",
  "dashboards-alerts",
];

test("runbooks cover the ten T6.5 procedures with owners and escalation", () => {
  const report = assembleRunbooks();
  assert.equal(report.notForProduction, true);
  assert.equal(report.procedures.length, 10);
  assert.deepEqual(
    report.procedures.map((procedure) => procedure.id),
    PROCEDURES,
  );
  for (const procedure of report.procedures) {
    assert.equal(existsSync(join(HAZE_ROOT, procedure.path)), true, procedure.path);
    assert.ok(procedure.owner.length > 0, `${procedure.id} missing owner`);
    assert.ok(procedure.escalation.length > 0, `${procedure.id} missing escalation`);
    assert.equal(procedure.localTabletop, "pass");
    assert.equal(procedure.fujiRehearsal, "pass-fuji-configured");
  }
  assert.match(report.verdict, /^pass/);
});

test("local tabletop rehearses T4.5 backup, rotation, pause, and emergency exit", () => {
  const report = assembleRunbooks();
  assert.equal(report.rehearsal.backupRestoreDocumented, true);
  assert.equal(report.rehearsal.rotationIdDocumented, true);
  assert.equal(report.rehearsal.pauseDocumented, true);
  assert.equal(report.rehearsal.emergencyExitDocumented, true);
  assert.equal(report.rehearsal.redactEvidenceDocumented, true);
  assert.equal(report.rehearsal.fuji, "pass-fuji-configured");
});

test("published runbooks fixture hashes match verifyRunbooks", () => {
  const verified = verifyRunbooks();
  const assembled = assembleRunbooks();
  assert.match(verified.fixtureHash, /^0x[0-9a-f]{64}$/);
  assert.equal(verified.fixtureHash, assembled.hash);
  const published = JSON.parse(readFileSync(join(HAZE_ROOT, "dev/fixtures/runbooks.json"), "utf8"));
  assert.equal(published.fixtureHash, verified.fixtureHash);
  assert.equal(published.not_for_production, true);
  assert.equal(published.verdict, assembled.verdict);
  assert.equal(published.procedures, 10);
  assert.equal(published.fuji_rehearsal, "pass-fuji-configured");
});

test("npm runbooks script verifies the published catalog", () => {
  const pkg = JSON.parse(readFileSync(join(HAZE_ROOT, "package.json"), "utf8"));
  assert.equal(pkg.scripts.runbooks, "node --experimental-strip-types dev/runbooks.mjs");
  const output = execFileSync(process.execPath, ["--experimental-strip-types", "dev/runbooks.mjs", "verify"], {
    cwd: HAZE_ROOT,
    encoding: "utf8",
  });
  assert.match(output, /runbooks-verify ok/);
  assert.match(output, /0x[0-9a-f]{64}/);
});
