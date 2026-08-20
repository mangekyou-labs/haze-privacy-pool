import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { assembleAudit, verifyAudit } from "../dev/audit.mjs";
import { assemblePilot } from "../dev/pilot.mjs";
import { assembleFujiRelease } from "../dev/fuji-release.mjs";
import { assembleGates } from "../dev/gates.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const SURFACES = [
  "circuits",
  "ceremony-tooling",
  "contracts",
  "sdk-key-handling",
  "services",
  "frontends",
  "governance",
  "operational-controls",
];

test("independent audit reviews post-pilot surfaces with a frozen spend circuit", () => {
  const audit = assembleAudit();
  const release = assembleFujiRelease();
  const pilot = assemblePilot();
  const gates = assembleGates();
  assert.equal(audit.notForProduction, true);
  assert.equal(audit.kind, "independent-library-audit");
  assert.deepEqual(
    audit.surfaces.map((surface) => surface.id),
    SURFACES,
  );
  for (const surface of audit.surfaces) {
    assert.equal(surface.status, "reviewed");
    assert.ok(surface.evidence.length > 0, `${surface.id} missing evidence`);
    for (const path of surface.evidence) {
      assert.equal(existsSync(join(HAZE_ROOT, path)), true, path);
    }
  }
  assert.equal(audit.fujiReleaseHash, release.hash);
  assert.equal(audit.pilotHash, pilot.hash);
  assert.equal(audit.circuitFreeze.circuitId, "haze-spend-v1");
  assert.equal(audit.circuitFreeze.nConstraints, 588459);
  assert.equal(audit.circuitFreeze.circomVersion, "2.2.3");
  assert.match(audit.circuitFreeze.sourceHash, /^0x[0-9a-f]{64}$/);
  assert.match(audit.circuitFreeze.r1csHash, /^0x[0-9a-f]{64}$/);
  assert.match(audit.circuitFreeze.buildHash, /^0x[0-9a-f]{64}$/);
  assert.equal(audit.circuitFreeze.notForProduction, true);
  assert.equal(gates.sc08.verdict, "pass");
  assert.doesNotMatch(JSON.stringify(audit), /alchemy|infura|quicknode|auth0|okta|aws-sdk|vercel/i);
});

test("independent audit remediates critical/high findings and records bug policy", () => {
  const audit = assembleAudit();
  assert.equal(audit.openCritical, 0);
  assert.equal(audit.openHigh, 0);
  assert.equal(audit.findings.critical.length, 0);
  assert.equal(audit.findings.high.length, 0);
  assert.equal(audit.remediations.includes("M-05"), true);
  assert.equal(audit.remediations.includes("M-01"), true);
  assert.equal(audit.remediations.includes("M-03"), true);
  const remaining = audit.findings.medium.map((finding) => finding.id);
  assert.deepEqual(remaining, []);
  assert.equal(audit.bugPolicy.path, "SECURITY.md");
  assert.equal(audit.bugPolicy.criticalHigh, "fix-before-release");
  assert.equal(audit.bugPolicy.medium, "owner-and-disposition");
  assert.equal(existsSync(join(HAZE_ROOT, "SECURITY.md")), true);
  assert.deepEqual(audit.coverage, ["SC-08", "SC-09"]);
  assert.equal(audit.sc09.independentAuditApproved, false);
  assert.match(audit.verdict, /^pass/);
});

test("published audit fixture hashes match verifyAudit and keep SC-09 closed", () => {
  const verified = verifyAudit();
  const assembled = assembleAudit();
  assert.match(verified.fixtureHash, /^0x[0-9a-f]{64}$/);
  assert.equal(verified.fixtureHash, assembled.hash);
  const published = JSON.parse(readFileSync(join(HAZE_ROOT, "dev/fixtures/audit.json"), "utf8"));
  assert.equal(published.fixtureHash, verified.fixtureHash);
  assert.equal(published.not_for_production, true);
  assert.equal(published.kind, "independent-library-audit");
  assert.equal(published.sc09_independent_audit_approved, false);
  assert.equal(published.verdict, assembled.verdict);
  const provenance = JSON.parse(readFileSync(join(HAZE_ROOT, "dev/artifacts/provenance.json"), "utf8"));
  assert.equal(provenance.sc09.independent_audit.approved, false);
  assert.equal(provenance.sc09.fuji_pilot.approved, false);
  assert.equal(provenance.sc09.production_ceremony.approved, false);
  assert.equal(provenance.sc09.incident_review.approved, false);
  assert.equal(provenance.spend_prove, "KEYS_MISSING");
});

test("npm independent-audit script verifies the published report", () => {
  const pkg = JSON.parse(readFileSync(join(HAZE_ROOT, "package.json"), "utf8"));
  assert.equal(pkg.scripts["independent-audit"], "node --experimental-strip-types dev/audit.mjs");
  assert.notEqual(pkg.scripts.audit, pkg.scripts["independent-audit"]);
  const output = execFileSync(process.execPath, ["--experimental-strip-types", "dev/audit.mjs", "verify"], {
    cwd: HAZE_ROOT,
    encoding: "utf8",
  });
  assert.match(output, /independent-audit-verify ok/);
  assert.match(output, /0x[0-9a-f]{64}/);
});
