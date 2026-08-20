import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { assembleAudit } from "../dev/audit.mjs";
import { assembleCeremonyRelease } from "../dev/ceremony-release.mjs";
import { assembleFujiRelease } from "../dev/fuji-release.mjs";
import { assemblePilot } from "../dev/pilot.mjs";
import { assembleReadiness, verifyReadiness } from "../dev/readiness.mjs";
import { assembleRunbooks } from "../dev/runbooks.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const CHECKS = [
  "governance-owners",
  "kms",
  "identity",
  "rpc",
  "backups",
  "monitoring",
  "on-call",
  "incident-legal",
  "deployment-manifests",
  "audit-remediation",
  "ceremony-evidence",
];

test("operational readiness records operator-owned owners and providers against T7.2-T7.4 pins", () => {
  const readiness = assembleReadiness();
  const release = assembleFujiRelease();
  const pilot = assemblePilot();
  const audit = assembleAudit();
  const ceremony = assembleCeremonyRelease();
  const runbooks = assembleRunbooks();
  assert.equal(readiness.notForProduction, true);
  assert.equal(readiness.kind, "library-operational-readiness");
  assert.equal(readiness.mainnetAuthorized, false);
  assert.equal(readiness.broadcast, false);
  assert.equal(readiness.network, "mainnet");
  assert.equal(readiness.chainId, 43114);
  assert.deepEqual(
    readiness.checks.map((check) => check.id),
    CHECKS,
  );
  for (const check of readiness.checks) {
    assert.ok(check.status.length > 0, `${check.id} missing status`);
    assert.ok(check.evidence.length > 0, `${check.id} missing evidence`);
    for (const path of check.evidence) {
      assert.equal(existsSync(join(HAZE_ROOT, path)), true, path);
    }
  }
  assert.equal(readiness.owners.multisig, "operator-owned");
  assert.equal(readiness.owners.timelock, "operator-owned");
  assert.equal(readiness.providers.kms, "operator-owned");
  assert.equal(readiness.providers.identity, "operator-owned");
  assert.equal(readiness.providers.rpc, "operator-owned");
  assert.equal(readiness.fujiReleaseHash, release.hash);
  assert.equal(readiness.pilotHash, pilot.hash);
  assert.equal(readiness.auditHash, audit.hash);
  assert.equal(readiness.ceremonyHash, ceremony.hash);
  assert.equal(readiness.runbooksHash, runbooks.hash);
  assert.equal(readiness.spendProve, "KEYS_MISSING");
  assert.equal(readiness.fujiGas, "operator-owned");
  assert.doesNotMatch(JSON.stringify(readiness), /alchemy|infura|quicknode|auth0|okta|aws-sdk|vercel/i);
});

test("operational readiness remediates M-01 and M-03 as operator-owned hard stops and keeps SC-09 closed", () => {
  const readiness = assembleReadiness();
  assert.equal(readiness.remediations.includes("M-01"), true);
  assert.equal(readiness.remediations.includes("M-03"), true);
  assert.deepEqual(
    readiness.findings.medium.map((finding) => finding.id),
    [],
  );
  assert.equal(readiness.smoke.developmentFixturesRejected, true);
  assert.equal(readiness.smoke.productionKeysMissing, true);
  assert.deepEqual(readiness.coverage, ["SC-09"]);
  assert.equal(readiness.sc09.incidentReviewApproved, false);
  assert.equal(readiness.sc09.productionCeremonyApproved, false);
  assert.equal(readiness.verdict, "pass-library-readiness");
  assert.equal(readiness.mainnetAuthorized, false);
});

test("published readiness fixture hashes match verifyReadiness and keep SC-09 closed", () => {
  const verified = verifyReadiness();
  const assembled = assembleReadiness();
  assert.match(verified.fixtureHash, /^0x[0-9a-f]{64}$/);
  assert.equal(verified.fixtureHash, assembled.hash);
  const published = JSON.parse(readFileSync(join(HAZE_ROOT, "dev/fixtures/readiness.json"), "utf8"));
  assert.equal(published.fixtureHash, verified.fixtureHash);
  assert.equal(published.not_for_production, true);
  assert.equal(published.kind, "library-operational-readiness");
  assert.equal(published.mainnet_authorized, false);
  assert.equal(published.spend_prove, "KEYS_MISSING");
  assert.equal(published.sc09_incident_review_approved, false);
  assert.equal(published.verdict, assembled.verdict);
  const provenance = JSON.parse(readFileSync(join(HAZE_ROOT, "dev/artifacts/provenance.json"), "utf8"));
  assert.equal(provenance.sc09.independent_audit.approved, false);
  assert.equal(provenance.sc09.fuji_pilot.approved, false);
  assert.equal(provenance.sc09.production_ceremony.approved, false);
  assert.equal(provenance.sc09.incident_review.approved, false);
  assert.equal(provenance.spend_prove, "KEYS_MISSING");
  const mainnet = JSON.parse(readFileSync(join(HAZE_ROOT, "deployments/mainnet-v1.json"), "utf8"));
  assert.equal(mainnet.chainId, 43114);
  assert.equal(mainnet.authorized, false);
  assert.equal(mainnet.broadcast, false);
  assert.equal(mainnet.not_for_production, true);
  assert.equal(mainnet.spend_prove, "KEYS_MISSING");
});

test("npm readiness script verifies the published checklist", () => {
  const pkg = JSON.parse(readFileSync(join(HAZE_ROOT, "package.json"), "utf8"));
  assert.equal(pkg.scripts.readiness, "node --experimental-strip-types dev/readiness.mjs");
  const output = execFileSync(process.execPath, ["--experimental-strip-types", "dev/readiness.mjs", "verify"], {
    cwd: HAZE_ROOT,
    encoding: "utf8",
  });
  assert.match(output, /readiness-verify ok/);
  assert.match(output, /0x[0-9a-f]{64}/);
});
