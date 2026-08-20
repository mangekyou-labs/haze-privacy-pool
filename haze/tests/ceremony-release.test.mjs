import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { assembleAudit } from "../dev/audit.mjs";
import { assembleCeremonyRelease, verifyCeremonyRelease } from "../dev/ceremony-release.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const FREEZE = {
  circuitId: "haze-spend-v1",
  nConstraints: 588459,
  circomVersion: "2.2.3",
  sourceHash: "0xddab1e2d4aca797058f3e3aca49c99a1bd5a396f3c3bf8dd1bc3c47a8e1fd9b1",
  r1csHash: "0x98cc762ccc18a9a3b0aba3b6be3dba217c928629cf8f330a09779ffa5e23f02d",
  buildHash: "0x533f1d9d172c8395b4849bd7b90901b5314b7fc4735b878385e22b5a19d3cd41",
};

test("production ceremony package pins T7.3 freeze and verifies the public rehearsal transcript", () => {
  const ceremony = assembleCeremonyRelease();
  const audit = assembleAudit();
  assert.equal(ceremony.notForProduction, true);
  assert.equal(ceremony.kind, "library-production-ceremony");
  assert.equal(ceremony.contributionProcess, "documented-rehearsed");
  assert.equal(ceremony.liveMpc, false);
  assert.equal(ceremony.transcriptVerified, true);
  assert.equal(ceremony.transcript.circuitId, "haze-development-equality-v1");
  assert.equal(ceremony.transcript.contributions, 2);
  assert.equal(
    ceremony.transcript.finalTranscript,
    "0x16824b61154c52717ba74edc9335e92f053317835c39bdcaa5290a484e5ca039",
  );
  assert.equal(ceremony.auditHash, audit.hash);
  assert.equal(ceremony.circuitFreeze.circuitId, FREEZE.circuitId);
  assert.equal(ceremony.circuitFreeze.nConstraints, FREEZE.nConstraints);
  assert.equal(ceremony.circuitFreeze.circomVersion, FREEZE.circomVersion);
  assert.equal(ceremony.circuitFreeze.sourceHash, FREEZE.sourceHash);
  assert.equal(ceremony.circuitFreeze.r1csHash, FREEZE.r1csHash);
  assert.equal(ceremony.circuitFreeze.buildHash, FREEZE.buildHash);
  assert.equal(ceremony.circuitFreeze.notForProduction, true);
  assert.equal(ceremony.verifier.file, "dev/artifacts/DevelopmentEqualityVerifier.sol");
  assert.equal(ceremony.verifier.notForProduction, true);
  assert.equal(existsSync(join(HAZE_ROOT, ceremony.verifier.file)), true);
  assert.equal(ceremony.signedManifest.file, "dev/artifacts/rehearsal-signed-manifest.json");
  assert.equal(ceremony.signedManifest.notForProduction, true);
  assert.equal(ceremony.signedManifest.signer, "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf");
  assert.equal(ceremony.spendProve, "KEYS_MISSING");
  assert.doesNotMatch(JSON.stringify(ceremony), /alchemy|infura|quicknode|auth0|okta|aws-sdk|vercel/i);
});

test("production ceremony remediates M-01 by retargeting KEYS_MISSING to T7.5 and keeps SC-09 closed", () => {
  const ceremony = assembleCeremonyRelease();
  assert.equal(ceremony.remediations.includes("M-01"), true);
  const remaining = ceremony.findings.medium.map((finding) => finding.id);
  assert.deepEqual(remaining, ["M-01", "M-03"]);
  const keys = ceremony.findings.medium.find((finding) => finding.id === "M-01");
  assert.equal(keys.until, "T7.5");
  assert.equal(keys.reason, "KEYS_MISSING");
  const gas = ceremony.findings.medium.find((finding) => finding.id === "M-03");
  assert.equal(gas.until, "T7.5");
  assert.equal(gas.reason, "FUJI_GAS");
  assert.deepEqual(ceremony.coverage, ["SC-09"]);
  assert.equal(ceremony.sc09.productionCeremonyApproved, false);
  assert.equal(ceremony.verdict, "pass-library-ceremony");
});

test("published ceremony-release fixture hashes match verifyCeremonyRelease and keep SC-09 closed", () => {
  const verified = verifyCeremonyRelease();
  const assembled = assembleCeremonyRelease();
  assert.match(verified.fixtureHash, /^0x[0-9a-f]{64}$/);
  assert.equal(verified.fixtureHash, assembled.hash);
  const published = JSON.parse(readFileSync(join(HAZE_ROOT, "dev/fixtures/ceremony-release.json"), "utf8"));
  assert.equal(published.fixtureHash, verified.fixtureHash);
  assert.equal(published.not_for_production, true);
  assert.equal(published.kind, "library-production-ceremony");
  assert.equal(published.sc09_production_ceremony_approved, false);
  assert.equal(published.spend_prove, "KEYS_MISSING");
  assert.equal(published.verdict, assembled.verdict);
  const provenance = JSON.parse(readFileSync(join(HAZE_ROOT, "dev/artifacts/provenance.json"), "utf8"));
  assert.equal(provenance.sc09.independent_audit.approved, false);
  assert.equal(provenance.sc09.fuji_pilot.approved, false);
  assert.equal(provenance.sc09.production_ceremony.approved, false);
  assert.equal(provenance.sc09.incident_review.approved, false);
  assert.equal(provenance.spend_prove, "KEYS_MISSING");
});

test("npm ceremony-release script verifies the published package", () => {
  const pkg = JSON.parse(readFileSync(join(HAZE_ROOT, "package.json"), "utf8"));
  assert.equal(pkg.scripts["ceremony-release"], "node --experimental-strip-types dev/ceremony-release.mjs");
  const output = execFileSync(process.execPath, ["--experimental-strip-types", "dev/ceremony-release.mjs", "verify"], {
    cwd: HAZE_ROOT,
    encoding: "utf8",
  });
  assert.match(output, /ceremony-release-verify ok/);
  assert.match(output, /0x[0-9a-f]{64}/);
});
