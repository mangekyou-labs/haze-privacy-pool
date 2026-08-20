import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { assembleReview, verifyReview } from "../dev/security-review.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const SURFACES = [
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

test("security review covers the ten T6.4 surfaces with no open critical or high findings", () => {
  const report = assembleReview();
  assert.equal(report.notForProduction, true);
  assert.equal(report.surfaces.length, 10);
  assert.deepEqual(
    report.surfaces.map((surface) => surface.id),
    SURFACES,
  );
  for (const surface of report.surfaces) {
    assert.equal(surface.status, "reviewed");
    assert.ok(surface.evidence.length > 0, `${surface.id} missing evidence`);
    for (const path of surface.evidence) {
      assert.equal(existsSync(join(HAZE_ROOT, path)), true, path);
    }
  }
  assert.equal(report.findings.critical.length, 0);
  assert.equal(report.findings.high.length, 0);
  assert.equal(report.openCritical, 0);
  assert.equal(report.openHigh, 0);
  assert.match(report.verdict, /^pass/);
});

test("medium findings require an owner and an approved release disposition", () => {
  const report = assembleReview();
  assert.deepEqual(
    report.findings.medium.map((finding) => finding.id),
    [],
  );
  for (const finding of report.findings.medium) {
    assert.match(finding.id, /^M-\d{2}$/);
    assert.equal(typeof finding.title, "string");
    assert.ok(finding.title.length > 0);
    assert.equal(typeof finding.owner, "string");
    assert.ok(finding.owner.length > 0);
    assert.ok(
      finding.disposition === "approved-deferral" || finding.disposition === "accepted-risk",
      `${finding.id} missing approved disposition`,
    );
    assert.match(finding.until, /^T\d+\.\d+$/);
    assert.ok(finding.reason.length > 0);
  }
  assert.equal(
    report.findings.medium.some((finding) => finding.id === "M-01" || finding.id === "M-03"),
    false,
  );
  assert.equal(report.verdict, "pass");
});

test("security review inspects live source for proxy, custody, and license controls", () => {
  const report = assembleReview();
  assert.equal(report.checks.contractsForbidOwnerProxy, true);
  assert.equal(report.checks.navIsNotAuthorization, true);
  assert.equal(report.checks.witnessesNotLogged, true);
  assert.equal(report.checks.custodyApisDenied, true);
  assert.equal(report.checks.sdkLicense, "Apache-2.0");
  assert.equal(report.checks.nobleCurvesLicense, "MIT");
  assert.equal(report.checks.rustPackageCount, 6);
  assert.equal(report.checks.nodePackageCount, 3);
  assert.equal(report.checks.independentReview, "91cfa5ee");
});

test("published security-review fixture hashes match verifyReview", () => {
  const verified = verifyReview();
  const assembled = assembleReview();
  assert.match(verified.fixtureHash, /^0x[0-9a-f]{64}$/);
  assert.equal(verified.fixtureHash, assembled.hash);
  const published = JSON.parse(readFileSync(join(HAZE_ROOT, "dev/fixtures/security-review.json"), "utf8"));
  assert.equal(published.fixtureHash, verified.fixtureHash);
  assert.equal(published.not_for_production, true);
  assert.equal(published.verdict, assembled.verdict);
  assert.equal(published.open_critical, 0);
  assert.equal(published.open_high, 0);
  assert.equal(published.surfaces, 10);
});

test("npm security-review script verifies the published report", () => {
  const pkg = JSON.parse(readFileSync(join(HAZE_ROOT, "package.json"), "utf8"));
  assert.equal(pkg.scripts["security-review"], "node --experimental-strip-types dev/security-review.mjs");
  const output = execFileSync(process.execPath, ["--experimental-strip-types", "dev/security-review.mjs", "verify"], {
    cwd: HAZE_ROOT,
    encoding: "utf8",
  });
  assert.match(output, /security-review-verify ok/);
  assert.match(output, /0x[0-9a-f]{64}/);
});
