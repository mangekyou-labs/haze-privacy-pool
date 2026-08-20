import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  ApplicationStatus,
  PolicyStatus,
  ReleaseStatus,
  policyIsLive,
  releaseIsExitCapable,
} from "../sdk/typescript/src/registry.ts";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const VECTOR = join(HAZE_ROOT, "circuits/vectors/v1/haze-registry-v1.json");
const APP = join(HAZE_ROOT, "contracts/src/ApplicationRegistry.sol");
const POLICY = join(HAZE_ROOT, "contracts/src/PolicyRegistry.sol");
const VERSION = join(HAZE_ROOT, "contracts/src/VersionRegistry.sol");
const ACCESS = join(HAZE_ROOT, "contracts/src/HazeAccess.sol");

test("registry contracts exist without a proxy upgrade path", () => {
  for (const path of [APP, POLICY, VERSION, ACCESS]) {
    assert.equal(existsSync(path), true);
    const source = readFileSync(path, "utf8");
    assert.doesNotMatch(source, /\bupgradeTo\s*\(/);
    assert.doesNotMatch(source, /\bupgradeToAndCall\s*\(/);
    assert.doesNotMatch(source, /delegatecall/i);
  }
  const versionSource = readFileSync(VERSION, "utf8");
  assert.match(versionSource, /does not upgrade deployed code/);
  const accessSource = readFileSync(ACCESS, "utf8");
  assert.match(accessSource, /confer no registry mutation/);
});

test("policy freshness has no post-activation grace period", () => {
  const vector = JSON.parse(readFileSync(VECTOR, "utf8"));
  assert.equal(ApplicationStatus.Pending, vector.applicationStatus.pending);
  assert.equal(ApplicationStatus.Suspended, vector.applicationStatus.suspended);
  assert.equal(PolicyStatus.Scheduled, vector.policyStatus.scheduled);
  assert.equal(PolicyStatus.Retired, vector.policyStatus.retired);
  for (const row of vector.noGrace) {
    assert.equal(policyIsLive(row.activeVersion, row.activeRoot, row.version, row.root), row.live);
  }
  assert.equal(releaseIsExitCapable(ReleaseStatus.Unspecified, 1, 0), true);
  assert.equal(releaseIsExitCapable(ReleaseStatus.Scheduled, 1, 10), false);
  assert.equal(releaseIsExitCapable(ReleaseStatus.Active, 1, 0), true);
  assert.equal(releaseIsExitCapable(ReleaseStatus.Retired, 5, 10), true);
  assert.equal(releaseIsExitCapable(ReleaseStatus.Retired, 11, 10), false);
});
