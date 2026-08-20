import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  EMERGENCY_EXIT_ACTION,
  EMERGENCY_EXIT_COOLDOWN,
  EMERGENCY_EXIT_REQUEST_TYPE,
  EMERGENCY_PUBLIC_CAMEL,
  PoolAction,
  ReleaseStatus,
  emergencyExitRequestId,
  releaseIsExitCapable,
} from "../sdk/typescript/src/index.ts";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const VECTOR = join(HAZE_ROOT, "circuits/vectors/v1/haze-exit-v1.json");
const EXIT = join(HAZE_ROOT, "contracts/src/EmergencyExit.sol");
const POOL = join(HAZE_ROOT, "contracts/src/HazePool.sol");
const VERSION = join(HAZE_ROOT, "contracts/src/VersionRegistry.sol");

test("emergency-exit contract exists without a proxy or owner path", () => {
  assert.equal(existsSync(EXIT), true);
  const source = readFileSync(EXIT, "utf8");
  assert.doesNotMatch(source, /\bupgradeTo\s*\(/);
  assert.doesNotMatch(source, /\bupgradeToAndCall\s*\(/);
  assert.doesNotMatch(source, /delegatecall/i);
  assert.doesNotMatch(source, /\binitialize\s*\(/);
  assert.doesNotMatch(source, /\bowner\s*\(/);
  assert.match(source, /no owner, proxy, or upgrade path/);
  assert.match(source, /keccak256\(abi\.encodePacked\(inputs\)\)/);
  const pool = readFileSync(POOL, "utf8");
  assert.match(pool, /approvedExit/);
  assert.match(pool, /exitFromEmergency/);
  const versions = readFileSync(VERSION, "utf8");
  assert.match(versions, /isExitCapable/);
  assert.match(versions, /supportUntil/);
});

test("emergency-exit request id matches the frozen vector", () => {
  const vector = JSON.parse(readFileSync(VECTOR, "utf8"));
  assert.equal(vector.action, EMERGENCY_EXIT_ACTION);
  assert.equal(vector.action, PoolAction.EmergencyExit);
  assert.equal(vector.cooldownSeconds, EMERGENCY_EXIT_COOLDOWN);
  assert.equal(vector.requestType, EMERGENCY_EXIT_REQUEST_TYPE);
  assert.equal(vector.publicInputCount, EMERGENCY_PUBLIC_CAMEL.length);
  assert.deepEqual(vector.publicInputs, [...EMERGENCY_PUBLIC_CAMEL]);
  const hash = emergencyExitRequestId(vector.fixture);
  assert.equal(hash, vector.fixture.requestId);
});

test("retired versions remain exit-capable only through supportUntil", () => {
  assert.equal(releaseIsExitCapable(ReleaseStatus.Unspecified, 10, 0), true);
  assert.equal(releaseIsExitCapable(ReleaseStatus.Scheduled, 10, 20), false);
  assert.equal(releaseIsExitCapable(ReleaseStatus.Active, 10, 0), true);
  assert.equal(releaseIsExitCapable(ReleaseStatus.Retired, 10, 20), true);
  assert.equal(releaseIsExitCapable(ReleaseStatus.Retired, 21, 20), false);
});
