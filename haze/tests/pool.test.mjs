import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  POOL_DOMAIN_NAME,
  POOL_DOMAIN_VERSION,
  PoolAction,
  isDirectPoolAction,
  isNormalPoolAction,
} from "../sdk/typescript/src/pool.ts";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const VECTOR = join(HAZE_ROOT, "circuits/vectors/v1/haze-pool-v1.json");
const POOL = join(HAZE_ROOT, "contracts/src/HazePool.sol");
const ROUTER = join(HAZE_ROOT, "contracts/src/SwapAndShieldRouter.sol");
const EXIT = join(HAZE_ROOT, "contracts/src/EmergencyExit.sol");

test("haze pool exists without a proxy and binds an approved emergency-exit sibling", () => {
  assert.equal(existsSync(POOL), true);
  assert.equal(existsSync(ROUTER), true);
  assert.equal(existsSync(EXIT), true);
  const source = readFileSync(POOL, "utf8");
  assert.doesNotMatch(source, /\bupgradeTo\s*\(/);
  assert.doesNotMatch(source, /\bupgradeToAndCall\s*\(/);
  assert.doesNotMatch(source, /delegatecall/i);
  assert.doesNotMatch(source, /\binitialize\s*\(/);
  assert.match(source, /no owner, proxy, or upgrade path/);
  assert.match(source, /depositFromRouter/);
  assert.match(source, /keccak parents reduced mod r/);
});

test("pool domain and action codes match the frozen vector", () => {
  const vector = JSON.parse(readFileSync(VECTOR, "utf8"));
  assert.equal(POOL_DOMAIN_NAME, vector.domainName);
  assert.equal(POOL_DOMAIN_VERSION, vector.domainVersion);
  assert.equal(PoolAction.Deposit, vector.actions.deposit);
  assert.equal(PoolAction.Transfer, vector.actions.transfer);
  assert.equal(PoolAction.Withdraw, vector.actions.withdraw);
  assert.equal(PoolAction.SwapAndShield, vector.actions.swapAndShield);
  assert.equal(PoolAction.EmergencyExit, vector.actions.emergencyExit);
  assert.equal(isDirectPoolAction(PoolAction.Deposit), true);
  assert.equal(isDirectPoolAction(PoolAction.SwapAndShield), false);
  assert.equal(isNormalPoolAction(PoolAction.SwapAndShield), true);
  assert.equal(isNormalPoolAction(PoolAction.EmergencyExit), false);
});
