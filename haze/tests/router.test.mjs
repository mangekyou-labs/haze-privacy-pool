import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  PoolAction,
  SWAP_AND_SHIELD_ACTION,
  encodeRoute,
  routeHash,
  swapRoute,
} from "../sdk/typescript/src/index.ts";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const VECTOR = join(HAZE_ROOT, "circuits/vectors/v1/haze-router-v1.json");
const ROUTER = join(HAZE_ROOT, "contracts/src/SwapAndShieldRouter.sol");
const EXIT = join(HAZE_ROOT, "contracts/src/EmergencyExit.sol");
const VENDOR = /lfj|trader\s*joe|pangolin|uniswap/i;

test("swap-and-shield router exists without a proxy, vendor name, or emergency-exit path", () => {
  assert.equal(existsSync(ROUTER), true);
  assert.equal(existsSync(EXIT), true);
  const source = readFileSync(ROUTER, "utf8");
  assert.doesNotMatch(source, /\bupgradeTo\s*\(/);
  assert.doesNotMatch(source, /\bupgradeToAndCall\s*\(/);
  assert.doesNotMatch(source, /delegatecall/i);
  assert.doesNotMatch(source, /\binitialize\s*\(/);
  assert.doesNotMatch(source, /\bowner\s*\(/);
  assert.doesNotMatch(source, VENDOR);
  assert.match(source, /No owner, proxy, upgrade, or emergency-exit path/);
  assert.match(source, /keccak256\(abi\.encode\(route\.adapter, route\.data\)\)/);
  assert.match(source, /depositFromRouter/);
});

test("route hash encoding matches the frozen vector", () => {
  const vector = JSON.parse(readFileSync(VECTOR, "utf8"));
  assert.equal(vector.action, SWAP_AND_SHIELD_ACTION);
  assert.equal(vector.action, PoolAction.SwapAndShield);
  assert.equal(vector.routeHashEncoding, "abi.encode(adapter, data)");
  const hash = routeHash(vector.fixture.adapter, vector.fixture.data);
  assert.equal(hash, vector.fixture.routeHash);
  const built = swapRoute(vector.fixture.adapter, vector.fixture.data);
  assert.equal(built.expectedRouteHash, vector.fixture.routeHash);
  assert.equal(encodeRoute(vector.fixture.adapter, vector.fixture.data).length, 128);
});
