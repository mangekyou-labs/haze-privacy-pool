import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const INVARIANTS = join(HAZE_ROOT, "contracts/test/ProtocolInvariants.t.sol");
const GAS_TEST = join(HAZE_ROOT, "contracts/test/GasBudgets.t.sol");
const GAS_REPORT = join(HAZE_ROOT, "dev/artifacts/haze-gas-v1.json");
const FOUNDRY = join(HAZE_ROOT, "contracts/foundry.toml");

const REQUIRED_ACTIONS = [
  "verify",
  "deposit",
  "transfer",
  "withdraw",
  "swapAndShield",
  "requestEmergencyExit",
  "executeEmergencyExit",
  "scheduleRegister",
  "activateRegister",
  "schedulePolicy",
  "activatePolicy",
  "scheduleRelease",
  "activateRelease",
  "pause",
  "unpause",
  "scheduleToken",
  "activateToken",
];

test("invariant suite and gas report exist", () => {
  assert.equal(existsSync(INVARIANTS), true);
  assert.equal(existsSync(GAS_TEST), true);
  assert.equal(existsSync(GAS_REPORT), true);
  const invariants = readFileSync(INVARIANTS, "utf8");
  assert.match(invariants, /invariant_usdcConserved/);
  assert.match(invariants, /invariant_routerHasNoResidue/);
  assert.match(invariants, /invariant_nullifiersConsumedOnce/);
  assert.match(invariants, /invariant_rolesCannotSpendNotes/);
  assert.match(invariants, /targetContract/);
  const foundry = readFileSync(FOUNDRY, "utf8");
  assert.match(foundry, /\[invariant\]/);
});

test("provisional gas report covers every user and governance action", () => {
  const report = JSON.parse(readFileSync(GAS_REPORT, "utf8"));
  assert.equal(report.not_for_production, true);
  assert.equal(report.network, "local-foundry");
  assert.equal(report.fuji_required_before_mainnet, true);
  for (const action of REQUIRED_ACTIONS) {
    assert.equal(typeof report.actions[action].measured, "number");
    assert.equal(typeof report.actions[action].budget, "number");
    assert.ok(report.actions[action].measured > 0);
    assert.ok(report.actions[action].budget >= report.actions[action].measured);
  }
});
