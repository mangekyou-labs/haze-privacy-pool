import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const runner = readFileSync(new URL("../dev/dappwright-live-spend-walk.mjs", import.meta.url), "utf8");

test("D7 runner is production-only and uses only the exact environment wallet", () => {
  assert.match(runner, /https:\/\/haze-mu-flax\.vercel\.app/);
  assert.match(runner, /process\.env\.PRIVATE_KEY/);
  assert.match(runner, /startsWith\("0x"\)\s*\?\s*rawPrivateKey\s*:\s*`0x\$\{rawPrivateKey\}`/);
  assert.match(runner, /0xeD37FD0d6F0f69236E7472B36796e133D20EcC32/);
  assert.match(runner, /assertProductionOrigin/);
  assert.doesNotMatch(runner, /loadPrivateKey|LOCAL_TEST_SEED|sidecar|fuji-v1\.live|localhost|127\.0\.0\.1|\?live=1|HAZE_OPERATOR_PROVE|operator-prove|readFileSync/);
});

test("D7 runner deposits, reload-recovers, then withdraws in one fresh profile", () => {
  const shield = runner.indexOf('openRoute("/shield")');
  const reload = runner.lastIndexOf("await reloadAfterDepositHash");
  const withdraw = runner.indexOf('openRoute("/withdraw")');
  assert.ok(shield >= 0 && reload > shield && withdraw > reload);
  assert.match(runner, /headless:\s*false/);
  assert.match(runner, /recovering/);
  assert.match(runner, /ready|confirmed/);
  assert.match(runner, /sameBrowserProfile:\s*true/);
  assert.match(runner, /persistedDepositNote/);
  assert.match(runner, /PROVING_TIMEOUT_MS\s*=\s*2_400_000/);
  assert.match(runner, /observedKinds/);
});

test("D7 runner scopes wallet connection to the Fuji transaction region", () => {
  assert.match(runner, /const transactionRegion = \(\) => page\.getByRole\("region", \{ name: "Fuji browser transaction" \}\)/);
  assert.match(runner, /transactionRegion\(\)\.getByRole\("button", \{ name: "Connect wallet", exact: true \}\)/);
  assert.doesNotMatch(runner, /page\.getByRole\("button", \{ name: "Connect wallet" \}\)/);
});

test("D7 runner returns MetaMask to account home before switching to Fuji", () => {
  const home = runner.indexOf('getByTestId("account-options-menu-button")');
  const network = runner.indexOf("wallet.switchNetwork(FUJI_NAME)");
  assert.ok(home >= 0 && network > home);
  assert.match(runner, /add-wallet-page-back-button/);
});

test("D7 evidence separates transactions from disclosure and redacts observations", () => {
  assert.match(runner, /data-transaction-status/);
  assert.match(runner, /data-disclosure-status/);
  assert.match(runner, /membershipUpdate/);
  assert.match(runner, /usdcApproval/);
  assert.match(runner, /deposit/);
  assert.match(runner, /withdrawal/);
  assert.match(runner, /PrivateTransaction/);
  assert.match(runner, /blockNumber/);
  assert.match(runner, /applicationId/);
  assert.match(runner, /commitment/i);
  assert.match(runner, /nullifier/i);
  assert.match(runner, /explorer/);
  assert.match(runner, /deposit-recovery\.png/);
  assert.match(runner, /withdrawal\.png/);
  assert.match(runner, /disclosure\.png/);
  assert.doesNotMatch(runner, /calldata|signature[^A-Za-z]/i);
});
