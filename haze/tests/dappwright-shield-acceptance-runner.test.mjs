import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const ROOT = dirname(fileURLToPath(import.meta.url));
const shieldPath = join(ROOT, "../dev/dappwright-shield-acceptance.mjs");
const completePath = join(ROOT, "../dev/dappwright-complete-acceptance.mjs");

test("shield acceptance runner waits for vault-ready before History cards", () => {
  assert.ok(existsSync(shieldPath), "dappwright-shield-acceptance.mjs must exist");
  const runner = readFileSync(shieldPath, "utf8");

  assert.match(runner, /data-vault-ready/);
  assert.match(runner, /haze-history-card/);
  assert.match(runner, /href=["']\/history["']|a\.haze-tab.*history|getByRole\([^)]*History/i);
});

test("shield acceptance records a history-stage failure instead of Shield execution when History times out after finality", () => {
  const runner = readFileSync(shieldPath, "utf8");
  assert.match(runner, /recordFailure\(\s*"shield",\s*"history"/);
  const finality = runner.indexOf("recordFinality");
  const historyStage = runner.indexOf('recordFailure("shield", "history"');
  assert.ok(finality >= 0 && historyStage > finality, "history-stage failure must be recorded after Shield finality");
  assert.match(runner, /screenshot|page\.content\(\)/);
});

test("shield acceptance hands playwright-cli a storage state only after History is proven", () => {
  const runner = readFileSync(shieldPath, "utf8");
  const cards = runner.lastIndexOf("haze-history-card");
  const storage = runner.indexOf("storageState");
  const cli = runner.indexOf("execSync(`playwright-cli");
  assert.ok(cards >= 0 && storage > cards, "storageState must be saved after History cards are asserted");
  assert.ok(cli > storage, "playwright-cli must run only after dappwright saved storage state");
  assert.match(runner, /playwright-cli -s=/);
});

test("shield acceptance records playwright-cli execution and uses --filename for screenshots", () => {
  const runner = readFileSync(shieldPath, "utf8");
  assert.match(runner, /screenshot --filename=/);
  assert.match(runner, /markToolExecuted\(\s*["']playwrightCli["']\s*\)/);
  assert.match(runner, /verifyFujiMvpV2Manifest\([^)]*shieldOnly:\s*true/);
  const mark = runner.indexOf('markToolExecuted("playwrightCli")');
  const verify = runner.lastIndexOf("verifyFujiMvpV2Manifest(");
  assert.ok(mark >= 0 && verify > mark, "playwrightCli must be marked before evidence verification");
  assert.doesNotMatch(
    runner,
    /playwright-cli execution notice/,
    "CLI failures must fail the Shield gate, not be swallowed",
  );
});

test("complete acceptance records playwright-cli screenshots with --filename", () => {
  const runner = readFileSync(completePath, "utf8");
  assert.match(runner, /screenshot --filename=/);
  assert.match(runner, /markToolExecuted\(\s*["']playwrightCli["']\s*\)/);
});

test("complete acceptance bootstraps the dedicated auditor session before the CLI walkthrough", () => {
  const runner = readFileSync(completePath, "utf8");
  assert.match(runner, /import\s*\{\s*runAuditBootstrap\s*\}/);

  const bootstrap = runner.indexOf("await runAuditBootstrap(");
  const cliWalk = runner.indexOf("await runPlaywrightCliAuditWalk(");
  assert.ok(bootstrap >= 0 && cliWalk > bootstrap, "auditor SIWE bootstrap must precede the CLI audit walk");
  assert.match(runner.slice(bootstrap, cliWalk + 400), /sessionStatePath:\s*auditBootstrap\.sessionStatePath/);
});

test("complete acceptance retries transient production navigation and routes Swap through the bounded helper", () => {
  const runner = readFileSync(completePath, "utf8");
  assert.match(runner, /ERR_NETWORK_CHANGED/);
  assert.match(runner, /async function openRoute/);
  assert.match(runner, /for\s*\([^)]*attempt[^)]*<\s*3/);
  assert.match(runner, /await openRoute\(["']\/swap["']\)/);
  assert.doesNotMatch(runner, /await page\.goto\(`\$\{origin\}\/swap`/);
});

test("complete acceptance imports Account B with wallet.importPK", () => {
  const runner = readFileSync(completePath, "utf8");
  assert.doesNotMatch(runner, /wallet\.importAccount/);
  assert.match(runner, /wallet\.importPK\(/);
  assert.match(runner, /duplicate/i);
});

test("complete acceptance dismisses leftover MetaMask UI after Account B import/switch and confirms connect signatures", () => {
  const runner = readFileSync(completePath, "utf8");
  const importPk = runner.indexOf("wallet.importPK(");
  const switchAccount = runner.indexOf('switchAccount("Account 2")');
  const connectVaultCall = runner.indexOf("await connectVault()", switchAccount);
  assert.ok(importPk >= 0 && switchAccount > importPk && connectVaultCall > switchAccount);

  assert.match(runner, /async function dismissMetaMaskLeftover/);
  assert.match(runner, /account-options-menu-button/);

  const afterImport = runner.slice(importPk, switchAccount);
  assert.match(
    afterImport,
    /dismissMetaMaskLeftover/,
    "duplicate importPK leaves MetaMask on add-wallet/account-list; dismiss before switchAccount",
  );

  const afterSwitch = runner.slice(switchAccount, connectVaultCall);
  assert.match(
    afterSwitch,
    /dismissMetaMaskLeftover/,
    "switchAccount leaves the account menu open; dismiss before Connect",
  );

  const connectFn = runner.indexOf("async function connectVault");
  const switchFn = runner.indexOf("async function switchAndVerifyAccount");
  const connectBody = runner.slice(connectFn, switchFn);
  assert.match(connectBody, /bringToFront/);
  assert.match(connectBody, /eth_requestAccounts/);
  assert.match(connectBody, /eth_signTypedData_v4/);
  assert.match(connectBody, /personal_sign/);
  assert.doesNotMatch(
    connectBody,
    /confirmAny\(\s*["']wallet_connect_or_sign["']\s*,\s*2000\s*\)/,
    "2s confirm loop races MetaMask after account switch; confirm the three connect steps with the default timeout",
  );
});

test("complete acceptance keeps confirming connect signatures until the session address is visible", () => {
  const runner = readFileSync(completePath, "utf8");
  const connectFn = runner.indexOf("async function connectVault");
  const switchFn = runner.indexOf("async function switchAndVerifyAccount");
  const connectBody = runner.slice(connectFn, switchFn);
  const loop = connectBody.search(/while\s*\(\s*Date\.now\(\)\s*</);
  assert.ok(loop >= 0, "connectVault must retry until the session chip is visible");
  const waitFor = connectBody.indexOf("addressEl.waitFor");
  assert.ok(waitFor < 0 || waitFor > loop, "must keep confirming before a one-shot waitFor");
  const requestAccounts = connectBody.indexOf("eth_requestAccounts");
  assert.ok(requestAccounts > loop, "the retry loop must include the connect signatures");
  assert.match(connectBody, /120_000|120000/, "typed-data + personal_sign after eth_requestAccounts needs more than 60s");
  const sessionControl = connectBody.indexOf("haze-session-control");
  assert.ok(sessionControl >= 0 && sessionControl < loop, "must wait for the portaled session control before clicking Connect");
});

test("complete acceptance isolates dappwright MetaMask session from shared TEST_WORKER_INDEX 0", () => {
  const runner = readFileSync(completePath, "utf8");
  const worker = runner.indexOf("TEST_WORKER_INDEX");
  const bootstrap = runner.indexOf('bootstrap("chromium"');
  assert.ok(worker >= 0 && bootstrap > worker, "must pin TEST_WORKER_INDEX before the pool-wallet bootstrap");
  assert.match(runner, /TEST_WORKER_INDEX[\s\S]{0,120}haze-fuji-mvp/);
});

test("complete acceptance bounds wallet.approve so connectVault cannot hang on a leftover dialog", () => {
  const runner = readFileSync(completePath, "utf8");
  const confirmFn = runner.indexOf("async function confirmAny");
  const connectFn = runner.indexOf("async function connectVault");
  assert.ok(confirmFn >= 0 && connectFn > confirmFn);
  const confirmBody = runner.slice(confirmFn, connectFn);
  assert.match(confirmBody, /Promise\.race/);
  assert.match(confirmBody, /wallet\.approve\(/);
});

test("complete acceptance does not pin MetaMask over other Playwright windows while waiting for Connect", () => {
  const runner = readFileSync(completePath, "utf8");
  const connectFn = runner.indexOf("async function connectVault");
  const switchFn = runner.indexOf("async function switchAndVerifyAccount");
  const connectBody = runner.slice(connectFn, switchFn);
  const loop = connectBody.search(/while\s*\(\s*Date\.now\(\)\s*</);
  assert.ok(loop >= 0, "connectVault must retry until the session chip is visible");
  const loopBody = connectBody.slice(loop);
  assert.doesNotMatch(
    loopBody,
    /\.bringToFront\(/,
    "connectVault must not steal window focus on every retry tick",
  );
  const confirmCalls = [...loopBody.matchAll(/confirmAny\s*\(/g)];
  assert.equal(confirmCalls.length, 1, "one confirmAny per tick; three sequential 3s approves pin MetaMask for ~9s");
  assert.match(
    loopBody,
    /notification\.html|isWalletNotificationPage|hasWalletNotification/,
    "only confirm when a MetaMask notification dialog is open",
  );
});

test("confirmAny does not race wallet.approve when no MetaMask notification is open", () => {
  const runner = readFileSync(completePath, "utf8");
  const confirmFn = runner.indexOf("async function confirmAny");
  const connectFn = runner.indexOf("async function connectVault");
  const confirmBody = runner.slice(confirmFn, connectFn);
  const notification = confirmBody.search(/notification\.html|isWalletNotificationPage|hasWalletNotification/);
  const approve = confirmBody.indexOf("wallet.approve");
  assert.ok(notification >= 0, "confirmAny must look for notification.html before polling");
  assert.ok(approve >= 0 && notification < approve, "empty MetaMask home must not start wallet.approve");
  assert.match(confirmBody, /return false/);
});

test("complete acceptance selects MetaMask accounts by address after switchAccount", () => {
  const runner = readFileSync(completePath, "utf8");
  assert.match(runner, /account-menu-icon/);
  assert.match(runner, /0xf39|f39Fd6|ACCOUNT_A_ADDRESS\.slice/);
  assert.match(runner, /0x7099|70997970|ACCOUNT_B_ADDRESS\.slice/);
  const switchFn = runner.indexOf("async function switchAndVerifyAccount");
  const phase1 = runner.indexOf("PHASE 1");
  const switchBody = runner.slice(switchFn, phase1);
  assert.match(switchBody, /account-menu-icon|selectMetaMaskAccount/);
  const switchAccount2 = runner.indexOf('switchAccount("Account 2")');
  const connectVaultCall = runner.indexOf("await connectVault()", switchAccount2);
  assert.match(
    runner.slice(switchAccount2, connectVaultCall),
    /selectMetaMaskAccount|account-menu-icon|0x7099|70997970/,
  );
});

test("complete acceptance revokes MetaMask site permissions before reconnecting a switched account", () => {
  const runner = readFileSync(completePath, "utf8");
  const switchFn = runner.indexOf("async function switchAndVerifyAccount");
  const phase1 = runner.indexOf("PHASE 1");
  const switchBody = runner.slice(switchFn, phase1);
  assert.match(switchBody, /wallet_revokePermissions/);
  assert.match(switchBody, /eth_accounts/);
});

test("complete acceptance disconnects a mismatched header session before reconnecting the switched account", () => {
  const runner = readFileSync(completePath, "utf8");
  const switchFn = runner.indexOf("async function switchAndVerifyAccount");
  const phase1 = runner.indexOf("PHASE 1");
  const switchBody = runner.slice(switchFn, phase1);
  assert.match(switchBody, /data-action=["']disconnect["']/);
  assert.match(switchBody, /connectVault\(/);
  assert.match(switchBody, /ACCOUNT_SWITCH_FAILED/);
});

test("complete acceptance does not redeclare Recover locators in the same function", () => {
  const runner = readFileSync(completePath, "utf8");
  const decls = runner.match(/\bconst recoverBtn\b/g) || [];
  assert.ok(decls.length <= 1, "Phase 2 and Phase 4 Recover locators must use distinct identifiers");
});

test("complete acceptance skips Shield when recover already found a spendable note", () => {
  const runner = readFileSync(completePath, "utf8");
  const shield = runner.indexOf("PHASE 2");
  const send = runner.indexOf("PHASE 3");
  const shieldBody = runner.slice(shield, send);
  assert.match(shieldBody, /data-spendable-note-count/);
  assert.match(shieldBody, /SKIP_SHIELD|skipShield|spendableNoteCount/);
  assert.match(shieldBody, /Recover from wallet message/);
  const confirm = shieldBody.indexOf("haze-confirm");
  const skip = Math.max(
    shieldBody.search(/SKIP_SHIELD|skipShield|spendableNoteCount/),
    0,
  );
  assert.ok(confirm > skip, "Shield confirm must run only after the spendable-note skip check");
});

test("complete acceptance only skips Shield for the recovered note's own finalized Shield transaction", () => {
  const runner = readFileSync(completePath, "utf8");
  const shield = runner.indexOf("PHASE 2");
  const send = runner.indexOf("PHASE 3");
  const shieldBody = runner.slice(shield, send);
  assert.match(shieldBody, /data-spendable-shield-note-count/);
  assert.match(shieldBody, /data-spendable-shield-tx-hash/);
  assert.match(shieldBody, /shieldTxHash\s*=\s*recoveredShieldTxHash/);
  assert.match(shieldBody, /waitForFinality\(shieldTxHash,\s*1\)/);
});

test("complete acceptance waits long enough for cold Fuji proving artifacts before Shield broadcast timeout", () => {
  const runner = readFileSync(completePath, "utf8");
  const shield = runner.indexOf("PHASE 2");
  const send = runner.indexOf("PHASE 3");
  const shieldBody = runner.slice(shield, send);
  assert.match(shieldBody, /data-vault-ready|waitForVaultReady|connectVault\(/);
  assert.match(shieldBody, /900_000|15 \* 60 \* 1000|900000/);
  assert.match(shieldBody, /haze-error|\[data-error\]/);
});

test("complete acceptance fails fast on terminal Withdraw UI errors without shortening cold proving", () => {
  const runner = readFileSync(completePath, "utf8");
  const phase4 = runner.indexOf("PHASE 4");
  const phase5 = runner.indexOf("PHASE 5");
  assert.ok(phase4 >= 0 && phase5 > phase4, "Phase 4 and Phase 5 markers required");
  const withdrawBody = runner.slice(phase4, phase5);

  assert.match(withdrawBody, /WITHDRAW_UI_ERROR/);
  assert.match(withdrawBody, /\.haze-error|\[data-error\]/);
  assert.match(withdrawBody, /900_000|15 \* 60 \* 1000|900000/);
});

test("complete acceptance establishes a pool-user BFF session before the PILOT faucet", () => {
  const runner = readFileSync(completePath, "utf8");
  const phase5 = runner.indexOf("PHASE 5");
  const phase6 = runner.indexOf("PHASE 6");
  assert.ok(phase5 >= 0 && phase6 > phase5, "Phase 5 and Phase 6 markers required");
  const body = runner.slice(phase5, phase6);

  assert.match(body, /\/api\/v1\/auth\/challenge/);
  assert.match(body, /pool-user/);
  assert.match(body, /personal_sign/);
  assert.match(body, /\/api\/v1\/auth\/verify/);

  const challenge = body.indexOf("/api/v1/auth/challenge");
  const verify = body.indexOf("/api/v1/auth/verify");
  const faucet = body.indexOf("/api/v1/pool/faucet");
  assert.ok(challenge >= 0 && verify > challenge && faucet > verify, "SIWE challenge then verify then faucet");
  assert.match(body.slice(faucet), /credentials:\s*["']include["']/);
});

test("complete acceptance skips the PILOT faucet when Account A already holds enough PILOT", () => {
  const runner = readFileSync(completePath, "utf8");
  const phase5 = runner.indexOf("PHASE 5");
  const phase6 = runner.indexOf("PHASE 6");
  const body = runner.slice(phase5, phase6);
  assert.match(body, /SKIP_FAUCET|skipFaucet/);
  assert.match(body, /balanceOf|70a08231/);
  const skip = body.search(/SKIP_FAUCET|skipFaucet/);
  const faucet = body.indexOf("/api/v1/pool/faucet");
  assert.ok(skip >= 0 && faucet > skip, "PILOT balance skip must run before faucet POST");
});

test("complete acceptance fails fast when Swap renders a terminal UI error", () => {
  const runner = readFileSync(completePath, "utf8");
  const phase5 = runner.indexOf("PHASE 5");
  const phase6 = runner.indexOf("PHASE 6");
  const body = runner.slice(phase5, phase6);
  assert.match(body, /SWAP_UI_ERROR/);
  assert.match(body, /\.haze-error/);
});

test("complete acceptance waits for vault-ready before capturing Account B haze1 and does not fake a Shield failure", () => {
  assert.ok(existsSync(completePath), "dappwright-complete-acceptance.mjs must exist");
  const runner = readFileSync(completePath, "utf8");

  assert.match(runner, /data-vault-ready/);
  const phase1 = runner.indexOf("PHASE 1");
  const vaultReady = runner.indexOf("waitForVaultReady", phase1);
  const haze1 = runner.indexOf("data-haze-address", phase1);
  assert.ok(phase1 >= 0 && vaultReady > phase1 && haze1 > vaultReady, "Phase 1 must wait for vault-ready before [data-haze-address]");
  assert.match(runner, /FAILED_TO_CAPTURE_ACCOUNT_B_HAZE1/);
  assert.doesNotMatch(runner, /recordFailure\("shield"/);
  assert.match(runner, /href=["']\/history["']|a\.haze-tab.*history|getByRole\([^)]*History/i);
  const storage = runner.indexOf("storageState");
  const cli = runner.indexOf("execSync(`playwright-cli");
  assert.ok(storage >= 0 && cli > storage, "complete runner must save storage state before playwright-cli");
});
