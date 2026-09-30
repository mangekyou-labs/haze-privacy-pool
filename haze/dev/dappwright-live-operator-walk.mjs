/** Headed MetaMask Shield → Withdraw on the operator hatch. Not T7.4. Does not write fuji-v1.json. */

import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { bootstrap, MetaMaskWallet } from "@tenkeylabs/dappwright";
import { LOCAL_TEST_SEED, planDappwrightLiveOperator, recordLiveOperatorOverlay } from "./dappwright-bootstrap.mjs";
import { loadPrivateKey } from "./fuji-live-deploy.mjs";
import { DEFAULT_ZKEY } from "./operator-prove.mjs";

const ROOT = dirname(fileURLToPath(import.meta.url));
const COMMERCIAL = process.env.HAZE_COMMERCIAL_URL ?? "http://127.0.0.1:3014";
const FUJI_RPC = "https://api.avax-test.network/ext/bc/C/rpc";
const FUJI_NAME = "Avalanche Fuji C-Chain";
const LIVE_OVERLAY = join(ROOT, "../deployments/fuji-v1.live.json");
const COMMITTED_FUJI = join(ROOT, "../deployments/fuji-v1.json");
const SHIELD_SHOT = join(ROOT, "../output/playwright/dapp-fuji-operator-shield.png");
const WITHDRAW_SHOT = join(ROOT, "../output/playwright/dapp-fuji-operator-withdraw.png");

function sidecar() {
  if (!existsSync(LIVE_OVERLAY)) {
    return null;
  }
  return JSON.parse(readFileSync(LIVE_OVERLAY, "utf8"));
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForStatus(page, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const text = (await page.locator("[data-live-status]").textContent()) ?? "";
    if (/^0x[0-9a-fA-F]{64}$/.test(text.trim()) || /FAILED|DENIED|MISSING|rejected|REVERTED/i.test(text)) {
      return text.trim();
    }
    await sleep(1000);
  }
  return (await page.locator("[data-live-status]").textContent())?.trim() ?? "";
}

async function waitFujiReceipt(hash, timeoutMs = 180_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const body = await fetch(FUJI_RPC, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "eth_getTransactionReceipt",
        params: [hash],
      }),
    }).then((response) => response.json());
    if (body.result) {
      return body.result;
    }
    await sleep(1000);
  }
  return null;
}

const overlay = sidecar();
const planned = planDappwrightLiveOperator({
  sidecar: overlay,
  zkeyExists: existsSync(DEFAULT_ZKEY),
  commercialUrl: COMMERCIAL,
});
if (!planned.ok) {
  console.error(JSON.stringify(planned));
  process.exit(1);
}

const privateKey = loadPrivateKey();
const [wallet, , context] = await bootstrap("chromium", {
  wallet: "metamask",
  version: MetaMaskWallet.recommendedVersion,
  seed: LOCAL_TEST_SEED,
  headless: false,
});

async function importPrivateKey(wallet, pk) {
  const mm = wallet.page;
  await mm.bringToFront();
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      await mm.getByTestId("account-menu-icon").click({ timeout: 10_000 });
    } catch {
      // already open
    }
    await mm.getByTestId("account-list-add-wallet-button").click();
    const importRow = mm.getByTestId("add-wallet-modal-import-account");
    await importRow.waitFor({ state: "visible" });
    await sleep(400);
    await importRow.click({ force: true });
    const field = mm.getByRole("textbox").or(mm.locator('input[type="password"]')).first();
    await field.waitFor({ state: "visible", timeout: 15_000 });
    await field.fill(pk);
    await mm.getByTestId("import-account-confirm-button").click();
    const back = mm.getByRole("button", { name: /back/i }).first();
    if (await back.isVisible().catch(() => false)) {
      await back.click();
    }
    return;
  }
}

await importPrivateKey(wallet, privateKey);
const mm = wallet.page;
await mm.bringToFront();
try {
  await mm.getByTestId("account-menu-icon").click({ timeout: 8_000 });
} catch {
  // already open
}
const imported = mm.getByText(/0xeD37|eD37FD0d/i).first();
if (await imported.isVisible().catch(() => false)) {
  await imported.click();
} else {
  const accounts = mm.locator("[data-testid='account-list-item'], [data-testid='multichain-account-cell']");
  const count = await accounts.count();
  if (count > 0) {
    await accounts.nth(count - 1).click();
  } else {
    await mm.keyboard.press("Escape");
  }
}
await mm.keyboard.press("Escape");
await sleep(400);
for (let i = 0; i < 5; i += 1) {
  if (await mm.getByTestId("account-options-menu-button").isVisible().catch(() => false)) {
    break;
  }
  const back = mm.getByTestId("add-wallet-page-back-button").or(mm.getByRole("button", { name: /^back$/i })).first();
  if (await back.isVisible().catch(() => false)) {
    await back.click();
  } else {
    await mm.keyboard.press("Escape");
  }
  await sleep(400);
}
try {
  await wallet.addNetwork({
    networkName: FUJI_NAME,
    rpc: FUJI_RPC,
    chainId: 43113,
    symbol: "AVAX",
  });
} catch (error) {
  console.error("addNetwork:", error instanceof Error ? error.message : error);
}
try {
  await wallet.switchNetwork(FUJI_NAME);
} catch (error) {
  console.error("switchNetwork:", error instanceof Error ? error.message : error);
}

async function confirmAny(label, timeoutMs = 45_000) {
  const deadline = Date.now() + timeoutMs;
  const names = /^(Confirm|Approve|Next|Sign)$/i;
  while (Date.now() < deadline) {
    for (const popup of context.pages()) {
      const url = popup.url();
      if (url.startsWith(COMMERCIAL)) {
        continue;
      }
      const scrollBtn = popup.locator("[data-testid='signature-request-scroll-button']").first();
      if (await scrollBtn.isVisible().catch(() => false)) {
        await scrollBtn.click().catch(() => undefined);
        await sleep(250);
      }
      const button = popup
        .getByTestId("confirm-footer-button")
        .or(popup.getByTestId("confirm-btn"))
        .or(popup.getByTestId("page-container-footer-next"))
        .or(popup.getByRole("button", { name: names }))
        .first();
      if ((await button.isVisible().catch(() => false)) && (await button.isEnabled().catch(() => false))) {
        await popup.bringToFront();
        await button.click();
        console.error(`confirmed ${label}`);
        const gone = Date.now() + 20_000;
        while (Date.now() < gone) {
          if (!(await button.isVisible().catch(() => false))) {
            break;
          }
          await sleep(250);
        }
        await sleep(400);
        return true;
      }
    }
    await sleep(250);
  }
  console.error(`no confirm UI for ${label}`);
  return false;
}

const page = await context.newPage();
page.on("console", (msg) => {
  console.error(`page:${msg.type()} ${msg.text()}`);
});
page.on("pageerror", (error) => {
  console.error(`pageerror ${error.message}`);
});

async function openLive(path, reviewed = false) {
  const suffix = reviewed ? "&reviewed=1" : "";
  await page.goto(`${COMMERCIAL}${path}?live=1${suffix}`, { waitUntil: "domcontentloaded" });
}

await openLive("/shield");
const hatch = await page.locator('[data-code="operator-demo"]').first().isVisible().catch(() => false);
if (!hatch) {
  console.error(JSON.stringify({ hatchMissing: true, url: page.url() }));
  await context.close();
  process.exit(1);
}

const connect = page.locator('button[data-action="connect"]').first();
if (await connect.isVisible()) {
  await connect.click();
  await confirmAny("connect");
  await confirmAny("network-switch", 8_000);
  await page.waitForLoadState("domcontentloaded");
  await page.locator("[data-address]").waitFor({ timeout: 45_000 });
  await sleep(500);
}

await openLive("/shield", true);
const connected = await page.locator("[data-address]").getAttribute("data-address").catch(() => null);
console.error(JSON.stringify({ connected, url: page.url() }));
if (!connected || !/ed37fd0d6f0f69236e7472b36796e133d20ecc32/i.test(connected)) {
  console.error(JSON.stringify({ wrongAccount: connected }));
  await context.close();
  process.exit(1);
}

async function currentChainId() {
  return page.evaluate(() => globalThis.ethereum?.request({ method: "eth_chainId" }));
}

async function ensureFujiNetwork() {
  let chainId = await currentChainId();
  if (chainId !== "0xa869") {
    const switchButton = page.locator('[data-code="wrong-chain"] [data-action="switch-network"]').first();
    if (await switchButton.isVisible().catch(() => false)) {
      await switchButton.click();
      await confirmAny("network-switch", 30_000);
      await page.waitForLoadState("domcontentloaded").catch(() => undefined);
      await sleep(500);
    }
    chainId = await currentChainId();
  }
  if (chainId !== "0xa869") {
    await wallet.switchNetwork(FUJI_NAME).catch((error) => {
      console.error("switchNetwork retry:", error instanceof Error ? error.message : error);
    });
    await sleep(500);
    chainId = await currentChainId();
  }
  console.error(JSON.stringify({ chainId }));
  if (chainId !== "0xa869") {
    await context.close();
    process.exit(1);
  }
}

await ensureFujiNetwork();

async function reviewAndSubmit() {
  const review = page.getByRole("button", { name: "I understand — continue" });
  if (await review.isVisible() && (await review.isEnabled())) {
    await Promise.all([page.waitForLoadState("domcontentloaded"), review.click()]);
  }
  const submit = page.locator('form[data-live="true"] button[data-action="run"]');
  await submit.waitFor({ state: "visible", timeout: 15_000 });
  if (!(await submit.isEnabled())) {
    const label = (await submit.textContent())?.trim();
    console.error(JSON.stringify({ blocked: label, url: page.url() }));
    process.exit(1);
  }
  return submit;
}

const shieldSubmit = await reviewAndSubmit();
await shieldSubmit.click();
await confirmAny("usdc-approve", 120_000);
await confirmAny("typed-data", 1_800_000);
await confirmAny("deposit", 120_000);

const shieldStatus = await waitForStatus(page, 1_800_000);
mkdirSync(dirname(SHIELD_SHOT), { recursive: true });
await page.screenshot({ path: SHIELD_SHOT, fullPage: true });
console.error(JSON.stringify({ shield: shieldStatus, screenshot: SHIELD_SHOT }));
if (!/^0x[0-9a-fA-F]{64}$/.test(shieldStatus)) {
  await context.close();
  process.exit(1);
}
const shieldReceipt = await waitFujiReceipt(shieldStatus);
console.error(JSON.stringify({ shieldReceipt: shieldReceipt?.status ?? null }));
if (shieldReceipt?.status !== "0x1") {
  await context.close();
  process.exit(1);
}

await openLive("/withdraw", true);
const withdrawSubmit = await reviewAndSubmit();
const recipient = page.locator('input[name="recipient"]');
if (await recipient.isVisible().catch(() => false)) {
  await recipient.fill(connected);
}
await withdrawSubmit.click();
await confirmAny("typed-data", 1_800_000);
await confirmAny("withdraw", 120_000);

const withdrawStatus = await waitForStatus(page, 1_800_000);
mkdirSync(dirname(WITHDRAW_SHOT), { recursive: true });
await page.screenshot({ path: WITHDRAW_SHOT, fullPage: true });
if (!/^0x[0-9a-fA-F]{64}$/.test(withdrawStatus)) {
  await context.close();
  process.exit(1);
}
const withdrawReceipt = await waitFujiReceipt(withdrawStatus);
console.error(JSON.stringify({ withdrawReceipt: withdrawReceipt?.status ?? null }));
if (withdrawReceipt?.status !== "0x1") {
  await context.close();
  process.exit(1);
}
const disclosurePhase = (await page.locator("[data-prove-phase]").textContent().catch(() => ""))?.trim() ?? "";
console.error(JSON.stringify({ auditAcceptance: disclosurePhase === "Scoped audit disclosure verified." }));
if (disclosurePhase !== "Scoped audit disclosure verified.") {
  await context.close();
  process.exit(1);
}
const recorded = recordLiveOperatorOverlay({
  overlayPath: LIVE_OVERLAY,
  shield: shieldStatus,
  withdraw: withdrawStatus,
  host: COMMERCIAL,
  shieldReceipt,
  withdrawReceipt,
});
console.error(JSON.stringify(recorded));
if (!recorded.ok) {
  await context.close();
  process.exit(1);
}
const published = JSON.parse(readFileSync(COMMITTED_FUJI, "utf8"));
console.log(
  JSON.stringify({
    shield: shieldStatus,
    withdraw: withdrawStatus,
    connected,
    host: COMMERCIAL,
    screenshots: [SHIELD_SHOT, WITHDRAW_SHOT],
    committedBroadcast: published.broadcast,
    committedSpendProve: published.spend_prove,
  }),
);
await context.close();
if (published.broadcast !== false || published.spend_prove !== "KEYS_MISSING") {
  process.exit(1);
}
if (!/^0x[0-9a-fA-F]{64}$/.test(withdrawStatus)) {
  process.exit(1);
}
