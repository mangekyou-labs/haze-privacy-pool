/** Headed MetaMask walk for operator-owned Groth16 withdraw. Not T7.4. Does not write fuji-v1.json. */

import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { bootstrap, MetaMaskWallet } from "@tenkeylabs/dappwright";
import { LOCAL_TEST_SEED, planDappwrightBootstrap } from "./dappwright-bootstrap.mjs";
import { loadPrivateKey } from "./fuji-live-deploy.mjs";

const ROOT = dirname(fileURLToPath(import.meta.url));
const COMMERCIAL = process.env.HAZE_COMMERCIAL_URL ?? "http://127.0.0.1:3013";
const FUJI_RPC = "https://api.avax-test.network/ext/bc/C/rpc";
const FUJI_NAME = "Avalanche Fuji C-Chain";
const SCREENSHOT = join(ROOT, "../output/playwright/dapp-fuji-withdraw.png");

function sidecar() {
  const path = join(ROOT, "../deployments/fuji-v1.live.json");
  if (!existsSync(path)) {
    return null;
  }
  return JSON.parse(readFileSync(path, "utf8"));
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForStatus(page, timeoutMs = 1_200_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const text = (await page.locator("[data-live-status]").textContent()) ?? "";
    if (/^0x[0-9a-fA-F]{64}$/.test(text.trim()) || /FAILED|DENIED|MISSING|rejected/i.test(text)) {
      return text.trim();
    }
    await sleep(1000);
  }
  return (await page.locator("[data-live-status]").textContent())?.trim() ?? "";
}

const overlay = sidecar();
const plan = planDappwrightBootstrap({
  launch: true,
  live: true,
  sidecar: overlay,
  commercialUrl: COMMERCIAL,
});
if (!plan.ok) {
  console.error(JSON.stringify(plan));
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
  const names = /^(Confirm|Approve|Next|Sign)$/;
  while (Date.now() < deadline) {
    for (const popup of context.pages()) {
      const url = popup.url();
      if (url.startsWith(COMMERCIAL)) {
        continue;
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
async function openLiveWithdraw(reviewed = false) {
  const suffix = reviewed ? "&reviewed=1" : "";
  await page.goto(`${COMMERCIAL}/withdraw?live=1${suffix}`, { waitUntil: "domcontentloaded" });
}

await openLiveWithdraw();
const connect = page.locator('button[data-action="connect"]').first();
if (await connect.isVisible()) {
  await connect.click();
  await confirmAny("connect");
  await confirmAny("network-switch", 8_000);
  await page.waitForLoadState("domcontentloaded");
  await page.locator("[data-address]").waitFor({ timeout: 45_000 });
  await sleep(500);
}

await openLiveWithdraw(true);
const connected = await page.locator("[data-address]").getAttribute("data-address").catch(() => null);
console.error(JSON.stringify({ connected, url: page.url() }));
if (!connected || !/ed37fd0d6f0f69236e7472b36796e133d20ecc32/i.test(connected)) {
  console.error(JSON.stringify({ wrongAccount: connected }));
  await context.close();
  process.exit(1);
}

const review = page.getByRole("button", { name: "I understand — continue" });
if (await review.isVisible() && (await review.isEnabled())) {
  await Promise.all([
    page.waitForLoadState("domcontentloaded"),
    review.click(),
  ]);
}

const submit = page.locator('form[data-live="true"] button[data-action="run"]');
if (!(await submit.isVisible().catch(() => false))) {
  const title = await page.locator("h1").textContent().catch(() => "");
  const forbidden = await page.locator("[data-code]").allTextContents().catch(() => []);
  console.error(JSON.stringify({ missingForm: true, title, forbidden, url: page.url() }));
}
await submit.waitFor({ state: "visible", timeout: 15_000 });
if (!(await submit.isEnabled())) {
  const label = (await submit.textContent())?.trim();
  console.error(JSON.stringify({ blocked: label, url: page.url() }));
  process.exit(1);
}

const recipient = page.locator('input[name="recipient"]');
if (await recipient.isVisible().catch(() => false)) {
  await recipient.fill(connected);
}

await submit.click();
await confirmAny("typed-data", 1_200_000);
await confirmAny("withdraw", 120_000);

const status = await waitForStatus(page);
mkdirSync(dirname(SCREENSHOT), { recursive: true });
await page.screenshot({ path: SCREENSHOT, fullPage: true });
console.log(JSON.stringify({ status, connected, url: page.url(), screenshot: SCREENSHOT }));
await context.close();
if (!/^0x[0-9a-fA-F]{64}$/.test(status)) {
  process.exit(1);
}
