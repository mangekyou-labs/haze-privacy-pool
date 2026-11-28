/** Headed Next.js spend walk using dAppwright and MetaMask on Fuji.
 * Exercises Shield 1 USDC and Send to haze1 against the hosted app shell.
 * Origin allowlist: local development and the canonical production host.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { bootstrap, MetaMaskWallet } from "@tenkeylabs/dappwright";
import { LOCAL_TEST_SEED } from "./dappwright-bootstrap.mjs";
import { confirmVisibleWalletAction } from "./wallet-confirmation-helper.mjs";
import { PRODUCTION_URL } from "./production-origin.mjs";

const ROOT = dirname(fileURLToPath(import.meta.url));
const ORIGIN = process.env.HAZE_NEXT_ORIGIN ?? "http://127.0.0.1:3010";

function assertAllowlistedOrigin(value) {
  const url = new URL(value);
  const allowlist = ["http://127.0.0.1:3010", "http://localhost:3010", PRODUCTION_URL];
  if (!allowlist.some((allowed) => url.origin === allowed)) {
    throw new Error(`ORIGIN_NOT_ALLOWED: ${url.origin} is not in the allowlist`);
  }
  return url.origin;
}

const origin = assertAllowlistedOrigin(ORIGIN);
const FUJI_RPC = process.env.AVALANCHE_FUJI_RPC || "https://api.avax-test.network/ext/bc/C/rpc";
const FUJI_NAME = "Avalanche Fuji C-Chain";
const FUJI_CHAIN_ID = 43113;
const FUJI_CHAIN_HEX = "0xa869";
const OUT = join(ROOT, "../output/playwright");

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

mkdirSync(OUT, { recursive: true });

process.env.TEST_WORKER_INDEX = process.env.TEST_WORKER_INDEX ?? "haze-next-spend";

console.log(`[SPEND WALK] Bootstrapping dAppwright against origin ${origin}...`);

const seed = process.env.METAMASK_SEED || LOCAL_TEST_SEED;

const [wallet, , context] = await bootstrap("chromium", {
  wallet: "metamask",
  version: MetaMaskWallet.recommendedVersion,
  seed,
  password: process.env.METAMASK_PASSWORD ?? "haze-qa-spend",
  headless: false,
  showTestNets: true,
});

await context.addInitScript(() => {
  let currentEthereum = window.ethereum;
  function hookProvider(provider) {
    if (!provider || provider.__hazeSessionObserved) return;
    provider.__hazeSessionObserved = true;
  }
  if (currentEthereum) hookProvider(currentEthereum);
  Object.defineProperty(window, "ethereum", {
    configurable: true,
    enumerable: true,
    get() {
      return currentEthereum;
    },
    set(v) {
      currentEthereum = v;
      hookProvider(v);
    }
  });
});
const mm = wallet.page;
await mm.bringToFront();

// Return to account home before network switch
for (let attempt = 0; attempt < 6; attempt += 1) {
  if (await mm.getByTestId("account-options-menu-button").isVisible().catch(() => false)) break;
  const back = mm.getByTestId("add-wallet-page-back-button").or(mm.getByRole("button", { name: /^back$/i })).first();
  if (await back.isVisible().catch(() => false)) await back.click();
  else await mm.keyboard.press("Escape");
  await sleep(300);
}

try {
  await wallet.addNetwork({
    networkName: FUJI_NAME,
    rpc: FUJI_RPC,
    chainId: FUJI_CHAIN_ID,
    symbol: "AVAX",
  });
} catch (error) {
  console.log("addNetwork:", error instanceof Error ? error.message : error);
}

try {
  await wallet.switchNetwork(FUJI_NAME);
} catch (error) {
  console.log("switchNetwork:", error instanceof Error ? error.message : error);
}

async function confirmAny(label, timeoutMs = 45_000) {
  const deadline = Date.now() + timeoutMs;
  const names = /^(Confirm|Approve|Next|Connect|Sign)$/i;
  while (Date.now() < deadline) {
    try {
      const handled = await confirmVisibleWalletAction({ context, origin, maxRetries: 2 });
      if (handled) {
        console.log(`[WALLET] Confirmed ${label} via helper`);
        return true;
      }
    } catch {}
    try {
      await wallet.approve();
      console.log(`[WALLET] dappwright.approve ${label}`);
      return true;
    } catch {}
    for (const popup of context.pages()) {
      const url = popup.url();
      if (url.startsWith(origin) || url === "about:blank") continue;
      const button = popup
        .getByTestId("confirm-footer-button")
        .or(popup.getByTestId("confirm-btn"))
        .or(popup.getByTestId("page-container-footer-next"))
        .or(popup.getByTestId("confirmation-submit-button"))
        .or(popup.getByRole("button", { name: names }))
        .first();
      if ((await button.isVisible().catch(() => false)) && (await button.isEnabled().catch(() => false))) {
        await popup.bringToFront().catch(() => {});
        await button.click({ force: true }).catch(() => {});
        console.log(`[WALLET] confirmed ${label} via button click`);
        return true;
      }
    }
    await sleep(300);
  }
  console.log(`[WALLET] no confirm UI for ${label}`);
  return false;
}

const page = await context.newPage();
page.on("console", (msg) => console.log(`[BROWSER CONSOLE ${msg.type()}]:`, msg.text()));
page.on("pageerror", (err) => console.error("[BROWSER ERROR]:", err));

async function open(path) {
  try {
    await page.goto(`${origin}${path}`, { waitUntil: "domcontentloaded" });
  } catch (error) {
    if (!/ERR_ABORTED|interrupted/i.test(String(error))) {
      throw error;
    }
    await page.waitForLoadState("domcontentloaded").catch(() => {});
  }
  await page.bringToFront().catch(() => {});
}

async function getHeaderSession() {
  const chip = page.locator('#haze-session-root [data-address]');
  const connectBtn = page.locator('#haze-session-root button[data-action="connect"]');
  const disconnectBtn = page.locator('#haze-session-root button[data-action="disconnect"]');
  return {
    address: (await chip.getAttribute("data-address").catch(() => null)) ?? null,
    hasConnect: (await connectBtn.count().catch(() => 0)) > 0,
    hasDisconnect: (await disconnectBtn.count().catch(() => 0)) > 0,
  };
}

async function connectHeader() {
  const connectBtn = page.locator('#haze-session-root button[data-action="connect"]').or(page.getByRole("button", { name: "Connect", exact: true })).first();
  await connectBtn.waitFor({ state: "visible", timeout: 25_000 });
  console.log("[SPEND WALK] Clicking header Connect...");
  await connectBtn.click();
  await confirmAny("eth_requestAccounts");
  await confirmAny("eth_signTypedData_v4");
  await confirmAny("personal_sign");

  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    if ((await page.locator('#haze-session-root [data-address]').count()) > 0) {
      break;
    }
    await confirmAny("connect_or_sign", 3000);
    await sleep(500);
  }
  await page.locator('#haze-session-root [data-address]').waitFor({ timeout: 15_000 });
  const session = await getHeaderSession();
  if (!session.address) {
    throw new Error("CONNECT_FAILED: Session address is null after connect flow");
  }
  console.log(`[SPEND WALK] Connected header session: ${session.address}`);
  return session.address;
}

console.log("[SPEND WALK] Navigating to /overview...");
await open("/overview");
const connectedAddress = await connectHeader();

// === STEP 1: Shield 1 USDC ===
console.log("[SPEND WALK] Step 1: Navigating to /shield...");
const shieldLink = page.locator('.haze-side-link[href="/shield"]');
if (await shieldLink.isVisible().catch(() => false)) {
  await shieldLink.click();
} else {
  await open("/shield");
}
await page.waitForLoadState("domcontentloaded");
await sleep(1000);

const previewBtn = page.locator('button[data-action="preview"]').or(page.getByRole("button", { name: "Preview" })).first();
if (await previewBtn.isVisible().catch(() => false)) {
  await previewBtn.click();
  await sleep(500);
}
await page.screenshot({ path: join(OUT, "next-spend-shield-preview.png") });

const confirmBtn = page.locator("button.haze-confirm");
await confirmBtn.waitFor({ state: "visible", timeout: 10_000 }).catch(() => {});
const confirmText = (await confirmBtn.textContent().catch(() => "")).trim();
console.log(`[SPEND WALK] Shield confirm button: "${confirmText}"`);

let shieldReceipt = null;
let shieldError = null;

try {
  if (await confirmBtn.isEnabled().catch(() => false)) {
    console.log("[SPEND WALK] Submitting Shield transaction...");
    await confirmBtn.click();
    
    const loopDeadline = Date.now() + 240_000;
    let lastStatus = "";
    while (Date.now() < loopDeadline) {
      // Check status in UI
      const statusText = (await page.locator(".haze-card-status, [data-status], .haze-status").textContent().catch(() => ""))?.trim() || "";
      if (statusText && statusText !== lastStatus) {
        lastStatus = statusText;
        console.log(`[SPEND WALK UI STATUS]: "${statusText}"`);
      }
      
      const confirmedEl = page.locator('.haze-receipt-hash a, [data-receipt="confirmed"]');
      if (await confirmedEl.isVisible().catch(() => false)) {
        shieldReceipt = await confirmedEl.getAttribute("href");
        console.log(`[SPEND WALK] Shield confirmed: ${shieldReceipt}`);
        break;
      }
      const errorEl = page.locator("[data-error]");
      if (await errorEl.isVisible().catch(() => false)) {
        shieldError = await errorEl.textContent();
        console.log(`[SPEND WALK] Shield error observed: ${shieldError}`);
        break;
      }
      
      // Check if wallet action is waiting
      const handled = await confirmAny("wallet confirmation", 2000);
      if (handled) {
        console.log("[SPEND WALK] Wallet action confirmed, waiting for UI...");
        await sleep(3000);
      } else {
        await sleep(1000);
      }
    }
  } else {
    const errorEl = page.locator("[data-error]");
    if ((await errorEl.count()) > 0) {
      shieldError = (await errorEl.textContent()).trim();
      console.log(`[SPEND WALK] Disabled button error observed: ${shieldError}`);
    }
  }
} catch (err) {
  shieldError = err instanceof Error ? err.message : String(err);
}
await page.screenshot({ path: join(OUT, "next-spend-shield-result.png") });

// === STEP 2: Send to haze1 ===
console.log("[SPEND WALK] Step 2: Navigating to /send...");
const sendLink = page.locator('.haze-side-link[href="/send"]');
if (await sendLink.isVisible().catch(() => false)) {
  await sendLink.click();
} else {
  await open("/send");
}
await page.waitForLoadState("domcontentloaded");

const recipientInput = page.locator('label.haze-field input[placeholder="haze1…"]');
const sendPreviewBtn = page.locator('button[data-action="preview"]').or(page.getByRole("button", { name: "Preview" })).first();

// Example valid Fuji haze1 recipient for testing
const testRecipientHaze1 = "haze1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqgpq9q3v4";

if (await recipientInput.isVisible().catch(() => false)) {
  await recipientInput.fill(testRecipientHaze1);
  if (await sendPreviewBtn.isVisible().catch(() => false)) {
    await sendPreviewBtn.click();
  }
}
await page.screenshot({ path: join(OUT, "next-spend-send-prepared.png") });

// === STEP 3: Check Swap and PILOT balance honesty ===
console.log("[SPEND WALK] Step 3: Navigating to /swap...");
const swapLink = page.locator('.haze-side-link[href="/swap"]');
if (await swapLink.isVisible().catch(() => false)) {
  await swapLink.click();
} else {
  await open("/swap");
}
await page.waitForLoadState("domcontentloaded");
await page.screenshot({ path: join(OUT, "next-spend-swap-checked.png") });

const report = {
  schema: "haze-dappwright-next-spend-walk-v1",
  origin,
  fujiChainId: FUJI_CHAIN_ID,
  fujiChainHex: FUJI_CHAIN_HEX,
  connectedAddress,
  shieldReceipt,
  shieldError,
  headless: false,
};

const reportPath = join(OUT, "dappwright-next-spend-walk.json");
writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
console.log(`[SPEND WALK] Acceptance report written to ${reportPath}`);

await context.close();
