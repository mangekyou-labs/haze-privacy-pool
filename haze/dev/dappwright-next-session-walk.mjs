/** Headed Next.js session walk using dAppwright and MetaMask on Fuji.
 * Uses LOCAL_TEST_SEED only. Does not read PRIVATE_KEY. Does not broadcast.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { bootstrap, MetaMaskWallet } from "@tenkeylabs/dappwright";
import { LOCAL_TEST_SEED } from "./dappwright-bootstrap.mjs";
import { confirmVisibleWalletAction } from "./wallet-confirmation-helper.mjs";

const ROOT = dirname(fileURLToPath(import.meta.url));
const ORIGIN = process.env.HAZE_NEXT_ORIGIN ?? "http://127.0.0.1:3010";
const FUJI_RPC = process.env.AVALANCHE_FUJI_RPC || "https://api.avax-test.network/ext/bc/C/rpc";
const FUJI_NAME = "Avalanche Fuji C-Chain";
const FUJI_CHAIN_ID = 43113;
const FUJI_CHAIN_HEX = "0xa869";
const OUT = join(ROOT, "../output/playwright");

const POOL_USER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const ADMIN_USER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
// Published Anvil HD key for index 1 only.
const ANVIL_ADMIN_PK = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

mkdirSync(OUT, { recursive: true });

process.env.TEST_WORKER_INDEX = process.env.TEST_WORKER_INDEX ?? "haze-next-session";

console.log(`[SESSION WALK] Bootstrapping dAppwright against origin ${ORIGIN}...`);

const [wallet, , context] = await bootstrap("chromium", {
  wallet: "metamask",
  version: MetaMaskWallet.recommendedVersion,
  seed: LOCAL_TEST_SEED,
  password: process.env.METAMASK_PASSWORD ?? "haze-qa-session",
  headless: false,
  showTestNets: true,
});

// Guard: prevent any broadcast and track signature requests
await context.addInitScript(() => {
  window.__hazeSignaturesRequested = window.__hazeSignaturesRequested || { typedData: 0, personalSign: 0 };
  let currentEthereum = window.ethereum;
  function hookProvider(provider) {
    if (!provider || provider.__hazeSessionObserved) return;
    const original = provider.request.bind(provider);
    provider.request = async (input) => {
      if (input?.method === "eth_sendTransaction") {
        throw new Error("BROADCAST_FORBIDDEN: eth_sendTransaction is forbidden in session walk");
      }
      if (input?.method === "eth_signTypedData_v4") {
        window.__hazeSignaturesRequested.typedData += 1;
      }
      if (input?.method === "personal_sign") {
        window.__hazeSignaturesRequested.personalSign += 1;
      }
      return original(input);
    };
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
      const handled = await confirmVisibleWalletAction({ context, origin: ORIGIN, maxRetries: 2 });
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
      if (url.startsWith(ORIGIN) || url === "about:blank") continue;
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
    await page.goto(`${ORIGIN}${path}`, { waitUntil: "domcontentloaded" });
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

async function connectHeader(expected) {
  const connectBtn = page.locator('#haze-session-root button[data-action="connect"]').or(page.getByRole("button", { name: "Connect", exact: true })).first();
  if (await connectBtn.isVisible().catch(() => false)) {
    console.log("[SESSION WALK] Clicking header Connect...");
    await connectBtn.click();
    // 1. eth_requestAccounts
    await confirmAny("eth_requestAccounts");
    // 2. eth_signTypedData_v4
    await confirmAny("eth_signTypedData_v4");
    // 3. personal_sign
    await confirmAny("personal_sign");
    await page.locator('#haze-session-root [data-address]').waitFor({ timeout: 45_000 });
  }
  const session = await getHeaderSession();
  console.log(`[SESSION WALK] Connected header session: ${session.address}`);
  return session;
}

// === STEP 1: Connect on /overview or /shield ===
console.log("[SESSION WALK] Step 1: Navigating to /overview...");
await open("/overview");
const initialSession = await getHeaderSession();
console.log("[SESSION WALK] Initial session on /overview:", initialSession);

const poolSession = await connectHeader(POOL_USER);
await page.screenshot({ path: join(OUT, "next-session-overview-connected.png") });

// Verify signature count right after initial connect: exactly 1 typed data and 1 personal sign
const initialSignatures = await page.evaluate(() => window.__hazeSignaturesRequested);
console.log("[SESSION WALK] Signatures after initial connect:", initialSignatures);

// === STEP 2: Walk full user-rail tabs without re-prompting signatures ===
const railRoutes = ["/shield", "/swap", "/send", "/withdraw", "/history", "/overview"];
for (const route of railRoutes) {
  console.log(`[SESSION WALK] Step 2: Navigating to ${route} via .haze-side-link...`);
  const link = page.locator(`.haze-side-link[href="${route}"]`);
  if (await link.isVisible().catch(() => false)) {
    await link.click();
  } else {
    await open(route);
  }
  await page.waitForLoadState("domcontentloaded");
  await sleep(300);
  const currentSession = await getHeaderSession();
  if (currentSession.address?.toLowerCase() !== POOL_USER.toLowerCase()) {
    throw new Error(`Session lost on ${route}! Found: ${currentSession.address}`);
  }
  if (currentSession.hasConnect) {
    throw new Error(`Connect button appeared on ${route} while connected!`);
  }
}

// Assert signature count did not increase (sign once per session invariant)
const finalRailSignatures = await page.evaluate(() => window.__hazeSignaturesRequested);
console.log("[SESSION WALK] Rail walk signature count:", finalRailSignatures);
const noExtraSignatures = finalRailSignatures.typedData === 1 && finalRailSignatures.personalSign === 1;
if (!noExtraSignatures) {
  throw new Error(`Extra signatures requested during tab navigation! Counts: ${JSON.stringify(finalRailSignatures)}`);
}
await page.screenshot({ path: join(OUT, "next-session-full-rail-persisted.png") });
// === STEP 3: Admin check for pool-user (FORBIDDEN, no role query parameter) ===
console.log("[SESSION WALK] Step 3: Navigating to /admin as pool-user (without role query)...");
await open("/admin");
const forbiddenCount = await page.locator("[data-code='FORBIDDEN']").count();
const forbiddenText = (await page.locator("[data-code='FORBIDDEN']").textContent().catch(() => "")).trim();
console.log(`[SESSION WALK] /admin forbidden banner: count=${forbiddenCount}, text="${forbiddenText}"`);
const adminWorkspaceCount = await page.locator("[data-workspace='admin'], .haze-admin").count();
await page.screenshot({ path: join(OUT, "next-session-admin-forbidden.png") });
if (forbiddenCount === 0 && adminWorkspaceCount > 0) {
  throw new Error("pool-user should not have admin access to /admin");
}

// === STEP 4: Account switch / mismatch check ===
console.log("[SESSION WALK] Step 4: Testing account switch...");

async function selectOrAddAccount2() {
  await mm.bringToFront();
  try {
    await mm.getByTestId("account-menu-icon").click({ timeout: 8_000 });
  } catch {}
  await sleep(500);

  const candidate = mm.getByText(/Account 2|0x7099/i).first();
  if (await candidate.isVisible().catch(() => false)) {
    await candidate.click();
  } else {
    const addBtn = mm.getByTestId("account-list-add-wallet-button").or(mm.getByText(/Add account|Add wallet/i)).first();
    if (await addBtn.isVisible().catch(() => false)) {
      await addBtn.click();
      await sleep(300);
      const newAcc = mm.getByTestId("add-wallet-modal-add-account-button").or(mm.getByText(/Add a new account/i)).first();
      if (await newAcc.isVisible().catch(() => false)) {
        await newAcc.click();
        await sleep(300);
        const createBtn = mm.getByTestId("add-account-create-button").or(mm.getByRole("button", { name: /create|add/i })).first();
        if (await createBtn.isVisible().catch(() => false)) {
          await createBtn.click();
        }
      }
    }
  }
  await mm.keyboard.press("Escape");
  await sleep(500);
}

await selectOrAddAccount2();
console.log("[SESSION WALK] Switched MetaMask to Account 2. Reloading /shield...");
await open("/shield");
const mismatchSession = await getHeaderSession();
console.log("[SESSION WALK] Session after switching account (should be disconnected or switchable):", mismatchSession);

// Connect as Account 2
const adminSession = await connectHeader(ADMIN_USER);
console.log("[SESSION WALK] Connected as Admin:", adminSession);
await open("/admin");
const adminForbidden = await page.locator("[data-code='FORBIDDEN']").count();
const adminWorkspace = await page.locator(".haze-admin, [data-workspace='admin']").count();
console.log(`[SESSION WALK] /admin as admin: forbidden=${adminForbidden}, workspace=${adminWorkspace}`);
await page.screenshot({ path: join(OUT, "next-session-admin-granted.png") });

const report = {
  schema: "haze-dappwright-next-session-walk-v1",
  origin: ORIGIN,
  fujiChainId: FUJI_CHAIN_ID,
  fujiChainHex: FUJI_CHAIN_HEX,
  poolUser: poolSession,
  railRoutesVisited: railRoutes,
  signaturesRequested: finalRailSignatures,
  noExtraSignatures,
  poolUserAdminForbidden: forbiddenCount > 0,
  adminUser: adminSession,
  adminWorkspaceVisible: adminWorkspace > 0,
  noBroadcastEnforced: true,
};

const reportPath = join(OUT, "dappwright-next-session-walk.json");
writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
console.log(`[SESSION WALK] Acceptance report written to ${reportPath}`);
console.log(JSON.stringify(report, null, 2));

await context.close();

const pass =
  poolSession.address?.toLowerCase() === POOL_USER.toLowerCase() &&
  noExtraSignatures &&
  report.noBroadcastEnforced;

process.exit(pass ? 0 : 1);
