/**
 * D8 Dappwright SIWE Bootstrap for dedicated Fuji compliance auditor.
 * Connects MetaMask on Avalanche Fuji (43113), completes SIWE,
 * and saves authenticated Playwright storageState to a protected path.
 */
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { bootstrap, MetaMaskWallet } from "@tenkeylabs/dappwright";
import { confirmVisibleWalletAction } from "./wallet-confirmation-helper.mjs";
import { PRODUCTION_URL } from "./production-origin.mjs";

const ROOT = dirname(fileURLToPath(import.meta.url));
const DEPLOYED_ORIGIN = process.env.HAZE_DEPLOYED_ORIGIN || PRODUCTION_URL;
const FUJI_RPC = process.env.AVALANCHE_FUJI_RPC || "https://api.avax-test.network/ext/bc/C/rpc";
const FUJI_NAME = "Avalanche Fuji C-Chain";
const FUJI_CHAIN_ID = 43113;

const PLAYWRIGHT_DIR = join(ROOT, "../.playwright");
const SESSION_STATE_PATH = join(PLAYWRIGHT_DIR, "audit-session.json");
const BOOTSTRAP_METADATA_PATH = join(PLAYWRIGHT_DIR, "audit-bootstrap-meta.json");

export function assertProductionOrigin(value) {
  const url = new URL(value);
  if (url.protocol !== "https:" || !url.origin.includes("vercel.app") || url.search || url.hash) {
    if (!url.origin.includes("localhost") && !url.origin.includes("127.0.0.1")) {
      throw new Error(`D8_INVALID_ORIGIN: ${value}`);
    }
  }
  return url.origin;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const normalize = (value) => value?.toLowerCase();

async function rpc(method, params) {
  const response = await fetch(FUJI_RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const body = await response.json();
  if (!response.ok || body.error) throw new Error(`FUJI_RPC_${method}_FAILED: ${JSON.stringify(body.error)}`);
  return body.result;
}

export async function runAuditBootstrap(options = {}) {
  const origin = assertProductionOrigin(options.origin || DEPLOYED_ORIGIN);
  const rawPrivateKey = options.privateKey || process.env.HAZE_AUDITOR_PRIVATE_KEY;
  if (!rawPrivateKey || !/^(?:0x)?[0-9a-f]{64}$/i.test(rawPrivateKey)) {
    throw new Error("D8_AUDITOR_PRIVATE_KEY_REQUIRED");
  }
  const privateKey = rawPrivateKey.startsWith("0x") ? rawPrivateKey : `0x${rawPrivateKey}`;

  mkdirSync(PLAYWRIGHT_DIR, { recursive: true });

  const previousWorkerIndex = process.env.TEST_WORKER_INDEX;
  process.env.TEST_WORKER_INDEX = "haze-audit";

  const bootstrapSeed = [...Array(11).fill("test"), "junk"].join(" ");
  let wallet;
  let context;
  try {
    const bootstrapped = await bootstrap("chromium", {
      wallet: "metamask",
      version: MetaMaskWallet.recommendedVersion,
      seed: bootstrapSeed,
      headless: options.headless ?? false,
    });
    wallet = bootstrapped[0];
    context = bootstrapped[2];
  } finally {
    if (previousWorkerIndex === undefined) delete process.env.TEST_WORKER_INDEX;
    else process.env.TEST_WORKER_INDEX = previousWorkerIndex;
  }

  // Import dedicated auditor wallet into MetaMask
  const mm = wallet.page;
  await mm.bringToFront();
  await mm.getByTestId("account-menu-icon").click({ timeout: 15_000 }).catch(() => {});
  await mm.getByTestId("account-list-add-wallet-button").click();
  const importRow = mm.getByTestId("add-wallet-modal-import-account");
  await importRow.waitFor({ state: "visible", timeout: 15_000 });
  await importRow.click({ force: true });

  const field = mm.getByRole("textbox").or(mm.locator('input[type="password"]')).first();
  await field.waitFor({ state: "visible", timeout: 15_000 });
  await field.fill(privateKey);
  await mm.getByTestId("import-account-confirm-button").click();
  await field.fill("").catch(() => {});

  // Wait for account import
  for (let attempt = 0; attempt < 6; attempt += 1) {
    if (await mm.getByTestId("account-options-menu-button").isVisible().catch(() => false)) break;
    const back = mm
      .getByTestId("add-wallet-page-back-button")
      .or(mm.getByRole("button", { name: /^back$/i }))
      .first();
    if (await back.isVisible().catch(() => false)) await back.click();
    else await mm.keyboard.press("Escape");
    await sleep(300);
  }

  // Switch to Avalanche Fuji
  await wallet
    .addNetwork({
      networkName: FUJI_NAME,
      rpc: FUJI_RPC,
      chainId: FUJI_CHAIN_ID,
      symbol: "AVAX",
    })
    .catch(() => {});
  await wallet.switchNetwork(FUJI_NAME);

  const page = await context.newPage();
  page.on("console", (msg) => console.log(`[BOOTSTRAP BROWSER CONSOLE ${msg.type()}]:`, msg.text()));
  page.on("pageerror", (err) => console.error("[BOOTSTRAP BROWSER ERROR]:", err));

  // Navigate to /audit
  await page.goto(`${origin}/audit`, { waitUntil: "domcontentloaded" });
  await page.waitForSelector('#haze-audit-workstation-root, .haze-compliance-workstation', {
    timeout: 30_000,
  });

  // Query auditor wallet address from provider
  const accounts = await page.evaluate(() =>
    globalThis.ethereum?.request?.({ method: "eth_accounts" }) || Promise.resolve([]),
  );
  const auditorAddress = accounts[0];

  // Get initial transaction count before SIWE
  const txCountBefore = auditorAddress
    ? await rpc("eth_getTransactionCount", [auditorAddress, "latest"])
    : "0x0";

  await page.waitForSelector(
    '[data-session-status="unauthenticated"], [data-session-status="authenticated"]',
    { timeout: 45_000 },
  );

  const alreadyAuthenticated = await page
    .locator('[data-session-status="authenticated"]')
    .isVisible()
    .catch(() => false);

  if (!alreadyAuthenticated) {
    const siweButton = page.locator('button[data-action="connect-siwe"], button:has-text("Connect & Authenticate SIWE")');
    await siweButton.click();

    for (let i = 0; i < 5; i += 1) {
      await confirmVisibleWalletAction({ context, origin, maxRetries: 3 });
      await sleep(1000);
      const authenticated = await page
        .locator('[data-session-status="authenticated"], [data-action="logout"]')
        .isVisible()
        .catch(() => false);
      if (authenticated) break;
    }
  }

  await page.waitForSelector('[data-session-status="authenticated"], [data-action="logout"]', {
    timeout: 45_000,
  });

  // Check transaction count after SIWE (must be unchanged, SIWE is off-chain)
  const txCountAfter = auditorAddress
    ? await rpc("eth_getTransactionCount", [auditorAddress, "latest"])
    : "0x0";

  if (txCountBefore !== txCountAfter) {
    throw new Error("D8_AUDITOR_TX_COUNT_UNEXPECTEDLY_CHANGED");
  }

  // Save Playwright storage state (containing HttpOnly session cookie)
  await context.storageState({ path: SESSION_STATE_PATH });

  const metadata = {
    origin,
    auditorAddress,
    chainId: FUJI_CHAIN_ID,
    txCountBefore,
    txCountAfter,
    sessionStatePath: SESSION_STATE_PATH,
    timestamp: Date.now(),
  };
  writeFileSync(BOOTSTRAP_METADATA_PATH, JSON.stringify(metadata, null, 2), "utf8");

  await page.close();
  await context.close();

  return metadata;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  runAuditBootstrap()
    .then((meta) => {
      console.log("D8 Auditor SIWE Bootstrap successful:", meta);
      process.exit(0);
    })
    .catch((err) => {
      console.error("D8 Auditor SIWE Bootstrap failed:", err);
      process.exit(1);
    });
}
