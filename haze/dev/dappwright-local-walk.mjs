/** Headed local MetaMask walk. Anvil seed only. Does not read PRIVATE_KEY. Does not write fuji-v1. */

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { bootstrap, MetaMaskWallet } from "@tenkeylabs/dappwright";
import { LOCAL_TEST_SEED, planDappwrightBootstrap } from "./dappwright-bootstrap.mjs";

const ROOT = dirname(fileURLToPath(import.meta.url));
const COMMERCIAL = process.env.HAZE_COMMERCIAL_URL ?? "http://127.0.0.1:3012";
const RPC = process.env.AVALANCHE_RPC_URL ?? "http://127.0.0.1:8546";
const CHAIN_ID = Number(process.env.AVALANCHE_CHAIN_ID ?? 31337);
const NETWORK = process.env.AVALANCHE_NETWORK_NAME ?? "Anvil";
const OUT = join(ROOT, "../output/playwright");

const POOL = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const ADMIN = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
// Published Anvil HD key for index 1. Not process.env.PRIVATE_KEY.
const ANVIL_ADMIN_PK = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

const plan = planDappwrightBootstrap({
  launch: true,
  chainId: CHAIN_ID,
  commercialUrl: COMMERCIAL,
});
if (!plan.ok) {
  console.error(JSON.stringify(plan));
  process.exit(1);
}

process.env.TEST_WORKER_INDEX = process.env.TEST_WORKER_INDEX ?? "haze-local";

const [wallet, , context] = await bootstrap("chromium", {
  wallet: "metamask",
  version: MetaMaskWallet.recommendedVersion,
  seed: LOCAL_TEST_SEED,
  password: process.env.METAMASK_PASSWORD ?? "haze-local-qa",
  headless: false,
  showTestNets: true,
});

async function confirmAny(label, timeoutMs = 45_000) {
  const deadline = Date.now() + timeoutMs;
  const names = /^(Confirm|Approve|Next|Connect|Sign)$/i;
  while (Date.now() < deadline) {
    try {
      await wallet.approve();
      console.error(`dappwright.approve ${label}`);
      return true;
    } catch {
      // fall through to raw popup buttons
    }
    for (const popup of context.pages()) {
      const url = popup.url();
      if (url.startsWith(COMMERCIAL) || url === "about:blank") {
        continue;
      }
      const button = popup
        .getByTestId("confirm-footer-button")
        .or(popup.getByTestId("confirm-btn"))
        .or(popup.getByTestId("page-container-footer-next"))
        .or(popup.getByTestId("confirmation-submit-button"))
        .or(popup.getByRole("button", { name: names }))
        .first();
      if ((await button.isVisible().catch(() => false)) && (await button.isEnabled().catch(() => false))) {
        await popup.bringToFront();
        await button.click();
        console.error(`confirmed ${label} via ${url.slice(0, 80)}`);
        return true;
      }
    }
    await sleep(250);
  }
  console.error(`no confirm UI for ${label}`);
  return false;
}

try {
  await wallet.addNetwork({
    networkName: NETWORK,
    rpc: RPC,
    chainId: CHAIN_ID,
    symbol: "ETH",
  });
} catch (error) {
  console.error("addNetwork:", error instanceof Error ? error.message : error);
}

try {
  await wallet.switchNetwork(NETWORK);
} catch (error) {
  console.error("switchNetwork:", error instanceof Error ? error.message : error);
}

const page = await context.newPage();
mkdirSync(OUT, { recursive: true });

async function open(path) {
  try {
    await page.goto(`${COMMERCIAL}${path}`, { waitUntil: "domcontentloaded" });
  } catch (error) {
    if (!/ERR_ABORTED|interrupted/i.test(String(error))) {
      throw error;
    }
    await page.waitForLoadState("domcontentloaded").catch(() => {});
  }
}

async function session() {
  return {
    address: await page.locator("[data-address]").getAttribute("data-address").catch(() => null),
    role: await page.locator("[data-role]").getAttribute("data-role").catch(() => null),
    url: page.url(),
  };
}

async function connect(expected) {
  await open("/swap");
  const connectBtn = page.locator('button[data-action="connect"]').first();
  if (await connectBtn.isVisible().catch(() => false)) {
    await connectBtn.click();
    await confirmAny("connect");
    await page.locator("[data-address]").waitFor({ timeout: 45_000 });
  }
  const current = await session();
  current.expected = expected;
  current.matched = !expected || current.address?.toLowerCase() === expected.toLowerCase();
  return current;
}

const pool = await connect(POOL);
await page.screenshot({ path: join(OUT, "dapp-pool-connected.png") });
writeFileSync(join(OUT, "dappwright-local-walk.json"), `${JSON.stringify({ pool }, null, 2)}\n`);
await open("/admin");
const poolAdmin = {
  code: await page.locator("[data-code='FORBIDDEN']").count(),
  copy: (await page.locator("[data-code='FORBIDDEN']").textContent().catch(() => "")).trim(),
  hasWorkspace: (await page.locator("[data-workspace='admin']").count()) > 0,
};
await page.screenshot({ path: join(OUT, "dapp-pool-admin-denied.png") });
writeFileSync(join(OUT, "dappwright-local-walk.json"), `${JSON.stringify({ pool, poolAdmin }, null, 2)}\n`);

try {
  await wallet.importPK(ANVIL_ADMIN_PK);
} catch (error) {
  console.error("importPK:", error instanceof Error ? error.message : error);
}

async function selectAdminAccount() {
  const mm = wallet.page;
  await mm.bringToFront();
  try {
    await mm.getByTestId("account-menu-icon").click({ timeout: 8_000 });
  } catch {
    // already open
  }
  await mm.screenshot({ path: join(OUT, "mm-account-menu.png") });
  const cells = mm.locator(
    '[data-testid="multichain-account-cell"], [data-testid="account-list-item"], [data-testid="account-menu-icon"] ~ * [role="button"]',
  );
  const count = await cells.count();
  console.error(`account cells: ${count}`);
  if (count > 1) {
    await cells.nth(1).click();
    return;
  }
  const candidate = mm.getByText(/Account 2|0x7099|70997970/i).first();
  if (await candidate.isVisible().catch(() => false)) {
    await candidate.click();
  }
  await mm.keyboard.press("Escape");
}

await selectAdminAccount();
await open("/swap");
const disconnect = page.locator('button[data-action="disconnect"]').first();
if (await disconnect.isVisible().catch(() => false)) {
  await disconnect.click();
  await page.locator('button[data-action="connect"]').first().waitFor({ timeout: 20_000 });
}
const admin = await connect(ADMIN);
await open("/admin");
const adminOk = {
  title: (await page.locator("h1").textContent())?.trim(),
  hasWorkspace: (await page.locator("[data-workspace='admin']").count()) > 0,
  forbidden: await page.locator("[data-code='FORBIDDEN']").count(),
};
await page.screenshot({ path: join(OUT, "dapp-admin-connected.png") });

const report = {
  pool,
  poolAdmin,
  admin,
  adminOk,
  fujiUntouched: true,
};
writeFileSync(join(OUT, "dappwright-local-walk.json"), `${JSON.stringify(report, null, 2)}\n`);
console.log(JSON.stringify(report, null, 2));

const ok =
  pool.address?.toLowerCase() === POOL.toLowerCase() &&
  pool.role === "pool-user" &&
  poolAdmin.code > 0 &&
  /connected wallet/i.test(poolAdmin.copy) &&
  !poolAdmin.hasWorkspace &&
  admin.address?.toLowerCase() === ADMIN.toLowerCase() &&
  admin.role === "application-admin" &&
  adminOk.hasWorkspace &&
  adminOk.forbidden === 0;

await context.close();
process.exit(ok ? 0 : 1);
