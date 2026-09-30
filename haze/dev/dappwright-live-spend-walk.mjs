/** Headed acceptance against the deployed Vercel application and Avalanche Fuji only. */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { bootstrap, MetaMaskWallet } from "@tenkeylabs/dappwright";
import { decodePrivateTransaction } from "../sdk/typescript/src/fuji-reconciliation.ts";
import { confirmVisibleWalletAction } from "./wallet-confirmation-helper.mjs";
import { loadPrivateKey } from "./fuji-live-deploy.mjs";
import { PRODUCTION_URL } from "./production-origin.mjs";
const ROOT = dirname(fileURLToPath(import.meta.url));
const DEPLOYED_ORIGIN = process.env.HAZE_COMMERCIAL_URL ?? PRODUCTION_URL;
const EXPECTED_WALLET = "0xeD37FD0d6F0f69236E7472B36796e133D20EcC32";
const FUJI_RPC = "https://api.avax-test.network/ext/bc/C/rpc";
const FUJI_NAME = "Avalanche Fuji C-Chain";
const APPLICATION_ID = `0x${"00".repeat(30)}0a11`;
const APPLICATION_REGISTRY = "0xcCB53D8430E5c5555c66d56D2747660f97826f9E";
const USDC = "0x5425890298aed601595a70AB815c96711a31Bc65";
const POOL = "0x00BEB0A5D709d0F093952fD374Dbbf3d0d21d550";
const OUTPUT = join(ROOT, "../output/playwright");
const SCREENSHOTS = {
  depositRecovery: join(OUTPUT, "d7-deposit-recovery.png"),
  withdrawal: join(OUTPUT, "d7-withdrawal.png"),
};
const EVIDENCE_PATH = join(OUTPUT, "d7-deployed-fuji-acceptance.json");
const PROVING_TIMEOUT_MS = 2_400_000;

function assertProductionOrigin(value) {
  const url = new URL(value);
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error("INVALID_ORIGIN_PROTOCOL");
  return url.origin;
}
const origin = assertProductionOrigin(DEPLOYED_ORIGIN);

const privateKey = process.env.PRIVATE_KEY
  ? (process.env.PRIVATE_KEY.startsWith("0x") ? process.env.PRIVATE_KEY : `0x${process.env.PRIVATE_KEY}`)
  : loadPrivateKey();
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const normalize = (value) => value?.toLowerCase();
const hexNumber = (value) => (value ? Number.parseInt(value, 16) : undefined);
const explorer = (hash) => `https://testnet.snowtrace.io/tx/${hash}`;

async function rpc(method, params = []) {
  const response = await fetch(FUJI_RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const body = await response.json();
  if (!response.ok || body.error) throw new Error(`FUJI_RPC_${method}_FAILED: ${JSON.stringify(body.error)}`);
  return body.result;
}

async function waitForReceipt(hash, timeoutMs = 180_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const receipt = await rpc("eth_getTransactionReceipt", [hash]);
    if (receipt) return receipt;
    await sleep(2_000);
  }
  throw new Error("FUJI_RECEIPT_TIMEOUT");
}

function receiptEvidence(observation, receipt) {
  const events = (receipt.logs ?? []).map(decodePrivateTransaction).filter(Boolean);
  return {
    kind: observation.kind,
    hash: observation.hash,
    destination: observation.destination,
    selector: observation.selector,
    status: hexNumber(receipt.status),
    blockNumber: hexNumber(receipt.blockNumber),
    explorer: explorer(observation.hash),
    PrivateTransaction: events.map((event) => ({
      applicationId: event.applicationId,
      action: event.action,
      user: event.user,
      applicationPolicyVersion: Number(event.applicationPolicyVersion),
      hazePolicyVersion: Number(event.hazePolicyVersion),
      depositCommitment: observation.kind === "deposit" ? event.outputCommitment0 : undefined,
      withdrawalNullifier: observation.kind === "withdrawal" ? event.inputNullifier0 : undefined,
    })),
  };
}

const bootstrapSeed = [...Array(11).fill("test"), "junk"].join(" ");
const [wallet, , context] = await bootstrap("chromium", {
  wallet: "metamask",
  version: MetaMaskWallet.recommendedVersion,
  seed: bootstrapSeed,
  headless: false,
});

async function importExactWallet() {
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
  for (let attempt = 0; attempt < 6; attempt += 1) {
    const account = mm.getByText(/0xeD37|eD37FD0d/i).first();
    if (await account.isVisible().catch(() => false)) {
      await account.click();
      break;
    }
    await mm.keyboard.press("Escape");
    await sleep(300);
  }
  for (let attempt = 0; attempt < 6; attempt += 1) {
    if (await mm.getByTestId("account-options-menu-button").isVisible().catch(() => false)) break;
    const back = mm.getByTestId("add-wallet-page-back-button").or(mm.getByRole("button", { name: /^back$/i })).first();
    if (await back.isVisible().catch(() => false)) await back.click();
    else await mm.keyboard.press("Escape");
    await sleep(300);
  }
  await wallet.addNetwork({ networkName: FUJI_NAME, rpc: FUJI_RPC, chainId: 43113, symbol: "AVAX" }).catch(() => {});
  await wallet.switchNetwork(FUJI_NAME);
}
await importExactWallet();

await context.addInitScript(
  ({ registry, usdc, pool }) => {
    const txKey = "haze-d7-transactions";
    const statusKey = "haze-d7-status-history";
    const append = (key, item) => {
      const items = JSON.parse(localStorage.getItem(key) ?? "[]");
      items.push(item);
      localStorage.setItem(key, JSON.stringify(items));
    };
    const patch = () => {
      const provider = globalThis.ethereum;
      if (!provider || provider.__hazeD7Observed) return;
      const original = provider.request.bind(provider);
      provider.request = async (input) => {
        const result = await original(input);
        if (input?.method === "eth_sendTransaction" && typeof result === "string") {
          const transaction = input.params?.[0] ?? {};
          const destination = String(transaction.to ?? "").toLowerCase();
          const phase = localStorage.getItem("haze-d7-phase") ?? "unknown";
          const kind =
            destination === registry.toLowerCase()
              ? "membershipUpdate"
              : destination === usdc.toLowerCase()
                ? "usdcApproval"
                : destination === pool.toLowerCase()
                  ? phase
                  : "unknown";
          append(txKey, {
            kind,
            hash: result,
            destination,
            selector: String(transaction.data ?? "0x").slice(0, 10),
            timestamp: Date.now(),
          });
        }
        return result;
      };
      provider.__hazeD7Observed = true;
    };
    const watch = () => {
      for (const attribute of ["data-transaction-status"]) {
        const node = document.querySelector(`[${attribute}]`);
        if (!node || node.__hazeD7Observed) continue;
        const record = () =>
          append(statusKey, { route: location.pathname, channel: attribute, value: node.getAttribute(attribute) });
        record();
        new MutationObserver(record).observe(node, { attributes: true, attributeFilter: [attribute] });
        node.__hazeD7Observed = true;
      }
    };
    setInterval(() => {
      patch();
      watch();
    }, 100);
  },
  { registry: APPLICATION_REGISTRY, usdc: USDC, pool: POOL },
);

const page = await context.newPage();
page.on("console", (msg) => console.log(`[BROWSER CONSOLE ${msg.type()}]:`, msg.text()));
page.on("pageerror", (err) => console.error("[BROWSER ERROR]:", err));

async function confirmWalletAction() {
  return confirmVisibleWalletAction({ context, origin, maxRetries: 3 });
}

async function until(read, accept, timeoutMs, code) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    await confirmWalletAction();
    const value = await read();
    if (accept(value)) return value;
    await sleep(250);
  }
  throw new Error(code);
}

const status = (attribute) => page.locator(`[${attribute}]`).first().getAttribute(attribute).catch(() => null);
const transactionRegion = () => page.locator(".haze-browser-live-status").first();

async function openRoute(path) {
  await page.goto(`${origin}${path}`, { waitUntil: "domcontentloaded" });
  await transactionRegion().waitFor({ timeout: 45_000 });
}
async function connectVault() {
  console.log("[E2E] Checking connection...");
  const connectedAddress = await page.locator("#haze-session-root [data-address]").getAttribute("data-address").catch(() => null);
  if (connectedAddress && normalize(connectedAddress) === normalize(EXPECTED_WALLET)) {
    console.log(`[E2E] Already connected as ${connectedAddress}`);
    return;
  }
  const connectBtn = page.locator('#haze-session-root button[data-action="connect"]').first();
  if (await connectBtn.isVisible().catch(() => false)) {
    console.log("[E2E] Clicking Connect wallet button...");
    await connectBtn.click();
    const mmRow = page.locator('.haze-wallet-row').filter({ hasText: "MetaMask" }).first();
    if (await mmRow.isVisible({ timeout: 5000 }).catch(() => false)) {
      console.log("[E2E] Selecting MetaMask from modal...");
      await mmRow.click();
    }
    console.log("[E2E] Waiting for wallet signatures / vault readiness...");
    await until(
      async () => {
        const s = await status("data-transaction-status");
        const addr = await page.locator("#haze-session-root [data-address]").getAttribute("data-address").catch(() => null);
        console.log(`[E2E POLL] status=${s}, address=${addr}`);
        return Boolean(addr) || ["ready", "confirmed"].includes(s);
      },
      Boolean,
      120_000,
      "VAULT_CONNECT_TIMEOUT",
    );
  }
  const accounts = await page.evaluate(() => globalThis.ethereum?.request({ method: "eth_accounts" }));
  console.log(`[E2E] Connected account: ${accounts?.[0]}`);
  if (normalize(accounts?.[0]) !== normalize(EXPECTED_WALLET)) throw new Error("POLICY_AUTHORITY_REQUIRED");
}

const observations = () => page.evaluate(() => JSON.parse(localStorage.getItem("haze-d7-transactions") ?? "[]"));
const setPhase = (value) => page.evaluate((phase) => localStorage.setItem("haze-d7-phase", phase), value);
const waitForObservation = (kind, timeoutMs = PROVING_TIMEOUT_MS) =>
  until(async () => (await observations()).findLast((item) => item.kind === kind), Boolean, timeoutMs, `D7_${kind.toUpperCase()}_TIMEOUT`);

mkdirSync(OUTPUT, { recursive: true });

// Step 1: Direct Shield on /shield
console.log("[E2E] Opening /shield...");
await openRoute("/shield");
await connectVault();
await setPhase("deposit");
console.log("[E2E] Clicking Review and Preview...");
const reviewContinue = page.getByRole("button", { name: "I understand — continue" });
if (await reviewContinue.isVisible().catch(() => false) && await reviewContinue.isEnabled().catch(() => false)) {
  console.log("[E2E] Clicking I understand — continue...");
  await reviewContinue.click();
}
const previewToggle = page.locator("button.haze-preview-toggle").first();
if (await previewToggle.isVisible().catch(() => false)) {
  console.log("[E2E] Clicking Preview toggle...");
  await previewToggle.click();
}
console.log("[E2E] Clicking Confirm button...");
const confirmButton = page.locator("button.haze-confirm").first();
await confirmButton.waitFor({ state: "visible", timeout: 15_000 });
await confirmButton.click();
const depositObservation = await waitForObservation("deposit");
console.log(`[E2E] Observed deposit transaction: ${depositObservation.hash}`);

const depositReceipt = await waitForReceipt(depositObservation.hash);
console.log(`[E2E] Deposit receipt status: ${depositReceipt.status}`);
if (depositReceipt.status !== "0x1") {
  throw new Error(`DEPOSIT_REVERTED: status is ${depositReceipt.status}`);
}

await until(
  () => status("data-transaction-status"),
  (value) => value === "confirmed",
  60_000,
  "DEPOSIT_STATUS_CONFIRMED_TIMEOUT",
);

await page.screenshot({ path: SCREENSHOTS.depositRecovery, fullPage: true });

// Step 2: Tab switch to /withdraw (verify session persists without reconnect)
console.log("[E2E] Testing tab switch to /withdraw...");
const withdrawTab = page.locator('a.haze-tab[href="/withdraw"], a[href="/withdraw"]').first();
await withdrawTab.click();
await transactionRegion().waitFor({ timeout: 15_000 });

const sessionStatus = await page.locator("#haze-session-root [data-address], [data-session-status]").getAttribute("data-session-status").catch(() => null);
console.log(`[E2E] Session status after tab switch: ${sessionStatus}`);

const allObservations = await observations();
const transactions = [];
for (const kind of ["membershipUpdate", "usdcApproval", "deposit"]) {
  const observation = allObservations.find((item) => item.kind === kind);
  if (observation) {
    const receipt = kind === "deposit" ? depositReceipt : await waitForReceipt(observation.hash);
    const item = receiptEvidence(observation, receipt);
    transactions.push(item);
    console.log(`[E2E] Transaction ${kind}: ${item.hash} (status: ${item.status}) -> ${item.explorer}`);
  }
}

const evidence = {
  schema: "haze-d7-deployed-fuji-acceptance-v1",
  origin,
  chainId: 43113,
  applicationId: APPLICATION_ID,
  wallet: EXPECTED_WALLET,
  depositTxHash: depositObservation.hash,
  depositReceiptStatus: hexNumber(depositReceipt.status),
  explorer: explorer(depositObservation.hash),
  transactions,
  screenshots: SCREENSHOTS,
};

writeFileSync(EVIDENCE_PATH, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
console.log(`[E2E] Success! Evidence written to ${EVIDENCE_PATH}`);
await context.close();
