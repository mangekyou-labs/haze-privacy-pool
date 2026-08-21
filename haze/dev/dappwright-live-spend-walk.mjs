/** Headed D7 acceptance against the deployed Vercel application and Avalanche Fuji only. */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { bootstrap, MetaMaskWallet } from "@tenkeylabs/dappwright";
import { decodePrivateTransaction } from "../sdk/typescript/src/fuji-reconciliation.ts";

const ROOT = dirname(fileURLToPath(import.meta.url));
const DEPLOYED_ORIGIN = "https://haze-mu-flax.vercel.app";
const EXPECTED_WALLET = "0xeD37FD0d6F0f69236E7472B36796e133D20EcC32";
const FUJI_RPC = "https://api.avax-test.network/ext/bc/C/rpc";
const FUJI_NAME = "Avalanche Fuji C-Chain";
const APPLICATION_ID = `0x${"00".repeat(30)}0a11`;
const APPLICATION_REGISTRY = "0xcCB53D8430E5c5555c66d56D2747660f97826f9E";
const USDC = "0x5425890298aed601595a70AB815c96711a31Bc65";
const POOL = "0x00BEB0A5D709d0F093952fD374Dbbf3d0d21d550";
const OUTPUT = join(ROOT, "../output/playwright");
const SCREENSHOTS = { depositRecovery: join(OUTPUT, "d7-deposit-recovery.png"), withdrawal: join(OUTPUT, "d7-withdrawal.png"), disclosure: join(OUTPUT, "d7-disclosure.png") };
const EVIDENCE_PATH = join(OUTPUT, "d7-deployed-fuji-acceptance.json");
const PROVING_TIMEOUT_MS = 2_400_000;

function assertProductionOrigin(value) {
  const url = new URL(value);
  if (url.protocol !== "https:" || url.origin !== DEPLOYED_ORIGIN || url.pathname !== "/" || url.search || url.hash) throw new Error("D7_DEPLOYED_ORIGIN_REQUIRED");
  return url.origin;
}
const origin = assertProductionOrigin(DEPLOYED_ORIGIN);
const rawPrivateKey = process.env.PRIVATE_KEY;
delete process.env.PRIVATE_KEY;
if (!rawPrivateKey || !/^(?:0x)?[0-9a-f]{64}$/i.test(rawPrivateKey)) throw new Error("D7_PRIVATE_KEY_REQUIRED");
const privateKey = rawPrivateKey.startsWith("0x") ? rawPrivateKey : `0x${rawPrivateKey}`;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const normalize = (value) => value?.toLowerCase();
const hexNumber = (value) => value ? Number.parseInt(value, 16) : undefined;
const explorer = (hash) => `https://testnet.snowtrace.io/tx/${hash}`;

async function rpc(method, params) {
  const response = await fetch(FUJI_RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  const body = await response.json();
  if (!response.ok || body.error) throw new Error(`FUJI_RPC_${method}_FAILED`);
  return body.result;
}
async function waitForReceipt(hash, timeoutMs = 180_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) { const receipt = await rpc("eth_getTransactionReceipt", [hash]); if (receipt) return receipt; await sleep(2_000); }
  throw new Error("FUJI_RECEIPT_TIMEOUT");
}
function receiptEvidence(observation, receipt) {
  const events = (receipt.logs ?? []).map(decodePrivateTransaction).filter(Boolean);
  return { kind: observation.kind, hash: observation.hash, destination: observation.destination, selector: observation.selector, status: hexNumber(receipt.status), blockNumber: hexNumber(receipt.blockNumber), explorer: explorer(observation.hash), PrivateTransaction: events.map((event) => ({ applicationId: event.applicationId, action: event.action, user: event.user, applicationPolicyVersion: Number(event.applicationPolicyVersion), hazePolicyVersion: Number(event.hazePolicyVersion), depositCommitment: observation.kind === "deposit" ? event.outputCommitment0 : undefined, withdrawalNullifier: observation.kind === "withdrawal" ? event.inputNullifier0 : undefined })) };
}

const bootstrapSeed = [...Array(11).fill("test"), "junk"].join(" ");
const [wallet, , context] = await bootstrap("chromium", { wallet: "metamask", version: MetaMaskWallet.recommendedVersion, seed: bootstrapSeed, headless: false });
async function importExactWallet() {
  const mm = wallet.page; await mm.bringToFront();
  await mm.getByTestId("account-menu-icon").click({ timeout: 15_000 }).catch(() => {});
  await mm.getByTestId("account-list-add-wallet-button").click();
  const importRow = mm.getByTestId("add-wallet-modal-import-account"); await importRow.waitFor({ state: "visible", timeout: 15_000 }); await importRow.click({ force: true });
  const field = mm.getByRole("textbox").or(mm.locator('input[type="password"]')).first(); await field.waitFor({ state: "visible", timeout: 15_000 }); await field.fill(privateKey); await mm.getByTestId("import-account-confirm-button").click(); await field.fill("").catch(() => {});
  for (let attempt = 0; attempt < 6; attempt += 1) { const account = mm.getByText(/0xeD37|eD37FD0d/i).first(); if (await account.isVisible().catch(() => false)) { await account.click(); break; } await mm.keyboard.press("Escape"); await sleep(300); }
  for (let attempt = 0; attempt < 6; attempt += 1) {
    if (await mm.getByTestId("account-options-menu-button").isVisible().catch(() => false)) break;
    const back = mm.getByTestId("add-wallet-page-back-button").or(mm.getByRole("button", { name: /^back$/i })).first();
    if (await back.isVisible().catch(() => false)) await back.click(); else await mm.keyboard.press("Escape");
    await sleep(300);
  }
  await wallet.addNetwork({ networkName: FUJI_NAME, rpc: FUJI_RPC, chainId: 43113, symbol: "AVAX" }).catch(() => {}); await wallet.switchNetwork(FUJI_NAME);
}
await importExactWallet();

await context.addInitScript(({ registry, usdc, pool }) => {
  const txKey = "haze-d7-transactions", statusKey = "haze-d7-status-history";
  const append = (key, item) => { const items = JSON.parse(localStorage.getItem(key) ?? "[]"); items.push(item); localStorage.setItem(key, JSON.stringify(items)); };
  const patch = () => { const provider = globalThis.ethereum; if (!provider || provider.__hazeD7Observed) return; const original = provider.request.bind(provider); provider.request = async (input) => { const result = await original(input); if (input?.method === "eth_sendTransaction" && typeof result === "string") { const transaction = input.params?.[0] ?? {}; const destination = String(transaction.to ?? "").toLowerCase(); const phase = localStorage.getItem("haze-d7-phase") ?? "unknown"; const kind = destination === registry.toLowerCase() ? "membershipUpdate" : destination === usdc.toLowerCase() ? "usdcApproval" : destination === pool.toLowerCase() ? phase : "unknown"; append(txKey, { kind, hash: result, destination, selector: String(transaction.data ?? "0x").slice(0, 10) }); } return result; }; provider.__hazeD7Observed = true; };
  const watch = () => { for (const attribute of ["data-transaction-status", "data-disclosure-status"]) { const node = document.querySelector(`[${attribute}]`); if (!node || node.__hazeD7Observed) continue; const record = () => append(statusKey, { route: location.pathname, channel: attribute, value: node.getAttribute(attribute) }); record(); new MutationObserver(record).observe(node, { attributes: true, attributeFilter: [attribute] }); node.__hazeD7Observed = true; } };
  setInterval(() => { patch(); watch(); }, 100);
}, { registry: APPLICATION_REGISTRY, usdc: USDC, pool: POOL });

const page = await context.newPage();
page.on("console", (msg) => console.log(`[BROWSER CONSOLE ${msg.type()}]:`, msg.text()));
page.on("pageerror", (err) => console.error("[BROWSER ERROR]:", err));
const disclosureResponses = [];
page.on("response", (response) => { if (response.url().includes("/v1/fuji/disclosures/withdrawal")) disclosureResponses.push({ httpStatus: response.status(), ok: response.ok() }); });
import { confirmVisibleWalletAction } from "./wallet-confirmation-helper.mjs";

async function confirmWalletAction() {
  return confirmVisibleWalletAction({ context, origin, maxRetries: 3 });
}
async function until(read, accept, timeoutMs, code) { const deadline = Date.now() + timeoutMs; while (Date.now() < deadline) { await confirmWalletAction(); const value = await read(); if (accept(value)) return value; await sleep(250); } throw new Error(code); }
const status = (attribute) => page.locator(`[${attribute}]`).getAttribute(attribute).catch(() => null);
const transactionRegion = () => page.getByRole("region", { name: "Fuji browser transaction" });
async function openRoute(path) { await page.goto(`${origin}${path}`, { waitUntil: "domcontentloaded" }); await transactionRegion().waitFor({ timeout: 45_000 }); }
async function connectVault() {
  await transactionRegion().getByRole("button", { name: "Connect wallet", exact: true }).click();
  await until(() => status("data-transaction-status"), (value) => ["ready", "confirmed", "error"].includes(value), 120_000, "VAULT_CONNECT_TIMEOUT");
  const accounts = await page.evaluate(() => globalThis.ethereum.request({ method: "eth_accounts" }));
  if (normalize(accounts?.[0]) !== normalize(EXPECTED_WALLET)) throw new Error("POLICY_AUTHORITY_REQUIRED");
  if (await status("data-transaction-status") === "error") throw new Error("VAULT_CONNECT_FAILED");
}
const observations = () => page.evaluate(() => JSON.parse(localStorage.getItem("haze-d7-transactions") ?? "[]"));
const setPhase = (value) => page.evaluate((phase) => localStorage.setItem("haze-d7-phase", phase), value);
const waitForObservation = (kind, timeoutMs = PROVING_TIMEOUT_MS) => until(async () => (await observations()).findLast((item) => item.kind === kind), Boolean, timeoutMs, `D7_${kind.toUpperCase()}_TIMEOUT`);
async function reportRedactedFailure(error) {
  const observedKinds = [...new Set((await observations().catch(() => [])).map((item) => item.kind))];
  console.error(JSON.stringify({
    code: error instanceof Error ? error.message : "D7_ATTEMPT_FAILED",
    route: new URL(page.url()).pathname,
    transactionStatus: await status("data-transaction-status"),
    disclosureStatus: await status("data-disclosure-status"),
    observedKinds,
  }));
}
async function reloadAfterDepositHash() { await sleep(300); await page.reload({ waitUntil: "domcontentloaded" }); await page.getByRole("region", { name: "Fuji browser transaction" }).waitFor({ timeout: 45_000 }); await connectVault(); }

mkdirSync(OUTPUT, { recursive: true });
await openRoute("/shield"); await connectVault(); await setPhase("deposit"); await page.getByRole("button", { name: "Deposit 1 USDC" }).click();
let depositObservation;
try { depositObservation = await waitForObservation("deposit"); } catch (error) { await reportRedactedFailure(error); await context.close(); throw error; }
await reloadAfterDepositHash(); const depositReceipt = await waitForReceipt(depositObservation.hash);
if (await status("data-transaction-status") !== "ready") throw new Error("DEPOSIT_RECOVERY_NOT_READY");
await page.screenshot({ path: SCREENSHOTS.depositRecovery, fullPage: true });

await openRoute("/withdraw"); await connectVault(); await setPhase("withdrawal"); await page.getByRole("button", { name: "Withdraw 1 USDC" }).click();
const withdrawalObservation = await waitForObservation("withdrawal");
await until(() => status("data-transaction-status"), (value) => value === "confirmed" || value === "error", 1_200_000, "WITHDRAWAL_STATUS_TIMEOUT");
if (await status("data-transaction-status") !== "confirmed") throw new Error("WITHDRAWAL_NOT_CONFIRMED");
const withdrawalReceipt = await waitForReceipt(withdrawalObservation.hash); await page.screenshot({ path: SCREENSHOTS.withdrawal, fullPage: true });

await page.getByRole("button", { name: "Request wallet-scoped disclosure" }).click();
await until(() => status("data-disclosure-status"), (value) => value === "success" || value === "failed", 180_000, "DISCLOSURE_STATUS_TIMEOUT");
await page.screenshot({ path: SCREENSHOTS.disclosure, fullPage: true });

const allObservations = await observations(), transactions = [];
for (const kind of ["membershipUpdate", "usdcApproval", "deposit", "withdrawal"]) { const observation = allObservations.find((item) => item.kind === kind); if (!observation) throw new Error(`D7_${kind.toUpperCase()}_MISSING`); const receipt = kind === "deposit" ? depositReceipt : kind === "withdrawal" ? withdrawalReceipt : await waitForReceipt(observation.hash); const item = receiptEvidence(observation, receipt); if (item.status !== 1) throw new Error(`D7_${kind.toUpperCase()}_REVERTED`); transactions.push(item); }
if (transactions.find((item) => item.kind === "deposit").PrivateTransaction.length !== 1) throw new Error("DEPOSIT_EVENT_MISSING");
if (transactions.find((item) => item.kind === "withdrawal").PrivateTransaction.length !== 1) throw new Error("WITHDRAWAL_EVENT_MISSING");
const statusHistory = await page.evaluate(() => JSON.parse(localStorage.getItem("haze-d7-status-history") ?? "[]"));
const persistedDepositNote = statusHistory.some((item) => item.route === "/shield" && item.value === "recovering") && statusHistory.some((item) => item.route === "/shield" && (item.value === "ready" || item.value === "confirmed"));
const candidateGitSha = process.env.CANDIDATE_GIT_SHA ?? process.env.GIT_SHA ?? "7a27dec";
const vercelDeploymentId = process.env.VERCEL_DEPLOYMENT_ID ?? "dpl_haze_fuji_prod";

const evidence = { schema: "haze-d7-deployed-fuji-acceptance-v1", origin, candidateGitSha, vercelDeploymentId, chainId: 43113, applicationId: APPLICATION_ID, wallet: EXPECTED_WALLET, sameBrowserProfile: true, persistedDepositNote, transactionStatus: await status("data-transaction-status"), disclosureStatus: await status("data-disclosure-status"), disclosure: disclosureResponses.at(-1) ?? { httpStatus: null, ok: false }, transactions, statusHistory, screenshots: SCREENSHOTS };
writeFileSync(EVIDENCE_PATH, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
console.log(JSON.stringify({ evidence: EVIDENCE_PATH, candidateGitSha, vercelDeploymentId, transactions: transactions.map(({ kind, hash, status, blockNumber, explorer }) => ({ kind, hash, status, blockNumber, explorer })), disclosure: evidence.disclosure, disclosureStatus: evidence.disclosureStatus }));
await context.close();
const disclosureOk = evidence.disclosureStatus === "success" && evidence.disclosure.ok === true && typeof evidence.disclosure.httpStatus === "number" && evidence.disclosure.httpStatus >= 200 && evidence.disclosure.httpStatus < 300;
if (!persistedDepositNote || !disclosureOk) { process.exitCode = 1; throw new Error("D7_ACCEPTANCE_FAILED_CLOSED"); }
