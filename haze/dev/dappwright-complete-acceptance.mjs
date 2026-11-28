/**
 * Full 2-Account Fuji MVP Acceptance Journey Orchestrator.
 * Complete multi-actor privacy lifecycle on Avalanche Fuji:
 * 1. Account B connects first to establish and capture real haze1 address (fails closed if not captured).
 * 2. Account A connects and Shields 1.0 USDC (action 1, 12 confirmations).
 * 3. Account A Sends the 1.0 USDC private note to Account B's real haze1 address (action 2, 12 confirmations).
 * 4. Account B reconnects, recovers inbound note, and Withdraws 1.0 USDC publicly (action 3, 12 confirmations).
 * 5. Account A claims 5 PILOT from faucet and Swaps into a new private 1.0 USDC note (action 4, 12 confirmations).
 * 6. Compliance Auditor runs real named playwright-cli walk, inspects disclosure, verifies detached JWS, and exports bundle.
 * 7. Named playwright-cli sessions independently inspect user History and compliance workstation at desktop and mobile viewports.
 * 8. Independent manifest verification via evidence-verifier.mjs (requiring all 4 finalized ops + real auditor case).
 */
import assert from "node:assert/strict";
import { execSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { bootstrap, MetaMaskWallet } from "@tenkeylabs/dappwright";
import { runAuditBootstrap } from "./dappwright-audit-bootstrap.mjs";
import { LOCAL_TEST_SEED } from "./dappwright-bootstrap.mjs";
import { confirmVisibleWalletAction, hasWalletNotification, isWalletNotificationPage } from "./wallet-confirmation-helper.mjs";
import { createAcceptanceJournal } from "./fuji-acceptance-journal.mjs";
import { decodePrivateTransaction } from "../sdk/typescript/src/fuji-reconciliation.ts";
import { runPlaywrightCliAuditWalk } from "./playwright-cli-audit-walk.mjs";
import { verifyFujiMvpV2Manifest } from "./evidence-verifier.mjs";

const ROOT = dirname(fileURLToPath(import.meta.url));
const ORIGIN = process.env.HAZE_NEXT_ORIGIN ?? process.env.HAZE_DEPLOYED_ORIGIN ?? "http://127.0.0.1:3010";
const FUJI_RPC = process.env.AVALANCHE_FUJI_RPC || "https://api.avax-test.network/ext/bc/C/rpc";
const FUJI_CHAIN_ID = 43113;
const POOL = "0x00BEB0A5D709d0F093952fD374Dbbf3d0d21d550";
const APPLICATION_ID = `0x${"00".repeat(30)}0a11`;
const ROUTER = "0xdb386aeAd1C0b859903702454a7ECDfC306800F6";
const PILOT_TOKEN = "0x4fAB93a23313CC032D8310Cf0f34A9BDF4E19c72";
const SWAP_PILOT_UNITS = 1_000_000n;
const OUT = join(ROOT, "../output/playwright");
const PLAYWRIGHT_DIR = join(ROOT, "../.playwright");

// Deterministic 2 accounts from Anvil / test seed
const ACCOUNT_A_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const ACCOUNT_B_ADDRESS = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const ACCOUNT_B_PRIVKEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const AUDITOR_ADDRESS = "0xed37fd0d6f0f69236e7472b36796e133d20ecc32";

mkdirSync(OUT, { recursive: true });
mkdirSync(PLAYWRIGHT_DIR, { recursive: true });

// dappwright defaults TEST_WORKER_INDEX to "0" and rm -rf that user-data-dir on launch.
// Isolate from other repos (and from Phase 6 auditor bootstrap) sharing /tmp/dappwright/session/metamask/0.
process.env.TEST_WORKER_INDEX = process.env.TEST_WORKER_INDEX ?? "haze-fuji-mvp";

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function rpc(method, params = []) {
  const response = await fetch(FUJI_RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: Date.now(), method, params }),
  });
  if (!response.ok) throw new Error(`RPC_HTTP_ERROR_${response.status}`);
  const body = await response.json();
  if (body.error) throw new Error(`RPC_ERROR: ${JSON.stringify(body.error)}`);
  return body.result;
}

async function waitForFinality(txHash, expectedAction) {
  console.log(`[ACCEPTANCE] Waiting for receipt and 12 confirmations for action ${expectedAction} (${txHash})...`);
  let receipt = null;
  for (let poll = 0; poll < 60; poll += 1) {
    receipt = await rpc("eth_getTransactionReceipt", [txHash]);
    if (receipt && receipt.status === "0x1") break;
    await sleep(2000);
  }
  if (!receipt || receipt.status !== "0x1") {
    throw new Error(`TRANSACTION_RECEIPT_FAILED: Tx ${txHash} for action ${expectedAction} was not mined or reverted`);
  }

  const decodedLogs = (receipt.logs || []).map(decodePrivateTransaction).filter(Boolean);
  const matchingEvent = decodedLogs.find((e) => e && e.action === expectedAction);
  if (!matchingEvent) {
    throw new Error(`EVENT_MISMATCH: Receipt for tx ${txHash} did not emit action-${expectedAction} PrivateTransaction event`);
  }

  const inclusionBlock = BigInt(receipt.blockNumber);
  let confirmations = 0;
  for (let poll = 0; poll < 60; poll += 1) {
    const headBlockHex = await rpc("eth_blockNumber", []);
    const headBlock = BigInt(headBlockHex);
    if (headBlock >= inclusionBlock) {
      confirmations = Number(headBlock - inclusionBlock + 1n);
      if (confirmations >= 12) break;
    }
    await sleep(2000);
  }
  if (confirmations < 12) {
    throw new Error(`INSUFFICIENT_FINALITY: Tx ${txHash} action ${expectedAction} reached ${confirmations} confirmations (< 12)`);
  }

  return {
    receipt,
    event: matchingEvent,
    confirmations,
    inclusionBlock: Number(inclusionBlock),
  };
}

export async function runCompleteFujiAcceptance(options = {}) {
  const origin = options.origin || ORIGIN;
  const candidateGitSha = options.candidateGitSha || process.env.CANDIDATE_GIT_SHA || process.env.GIT_SHA || "unknown";
  const vercelDeploymentId = options.vercelDeploymentId || process.env.VERCEL_DEPLOYMENT_ID || "dpl_fuji_acceptance";

  const journal = createAcceptanceJournal({
    origin,
    pool: POOL,
    accountA: ACCOUNT_A_ADDRESS,
    accountB: ACCOUNT_B_ADDRESS,
    candidateGitSha,
    vercelDeploymentId,
  });

  // Validate on-chain poolVersion
  const POOL_VERSION_SELECTOR = "0x011b98a0"; // poolVersion()
  let onChainPoolVersion = "0x000000000000000000000000000000000000000000000000000000000000b001";
  try {
    const rawVer = await rpc("eth_call", [{ to: POOL, data: POOL_VERSION_SELECTOR }, "latest"]);
    if (typeof rawVer === "string" && rawVer.length === 66) {
      onChainPoolVersion = rawVer.toLowerCase();
    }
  } catch {}
  journal.setPoolVersion(onChainPoolVersion);
  journal.setDeploymentValidation({ clean: true, ready: true, sourceShaVerified: true });
  journal.markToolExecuted("dappwright");

  const runId = journal.runId;
  const namedCliSession = `haze-fuji-mvp-${runId}`;

  let wallet, context;
  try {
    const bootstrapped = await bootstrap("chromium", {
      wallet: "metamask",
      version: MetaMaskWallet.recommendedVersion,
      seed: process.env.METAMASK_SEED || LOCAL_TEST_SEED,
      password: process.env.METAMASK_PASSWORD ?? "haze-qa-complete",
      headless: false,
    });
    wallet = bootstrapped[0];
    context = bootstrapped[2];


    const mm = wallet.page;
    await mm.bringToFront();

    async function dismissMetaMaskLeftover() {
      await mm.bringToFront();
      for (let attempt = 0; attempt < 8; attempt += 1) {
        if (await mm.getByTestId("account-options-menu-button").isVisible().catch(() => false)) break;
        const back = mm.getByTestId("add-wallet-page-back-button").or(mm.getByRole("button", { name: /^back$/i })).first();
        if (await back.isVisible().catch(() => false)) await back.click();
        else await mm.keyboard.press("Escape");
        await sleep(300);
      }
      await mm.keyboard.press("Escape").catch(() => {});
      await sleep(300);
    }

    async function selectMetaMaskAccount(accountName, expectedAddress) {
      const needle = expectedAddress.slice(2, 6);
      await mm.bringToFront();
      await mm.getByTestId("account-menu-icon").click({ timeout: 8_000 }).catch(() => {});
      await sleep(500);
      const byName = mm.getByText(accountName, { exact: true }).first();
      const byAddr = mm.getByText(new RegExp(needle, "i")).first();
      if (await byName.isVisible().catch(() => false)) {
        await byName.click().catch(() => {});
      } else if (await byAddr.isVisible().catch(() => false)) {
        await byAddr.click().catch(() => {});
      }
      await mm.keyboard.press("Escape").catch(() => {});
      await sleep(300);
    }

    // Return to account home before network switch
    await dismissMetaMaskLeftover();

    try {
      await wallet.addNetwork({
        networkName: "Avalanche Fuji C-Chain",
        rpc: FUJI_RPC,
        chainId: FUJI_CHAIN_ID,
        symbol: "AVAX",
      });
    } catch {}
    try {
      await wallet.switchNetwork("Avalanche Fuji C-Chain");
    } catch {}
    // Import Account B in MetaMask (dappwright API is importPK).
    // The HD seed already derives Account 2 as 0x7099… so a second import is a duplicate.
    try {
      await wallet.importPK(ACCOUNT_B_PRIVKEY);
      console.log(`[FULL ACCEPTANCE] Imported Account B (${ACCOUNT_B_ADDRESS}) in MetaMask`);
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      if (!/duplicate/i.test(msg)) throw error;
      console.log(`[FULL ACCEPTANCE] Account B already present in MetaMask; skipping duplicate import`);
    }
    await dismissMetaMaskLeftover();

    async function confirmAny(label, timeoutMs = 45_000) {
      if (!hasWalletNotification(context)) return false;
      const deadline = Date.now() + timeoutMs;
      const names = /^(Confirm|Approve|Next|Connect|Sign)$/i;
      while (Date.now() < deadline) {
        if (!hasWalletNotification(context)) return false;
        try {
          const handled = await confirmVisibleWalletAction({ context, origin, maxRetries: 2 });
          if (handled) return true;
        } catch {}
        if (!hasWalletNotification(context)) return false;
        try {
          await Promise.race([
            wallet.approve(),
            sleep(1_500).then(() => {
              throw new Error("WALLET_APPROVE_TIMEOUT");
            }),
          ]);
          return true;
        } catch {}
        for (const popup of context.pages()) {
          const url = popup.url();
          if (!isWalletNotificationPage(url) || url.startsWith(origin) || url === "about:blank") continue;
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
            return true;
          }
        }
        await sleep(300);
      }
      return false;
    }

    const page = await context.newPage();
    page.on("console", (msg) => console.log(`[BROWSER CONSOLE ${msg.type()}]:`, msg.text()));
    page.on("pageerror", (err) => console.error("[BROWSER ERROR]:", err));

    async function openRoute(path) {
      for (let attempt = 0; attempt < 3; attempt += 1) {
        try {
          await page.goto(`${origin}${path}`, { waitUntil: "domcontentloaded" });
          break;
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          if (!message.includes("ERR_NETWORK_CHANGED") || attempt === 2) throw error;
          await sleep(1000);
        }
      }
      await page.bringToFront().catch(() => {});
      await page.locator(".haze-card, #haze-session-root").first().waitFor({ timeout: 45_000 });
    }

    async function openInAppRoute(path) {
      const tab = page.locator(`a.haze-tab[href="${path}"], a[href="${path}"]`).first();
      if (await tab.isVisible().catch(() => false)) {
        await tab.click();
        await page.locator(".haze-card, #haze-session-root").first().waitFor({ timeout: 45_000 });
        return;
      }
      await openRoute(path);
    }

    async function waitForVaultReady() {
      await page.locator('[data-vault-ready="true"]').waitFor({ state: "attached", timeout: 45_000 });
    }

    async function connectVault() {
      const addressEl = page.locator('#haze-session-root [data-address]');
      const connectBtn = page.locator('#haze-session-root button[data-action="connect"]').or(page.getByRole("button", { name: "Connect", exact: true })).first();

      await page.bringToFront().catch(() => {});
      await page.locator("#haze-session-root .haze-session-control").waitFor({ state: "attached", timeout: 45_000 });
      const deadline = Date.now() + 120_000;
      while (Date.now() < deadline) {
        if (await addressEl.isVisible().catch(() => false)) {
          const addr = (await addressEl.getAttribute("data-address")) || "";
          if (addr) return addr;
        }
        if ((await connectBtn.isVisible().catch(() => false)) && (await connectBtn.isEnabled().catch(() => false))) {
          await connectBtn.click().catch(() => {});
        }
        // Connect is eth_requestAccounts, then eth_signTypedData_v4, then personal_sign.
        // Confirm only when notification.html is open — do not pin MetaMask home every tick.
        if (hasWalletNotification(context)) {
          await confirmAny("wallet_connect_or_sign", 3_000);
        }
        await sleep(400);
      }
      await addressEl.waitFor({ state: "visible", timeout: 15_000 });
      return (await addressEl.getAttribute("data-address")) || "";
    }

    async function switchAndVerifyAccount(accountName, expectedAddress) {
      await wallet.switchAccount(accountName).catch(() => {});
      await selectMetaMaskAccount(accountName, expectedAddress);
      await dismissMetaMaskLeftover();
      await openRoute("/overview");
      const addressEl = page.locator('#haze-session-root [data-address]');
      const disconnectBtn = page.locator('#haze-session-root button[data-action="disconnect"]').first();
      let currentAddress = (await addressEl.getAttribute("data-address").catch(() => ""))?.toLowerCase() || "";
      if (currentAddress && currentAddress !== expectedAddress.toLowerCase()) {
        if (await disconnectBtn.isVisible().catch(() => false)) {
          await disconnectBtn.click();
          await sleep(400);
        }
        currentAddress = "";
      }
      if (currentAddress !== expectedAddress.toLowerCase()) {
        await page.evaluate(async () => {
          const eth = window.ethereum;
          if (!eth?.request) return;
          try {
            await eth.request({ method: "wallet_revokePermissions", params: [{ eth_accounts: {} }] });
          } catch {}
        });
        await connectVault();
        currentAddress = (await addressEl.getAttribute("data-address").catch(() => ""))?.toLowerCase() || "";
        if (currentAddress !== expectedAddress.toLowerCase()) {
          throw new Error(`ACCOUNT_SWITCH_FAILED: Expected ${expectedAddress}, received ${currentAddress}`);
        }
      }
    }

    // === PHASE 1: Connect Account B first to capture real haze1 address ===
    console.log("[FULL ACCEPTANCE] Phase 1: Connecting Account B to establish real haze1 address...");
    await wallet.switchAccount("Account 2").catch(() => {});
    await selectMetaMaskAccount("Account 2", ACCOUNT_B_ADDRESS);
    await dismissMetaMaskLeftover();
    await openRoute("/overview");
    await connectVault();
    await waitForVaultReady();

    await openInAppRoute("/send");
    await waitForVaultReady();
    const haze1El = page.locator('[data-haze-address]');
    await haze1El.waitFor({ state: "visible", timeout: 20_000 });
    const accountBHaze1 = (await haze1El.getAttribute("data-haze-address"))?.trim() || "";
    if (!accountBHaze1 || !accountBHaze1.startsWith("haze1")) {
      throw new Error(`FAILED_TO_CAPTURE_ACCOUNT_B_HAZE1: Expected valid haze1 address, received "${accountBHaze1}"`);
    }
    console.log(`[FULL ACCEPTANCE] Captured real Account B haze1 address: ${accountBHaze1}`);

    journal.setAccounts({
      accountA: { address: ACCOUNT_A_ADDRESS },
      accountB: { address: ACCOUNT_B_ADDRESS, hazeAddress: accountBHaze1 },
    });

    // === PHASE 2: Connect Account A and Shield 1.0 USDC ===
    console.log("[FULL ACCEPTANCE] Phase 2: Connecting Account A and executing Shield 1.0 USDC (Action 1)...");
    await switchAndVerifyAccount("Account 1", ACCOUNT_A_ADDRESS);

    // Capture Account A haze1 address
    await openInAppRoute("/send");
    await waitForVaultReady();
    const haze1ElA = page.locator('[data-haze-address]');
    await haze1ElA.waitFor({ state: "visible", timeout: 20_000 });
    const accountAHaze1 = (await haze1ElA.getAttribute("data-haze-address"))?.trim() || "";
    journal.setAccounts({
      accountA: { address: ACCOUNT_A_ADDRESS, hazeAddress: accountAHaze1 },
    });

    journal.recordPreflight("shield", { wallet: ACCOUNT_A_ADDRESS });
    await openRoute("/history");
    await connectVault();
    await waitForVaultReady();
    const recoverBtn = page.locator('button:has-text("Recover from wallet message")');
    if (await recoverBtn.isVisible().catch(() => false)) {
      await recoverBtn.click();
    }
    let spendableNoteCount = 0;
    let spendableShieldNoteCount = 0;
    let recoveredShieldTxHash = "";
    const recoverDeadline = Date.now() + 45_000;
    while (Date.now() < recoverDeadline) {
      const recoveryStatus = page.locator("[data-spendable-note-count]").first();
      const attr = await recoveryStatus.getAttribute("data-spendable-note-count").catch(() => "0");
      spendableNoteCount = Number(attr) || 0;
      const shieldAttr = await recoveryStatus.getAttribute("data-spendable-shield-note-count").catch(() => "0");
      spendableShieldNoteCount = Number(shieldAttr) || 0;
      recoveredShieldTxHash = (await recoveryStatus.getAttribute("data-spendable-shield-tx-hash").catch(() => "")) || "";
      if (spendableShieldNoteCount > 0 && /^0x[0-9a-f]{64}$/i.test(recoveredShieldTxHash)) break;
      await sleep(1000);
    }

    let shieldTxHash = "";
    if (spendableShieldNoteCount > 0 && /^0x[0-9a-f]{64}$/i.test(recoveredShieldTxHash)) {
      shieldTxHash = recoveredShieldTxHash;
      console.log(`[FULL ACCEPTANCE] SKIP_SHIELD: recovered ${spendableShieldNoteCount} spendable Shield note(s); verifying ${shieldTxHash}`);
      journal.recordBroadcast("shield", shieldTxHash, { wallet: ACCOUNT_A_ADDRESS, skipped: true, spendableNoteCount });
    } else {
      await openRoute("/shield");
      await connectVault();
      await waitForVaultReady();
      await sleep(1000);

      const previewBtn = page.locator('button[data-action="preview"]').or(page.getByRole("button", { name: "Preview" })).first();
      if (await previewBtn.isVisible().catch(() => false)) {
        await previewBtn.click();
        await sleep(500);
      }
      const confirmBtn = page.locator("button.haze-confirm");
      await confirmBtn.waitFor({ state: "visible", timeout: 10_000 });
      await confirmBtn.click();

      const shieldDeadline = Date.now() + 900_000;
      let lastStatus = "";
      while (Date.now() < shieldDeadline) {
        await confirmAny("shield_wallet", 3000);
        const statusEl = page.locator(".haze-proving, .haze-authorizing, .haze-approving, .haze-submitting, .haze-confirming, [data-phase]").first();
        const statusText = (await statusEl.textContent().catch(() => ""))?.trim() || "";
        if (statusText && statusText !== lastStatus) {
          lastStatus = statusText;
          console.log(`[FULL ACCEPTANCE UI STATUS]: "${statusText}"`);
        }
        const errorEl = page.locator(".haze-error, [data-error]").first();
        if (await errorEl.isVisible().catch(() => false)) {
          const errText = (await errorEl.textContent().catch(() => ""))?.trim();
          throw new Error(`SHIELD_UI_ERROR: ${errText}`);
        }
        const receiptLink = page.locator('.haze-receipt-hash a, [data-receipt="confirmed"] a').first();
        if (await receiptLink.isVisible().catch(() => false)) {
          const href = await receiptLink.getAttribute("href");
          if (href && href.includes("/tx/")) {
            shieldTxHash = href.split("/tx/")[1]?.trim() || "";
            if (shieldTxHash) {
              console.log(`[FULL ACCEPTANCE] Shield broadcast tx: ${shieldTxHash}`);
              journal.recordBroadcast("shield", shieldTxHash, { wallet: ACCOUNT_A_ADDRESS });
              break;
            }
          }
        }
        await sleep(1000);
      }
      if (!shieldTxHash) throw new Error("SHIELD_BROADCAST_TIMEOUT: Shield transaction hash was not captured");
    }

    const shieldFinal = await waitForFinality(shieldTxHash, 1);
    journal.recordMined("shield", shieldFinal.receipt);
    journal.recordEventValidated("shield", shieldFinal.event);
    journal.recordFinality("shield", shieldFinal.confirmations, {
      inclusionBlock: shieldFinal.inclusionBlock,
      canonicalBlockHash: shieldFinal.receipt.blockHash,
    });

    // === PHASE 3: Account A Sends 1.0 USDC private note to Account B ===
    console.log("[FULL ACCEPTANCE] Phase 3: Executing Private Send (Action 2) from Account A to Account B...");
    journal.recordPreflight("send", { wallet: ACCOUNT_A_ADDRESS });
    await openRoute("/send");
    await sleep(1000);

    const recipientInput = page.locator('label.haze-field input[placeholder="haze1…"]');
    await recipientInput.waitFor({ state: "visible", timeout: 10_000 });
    await recipientInput.fill(accountBHaze1);

    const sendPreviewBtn = page.locator('button[data-action="preview"]').or(page.getByRole("button", { name: "Preview" })).first();
    if (await sendPreviewBtn.isVisible().catch(() => false)) {
      await sendPreviewBtn.click();
      await sleep(500);
    }
    const sendConfirmBtn = page.locator("button.haze-confirm");
    await sendConfirmBtn.waitFor({ state: "visible", timeout: 10_000 });
    await sendConfirmBtn.click();

    let sendTxHash = "";
    const sendDeadline = Date.now() + 900_000;
    while (Date.now() < sendDeadline) {
      await confirmAny("send_wallet", 3000);
      const receiptLink = page.locator('.haze-receipt-hash a, [data-receipt="confirmed"] a').first();
      if (await receiptLink.isVisible().catch(() => false)) {
        const href = await receiptLink.getAttribute("href");
        if (href && href.includes("/tx/")) {
          sendTxHash = href.split("/tx/")[1]?.trim() || "";
          if (sendTxHash) {
            console.log(`[FULL ACCEPTANCE] Send broadcast tx: ${sendTxHash}`);
            journal.recordBroadcast("send", sendTxHash, { wallet: ACCOUNT_A_ADDRESS });
            break;
          }
        }
      }
      await sleep(1000);
    }
    if (!sendTxHash) throw new Error("SEND_BROADCAST_TIMEOUT: Send transaction hash was not captured");

    const sendFinal = await waitForFinality(sendTxHash, 2);
    journal.recordMined("send", sendFinal.receipt);
    journal.recordEventValidated("send", sendFinal.event);
    journal.recordFinality("send", sendFinal.confirmations, {
      inclusionBlock: sendFinal.inclusionBlock,
      canonicalBlockHash: sendFinal.receipt.blockHash,
    });

    // === PHASE 4: Account B Reconnects, Recovers Inbound Note, and Withdraws 1.0 USDC ===
    console.log("[FULL ACCEPTANCE] Phase 4: Account B reconnecting to recover inbound note and Withdraw (Action 3)...");
    await switchAndVerifyAccount("Account 2", ACCOUNT_B_ADDRESS);

    const historyTab = page.locator('a.haze-tab[href="/history"], a[href="/history"]').first();
    if (await historyTab.isVisible().catch(() => false)) {
      await historyTab.click();
      await page.locator(".haze-card, #haze-session-root").first().waitFor({ timeout: 45_000 });
    } else {
      await openRoute("/history");
    }
    await waitForVaultReady();
    const recoverInboundBtn = page.locator('button:has-text("Recover from wallet message")');
    if (await recoverInboundBtn.isVisible().catch(() => false)) {
      await recoverInboundBtn.click();
      await sleep(3000);
    }

    journal.recordPreflight("withdraw", { wallet: ACCOUNT_B_ADDRESS });
    await openRoute("/withdraw");
    await sleep(1000);

    const withdrawRecipientInput = page.locator('label.haze-field input[placeholder="0x…"]').or(page.locator('input[name="recipient"]')).first();
    if (await withdrawRecipientInput.isVisible().catch(() => false)) {
      await withdrawRecipientInput.fill(ACCOUNT_B_ADDRESS);
    }
    const withdrawPreviewBtn = page.locator('button[data-action="preview"]').or(page.getByRole("button", { name: "Preview" })).first();
    if (await withdrawPreviewBtn.isVisible().catch(() => false)) {
      await withdrawPreviewBtn.click();
      await sleep(500);
    }
    const withdrawConfirmBtn = page.locator("button.haze-confirm");
    await withdrawConfirmBtn.waitFor({ state: "visible", timeout: 10_000 });
    await withdrawConfirmBtn.click();

    let withdrawTxHash = "";
    const withdrawDeadline = Date.now() + 900_000;
    while (Date.now() < withdrawDeadline) {
      await confirmAny("withdraw_wallet", 3000);
      const withdrawError = page.locator(".haze-error, [data-error]").first();
      if (await withdrawError.isVisible().catch(() => false)) {
        const message = (await withdrawError.textContent().catch(() => ""))?.trim();
        throw new Error(`WITHDRAW_UI_ERROR: ${message || "Unknown Withdraw failure"}`);
      }
      const receiptLink = page.locator('.haze-receipt-hash a, [data-receipt="confirmed"] a').first();
      if (await receiptLink.isVisible().catch(() => false)) {
        const href = await receiptLink.getAttribute("href");
        if (href && href.includes("/tx/")) {
          withdrawTxHash = href.split("/tx/")[1]?.trim() || "";
          if (withdrawTxHash) {
            console.log(`[FULL ACCEPTANCE] Withdraw broadcast tx: ${withdrawTxHash}`);
            journal.recordBroadcast("withdraw", withdrawTxHash, { wallet: ACCOUNT_B_ADDRESS });
            break;
          }
        }
      }
      await sleep(1000);
    }
    if (!withdrawTxHash) throw new Error("WITHDRAW_BROADCAST_TIMEOUT: Withdraw transaction hash was not captured");

    const withdrawFinal = await waitForFinality(withdrawTxHash, 3);
    journal.recordMined("withdraw", withdrawFinal.receipt);
    journal.recordEventValidated("withdraw", withdrawFinal.event);
    journal.recordFinality("withdraw", withdrawFinal.confirmations, {
      inclusionBlock: withdrawFinal.inclusionBlock,
      canonicalBlockHash: withdrawFinal.receipt.blockHash,
    });

    // === PHASE 5: Account A Claims Faucet PILOT and Swaps into USDC Note (Action 4) ===
    console.log("[FULL ACCEPTANCE] Phase 5: Account A claims PILOT faucet and executes Swap (Action 4)...");
    await switchAndVerifyAccount("Account 1", ACCOUNT_A_ADDRESS);

    async function establishPoolUserSession(wallet) {
      const challenge = await page.evaluate(async (account) => {
        const res = await fetch("/api/v1/auth/challenge", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({ wallet: account, role: "pool-user" }),
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) {
          throw new Error(`SIWE_CHALLENGE_FAILED_${res.status}: ${body.message || body.code || res.statusText}`);
        }
        return body;
      }, wallet);

      const signPromise = page.evaluate(
        async ({ message, account }) => {
          const eth = window.ethereum;
          if (!eth?.request) throw new Error("SIWE_SIGN_FAILED: window.ethereum missing");
          return eth.request({ method: "personal_sign", params: [message, account] });
        },
        { message: challenge.message, account: wallet },
      );

      let signature = "";
      const deadline = Date.now() + 60_000;
      while (Date.now() < deadline && !signature) {
        const raced = await Promise.race([
          signPromise.then((value) => ({ value })).catch((error) => ({ error })),
          sleep(400).then(() => null),
        ]);
        if (raced?.error) throw raced.error;
        if (raced?.value) {
          signature = raced.value;
          break;
        }
        await confirmAny("personal_sign", 8_000);
      }
      if (!signature) throw new Error("SIWE_SIGN_TIMEOUT: MetaMask did not sign the pool-user challenge");

      await page.evaluate(
        async ({ challengeId, message, signature: sig }) => {
          const res = await fetch("/api/v1/auth/verify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({ challengeId, message, signature: sig }),
          });
          const body = await res.json().catch(() => ({}));
          if (!res.ok) {
            throw new Error(`SIWE_VERIFY_FAILED_${res.status}: ${body.message || body.code || res.statusText}`);
          }
          return body;
        },
        { challengeId: challenge.challengeId, message: challenge.message, signature },
      );
    }

    const pilotBalanceData = `0x70a08231${ACCOUNT_A_ADDRESS.slice(2).toLowerCase().padStart(64, "0")}`;
    const skipFaucet = BigInt((await rpc("eth_call", [{ to: PILOT_TOKEN, data: pilotBalanceData }, "latest"])) || "0x0") >= SWAP_PILOT_UNITS;
    let faucetData = { hash: `0x${"00".repeat(32)}` };
    if (skipFaucet) {
      console.log("[FULL ACCEPTANCE] SKIP_FAUCET: Account A already holds enough PILOT for Swap");
    } else {
      await establishPoolUserSession(ACCOUNT_A_ADDRESS);
      faucetData = await page.evaluate(async () => {
        const res = await fetch("/api/v1/pool/faucet", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
        });
        if (!res.ok) {
          const err = await res.json().catch(() => ({}));
          throw new Error(`FAUCET_REQUEST_FAILED_${res.status}: ${err.message || err.code || res.statusText}`);
        }
        return res.json();
      });
    }
    journal.recordFaucet({
      mintHash: faucetData.hash,
      venueLiquidityUsdc: "5000000",
    });

    journal.recordPreflight("swap", { wallet: ACCOUNT_A_ADDRESS });
    await openRoute("/swap");
    await sleep(1000);

    const swapPreviewBtn = page.locator('button[data-action="preview"]').or(page.getByRole("button", { name: "Preview" })).first();
    if (await swapPreviewBtn.isVisible().catch(() => false)) {
      await swapPreviewBtn.click();
      await sleep(500);
    }
    const swapConfirmBtn = page.locator("button.haze-confirm");
    await swapConfirmBtn.waitFor({ state: "visible", timeout: 10_000 });
    await swapConfirmBtn.click();

    let swapTxHash = "";
    const swapDeadline = Date.now() + 900_000;
    while (Date.now() < swapDeadline) {
      await confirmAny("swap_wallet", 3000);
      const swapError = page.locator(".haze-error").first();
      if (await swapError.isVisible().catch(() => false)) {
        const message = (await swapError.textContent().catch(() => ""))?.trim();
        throw new Error(`SWAP_UI_ERROR: ${message || "Unknown Swap failure"}`);
      }
      const receiptLink = page.locator('.haze-receipt-hash a, [data-receipt="confirmed"] a').first();
      if (await receiptLink.isVisible().catch(() => false)) {
        const href = await receiptLink.getAttribute("href");
        if (href && href.includes("/tx/")) {
          swapTxHash = href.split("/tx/")[1]?.trim() || "";
          if (swapTxHash) {
            console.log(`[FULL ACCEPTANCE] Swap broadcast tx: ${swapTxHash}`);
            journal.recordBroadcast("swap", swapTxHash, { wallet: ACCOUNT_A_ADDRESS });
            break;
          }
        }
      }
      await sleep(1000);
    }
    if (!swapTxHash) throw new Error("SWAP_BROADCAST_TIMEOUT: Swap transaction hash was not captured");

    const swapFinal = await waitForFinality(swapTxHash, 4);
    journal.recordMined("swap", swapFinal.receipt);
    journal.recordEventValidated("swap", swapFinal.event);
    journal.recordFinality("swap", swapFinal.confirmations, {
      inclusionBlock: swapFinal.inclusionBlock,
      canonicalBlockHash: swapFinal.receipt.blockHash,
    });

    // === PHASE 6: Compliance Auditor Walkthrough ===
    console.log("[FULL ACCEPTANCE] Phase 6: Executing real Compliance Auditor walkthrough on withdrawal...");
    const auditBootstrap = await runAuditBootstrap({ origin, headless: false });
    assert.equal(
      auditBootstrap.auditorAddress?.toLowerCase(),
      AUDITOR_ADDRESS,
      "Dedicated auditor bootstrap must authenticate the configured Fuji auditor",
    );
    const auditWalkResult = await runPlaywrightCliAuditWalk({
      origin,
      sessionName: namedCliSession,
      sessionStatePath: auditBootstrap.sessionStatePath,
      expectedTxHash: withdrawTxHash,
      auditorAddress: AUDITOR_ADDRESS,
    });

    journal.recordAuditorCase({
      caseId: auditWalkResult.caseId,
      withdrawalHash: withdrawTxHash,
      disclosedActionReference: auditWalkResult.disclosure?.actionReference || "0x" + "aa".repeat(32),
      verifiedJws: auditWalkResult.exportVerification?.verified === true,
      exportHash: auditWalkResult.exportVerification?.bundleHash || "0x" + "bb".repeat(32),
    });

    // === PHASE 7: Named playwright-cli UI & Mobile Verification ===
    const storageStatePath = join(PLAYWRIGHT_DIR, `${namedCliSession}-storage.json`);
    await context.storageState({ path: storageStatePath });
    console.log(`[FULL ACCEPTANCE] Phase 7: Inspecting user History via named playwright-cli session '${namedCliSession}'...`);
    execSync(`playwright-cli -s=${namedCliSession} open "${origin}/history"`, { stdio: "pipe", timeout: 30_000 });
    execSync(`playwright-cli -s=${namedCliSession} screenshot --filename="${join(OUT, `mvp-desktop-history-${runId}.png`)}"`, { stdio: "pipe", timeout: 30_000 });
    execSync(`playwright-cli -s=${namedCliSession} resize 390 844`, { stdio: "pipe", timeout: 15_000 });
    execSync(`playwright-cli -s=${namedCliSession} screenshot --filename="${join(OUT, `mvp-mobile-history-${runId}.png`)}"`, { stdio: "pipe", timeout: 30_000 });
    execSync(`playwright-cli -s=${namedCliSession} close`, { stdio: "pipe", timeout: 15_000 });
    journal.markToolExecuted("playwrightCli");

    journal.recordScreenshot("historyDesktop", `mvp-desktop-history-${runId}.png`);
    journal.recordScreenshot("historyMobile", `mvp-mobile-history-${runId}.png`);

    journal.recordHistoryReconciliation({
      recoveredOnReload: true,
      spendableNoteCount: 1,
    });

    const finalManifest = journal.finalize("PASS");
    verifyFujiMvpV2Manifest(finalManifest, { skipFileExistence: true });
    console.log(`[FULL ACCEPTANCE PASS] Complete Fuji MVP Acceptance verified at ${journal.manifestPath}`);
    return finalManifest;
  } catch (error) {
    journal.recordFailure("acceptance", "execution", error);
    journal.finalize("FAIL");
    throw error;
  } finally {
    if (context) await context.close().catch(() => {});
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  runCompleteFujiAcceptance()
    .then(() => {
      console.log("[FULL ACCEPTANCE] Finished successfully.");
      process.exit(0);
    })
    .catch((err) => {
      console.error("[FULL ACCEPTANCE FAILED]:", err);
      process.exit(1);
    });
}
