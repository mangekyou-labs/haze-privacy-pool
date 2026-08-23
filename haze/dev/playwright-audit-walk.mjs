/**
 * D8 Production Playwright Verification Walkthrough for Haze Compliance Auditor Workstation.
 * Executes visible audit investigation, cryptographic verification, canonical signed export,
 * access log tracking, mobile responsiveness, and negative security checks against Avalanche Fuji.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { p256 } from "@noble/curves/p256";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { chromium } from "playwright-core";

const ROOT = dirname(fileURLToPath(import.meta.url));
const DEPLOYED_ORIGIN = process.env.HAZE_DEPLOYED_ORIGIN || "https://haze-mu-flax.vercel.app";
const FUJI_RPC = process.env.AVALANCHE_FUJI_RPC || "https://api.avax-test.network/ext/bc/C/rpc";
const FUJI_CHAIN_ID = 43113;
const APPLICATION_ID = "0x0000000000000000000000000000000000000000000000000000000000000a11";

const GRANTED_FIELDS = ["tx_hash", "amount", "asset", "timestamp", "policy_version"];
const DENIED_FIELDS = ["user", "counterparty"];

const PLAYWRIGHT_DIR = join(ROOT, "../.playwright");
const SESSION_STATE_PATH = join(PLAYWRIGHT_DIR, "audit-session.json");
const BOOTSTRAP_METADATA_PATH = join(PLAYWRIGHT_DIR, "audit-bootstrap-meta.json");

const OUTPUT_DIR = join(ROOT, "../output/playwright");
const SCREENSHOTS = {
  login: join(OUTPUT_DIR, "d8-audit-production-login.png"),
  disclosure: join(OUTPUT_DIR, "d8-audit-production-disclosure.png"),
  export: join(OUTPUT_DIR, "d8-audit-production-export.png"),
  mobile: join(OUTPUT_DIR, "d8-audit-production-mobile.png"),
};
const EVIDENCE_PATH = join(OUTPUT_DIR, "d8-production-audit-acceptance.json");

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

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

function getAuditorPrivateKey() {
  if (process.env.HAZE_AUDITOR_PRIVATE_KEY) {
    return process.env.HAZE_AUDITOR_PRIVATE_KEY.replace(/^0x/, "");
  }
  if (process.env.PRIVATE_KEY) {
    return process.env.PRIVATE_KEY.replace(/^0x/, "");
  }
  const parentEnvPath = join(ROOT, "../../.env");
  if (existsSync(parentEnvPath)) {
    const content = readFileSync(parentEnvPath, "utf8");
    const match = content.match(/PRIVATE_KEY=(?:0x)?([0-9a-fA-F]{64})/);
    if (match?.[1]) return match[1];
  }
  return null;
}

function deriveAddress(privKeyHex) {
  const priv = Buffer.from(privKeyHex, "hex");
  const pub = secp256k1.getPublicKey(priv, false);
  const hash = keccak_256(pub.subarray(1));
  return `0x${Buffer.from(hash).subarray(12).toString("hex")}`;
}

function personalSign(message, privKeyHex) {
  const priv = Buffer.from(privKeyHex, "hex");
  const prefix = `\x19Ethereum Signed Message:\n${Buffer.byteLength(message, "utf8")}`;
  const msgBytes = Buffer.concat([Buffer.from(prefix, "utf8"), Buffer.from(message, "utf8")]);
  const digest = keccak_256(msgBytes);
  const sig = secp256k1.sign(digest, priv, { prehash: false });
  const compact = sig.toCompactRawBytes();
  const recovery = sig.recovery;
  const vHex = recovery.toString(16).padStart(2, "0");
  return `0x${Buffer.from(compact).toString("hex")}${vHex}`;
}

function canonicalizeJson(val) {
  if (val === null || typeof val !== "object") return JSON.stringify(val);
  if (Array.isArray(val)) return `[${val.map(canonicalizeJson).join(",")}]`;
  const keys = Object.keys(val).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalizeJson(val[k])}`).join(",")}}`;
}

function verifyEs256Jws(bundle, jwks) {
  const keyObj = jwks.keys?.find((k) => k.kid === bundle.signing_key_id);
  if (!keyObj) throw new Error(`Signing key ${bundle.signing_key_id} not found in JWKS`);
  const xBytes = Buffer.from(keyObj.x, "base64url");
  const yBytes = Buffer.from(keyObj.y, "base64url");
  const pubKey = Buffer.concat([Buffer.from([0x04]), xBytes, yBytes]);

  const [headerB64, , sigB64] = bundle.detached_jws.split(".");
  const canonicalPayload = canonicalizeJson(bundle.payload);
  const payloadB64 = Buffer.from(canonicalPayload, "utf8").toString("base64url");
  const signingInput = `${headerB64}.${payloadB64}`;
  const digest = createHash("sha256").update(signingInput).digest();
  const sigBytes = Buffer.from(sigB64, "base64url");

  const valid = p256.verify(sigBytes, digest, pubKey);
  if (!valid) throw new Error("ES256 detached JWS signature verification failed");
  return true;
}

export async function runProductionAuditWalk(options = {}) {
  const origin = options.origin || DEPLOYED_ORIGIN;
  mkdirSync(OUTPUT_DIR, { recursive: true });
  mkdirSync(PLAYWRIGHT_DIR, { recursive: true });

  const networkRequests = [];
  const complianceResponses = [];

  const privKeyHex = getAuditorPrivateKey();
  let auditorAddress = options.auditorAddress;
  if (!auditorAddress && privKeyHex) {
    auditorAddress = deriveAddress(privKeyHex);
  }
  if (!auditorAddress) {
    throw new Error("Auditor private key or address required for D8 verification walk");
  }

  // 1. Initial on-chain transaction count check
  const txCountInitial = await rpc("eth_getTransactionCount", [auditorAddress, "latest"]);

  // 2. Perform automated SIWE authentication
  console.log(`[D8 WALK] Authenticating SIWE for auditor ${auditorAddress} against ${origin}...`);
  const challengeRes = await fetch(`${origin}/api/compliance/auth/challenge`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ wallet: auditorAddress, applicationId: APPLICATION_ID }),
  });
  if (!challengeRes.ok) {
    throw new Error(`SIWE challenge creation failed: ${challengeRes.status} ${await challengeRes.text()}`);
  }
  const challengeData = await challengeRes.json();
  const signature = personalSign(challengeData.message, privKeyHex);

  const verifyRes = await fetch(`${origin}/api/compliance/auth/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      challengeId: challengeData.challengeId,
      message: challengeData.message,
      signature,
    }),
  });
  if (!verifyRes.ok) {
    throw new Error(`SIWE verify failed: ${verifyRes.status} ${await verifyRes.text()}`);
  }
  const sessionData = await verifyRes.json();
  assert.equal(sessionData.address.toLowerCase(), auditorAddress.toLowerCase());

  // Extract session token from cookie or response
  const setCookie = verifyRes.headers.get("set-cookie");
  let cookieVal = "";
  if (setCookie) {
    const match = setCookie.match(/haze_audit_session=([^;]+)/);
    if (match) cookieVal = match[1];
  }

  // Save Playwright storageState
  const urlObj = new URL(origin);
  const domain = urlObj.hostname;
  const storageState = {
    cookies: cookieVal
      ? [
          {
            name: "haze_audit_session",
            value: cookieVal,
            domain,
            path: "/",
            expires: Date.now() / 1000 + 3600,
            httpOnly: true,
            secure: urlObj.protocol === "https:",
            sameSite: "Strict",
          },
        ]
      : [],
    origins: [],
  };
  writeFileSync(SESSION_STATE_PATH, JSON.stringify(storageState, null, 2), "utf8");

  // 3. Launch Playwright Chromium
  const browser = await chromium.launch({ headless: options.headless ?? true });

  // A. Unauthenticated check & login screenshot
  const unauthContext = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const unauthPage = await unauthContext.newPage();
  await unauthPage.goto(`${origin}/audit`, { waitUntil: "domcontentloaded" });
  await unauthPage.waitForSelector("#haze-audit-workstation-root, .haze-workstation", {
    timeout: 30_000,
  });
  await unauthPage.screenshot({ path: SCREENSHOTS.login });
  await unauthContext.close();

  // B. Authenticated Workstation Walkthrough
  const authContext = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    storageState: SESSION_STATE_PATH,
  });
  const page = await authContext.newPage();

  page.on("request", (req) => {
    networkRequests.push({ url: req.url(), method: req.method() });
  });

  page.on("response", async (res) => {
    if (res.url().includes("/api/compliance/")) {
      let bodyJson = null;
      try {
        bodyJson = await res.json();
      } catch {}
      complianceResponses.push({
        url: res.url(),
        status: res.status(),
        ok: res.ok(),
        body: bodyJson,
      });
    }
  });

  await page.goto(`${origin}/audit`, { waitUntil: "networkidle" });
  await page.waitForSelector('[data-session-status="authenticated"]', { timeout: 30_000 });

  // Verify Case Queue
  await page.waitForSelector(".haze-case-list, .haze-workstation-panel", { timeout: 15_000 });
  const casesRes = await fetch(`${origin}/api/compliance/cases`, {
    headers: cookieVal ? { Cookie: `haze_audit_session=${cookieVal}` } : {},
  });
  assert.ok(casesRes.ok, "BFF cases endpoint must succeed for authenticated session");
  const casesJson = await casesRes.json();
  const casesList = casesJson.cases || [];
  assert.ok(casesList.length > 0, "At least one compliance case must be present in queue");

  const canonicalTx = "0x8218e5a4f14434e0007d421a8e82ba0914429a0cab43d7dba263d1ed232c8a03";
  const targetCase =
    casesList.find((c) => c.transactionHash?.toLowerCase() === canonicalTx.toLowerCase()) ||
    casesList[0];
  const caseId = targetCase.caseId;
  const transactionHash = targetCase.transactionHash;
  console.log(`[D8 WALK] Selected Case ID: ${caseId} Tx: ${transactionHash}`);

  // Verify Fuji On-Chain Finality
  const receipt = await rpc("eth_getTransactionReceipt", [transactionHash]);
  if (!receipt) throw new Error(`Receipt not found on Fuji for ${transactionHash}`);
  const txBlockNumber = Number.parseInt(receipt.blockNumber, 16);
  const currentBlockNumber = Number.parseInt(await rpc("eth_blockNumber", []), 16);
  const confirmationCount = currentBlockNumber - txBlockNumber + 1;
  assert.ok(confirmationCount >= 12, `Insufficient confirmations: ${confirmationCount}`);
  assert.equal(Number.parseInt(receipt.status, 16), 1, "Canonical receipt must have status 0x1");

  // Select case in UI
  const caseBtn = page.locator(`button[data-case-id="${caseId}"]`).first();
  if (await caseBtn.isVisible().catch(() => false)) {
    await caseBtn.click();
  }

  // Click Verify & Disclose
  const verifyBtn = page.locator('button[data-action="verify-case"]');
  await verifyBtn.waitFor({ state: "visible", timeout: 15_000 });
  await verifyBtn.click();

  // Wait for disclosure table and 6 structured checks
  await page.waitForSelector(".haze-disclosure-table, .haze-checklist", { timeout: 30_000 });

  // Verify 6 structured checks rendered in UI
  const checkItems = page.locator(".haze-checklist-item");
  const count = await checkItems.count();
  assert.equal(count, 6, "Must render exactly 6 structured verification checks");

  // Verify Decrypted Disclosure Record (exact 5 fields)
  const disclosureRes = await fetch(`${origin}/api/compliance/cases/${encodeURIComponent(caseId)}/disclosure`, {
    method: "POST",
    headers: cookieVal ? { Cookie: `haze_audit_session=${cookieVal}` } : {},
  });
  assert.ok(disclosureRes.ok, "Disclosure API request must succeed");
  const disclosurePayload = await disclosureRes.json();
  const fields = disclosurePayload.fields || {};

  for (const granted of GRANTED_FIELDS) {
    assert.ok(fields[granted] !== undefined, `Granted field ${granted} must be disclosed`);
  }
  for (const denied of DENIED_FIELDS) {
    assert.equal(fields[denied], undefined, `Denied field ${denied} must NOT be disclosed`);
    assert.equal(disclosurePayload[denied], undefined, `Root object must NOT contain ${denied}`);
  }

  await page.screenshot({ path: SCREENSHOTS.disclosure });

  // Open Export Modal
  const exportBtn = page.locator('button[data-action="export-case"]');
  await exportBtn.waitFor({ state: "visible", timeout: 15_000 });
  await exportBtn.click();
  await page.waitForSelector('#export-dialog-title, button[data-action="download-export-json"]', { timeout: 15_000 });

  // Fetch export directly to verify ES256 signature
  const exportRes = await fetch(`${origin}/api/compliance/cases/${encodeURIComponent(caseId)}/export`, {
    method: "POST",
    headers: cookieVal ? { Cookie: `haze_audit_session=${cookieVal}` } : {},
  });
  assert.ok(exportRes.ok, "Export endpoint must succeed");
  const exportBundle = await exportRes.json();

  // Fetch JWKS
  const jwksRes = await fetch(`${origin}/.well-known/jwks.json`);
  assert.ok(jwksRes.ok, "JWKS endpoint must return 200 OK");
  const jwks = await jwksRes.json();
  assert.ok(jwks.keys?.length > 0, "JWKS must contain public keys");

  // Verify detached JWS signature
  verifyEs256Jws(exportBundle, jwks);
  console.log("[D8 WALK] Verified ES256 detached JWS signature successfully!");

  // Negative test: Tampering with payload fails JWS verification
  const tamperedBundle = JSON.parse(JSON.stringify(exportBundle));
  tamperedBundle.payload.disclosed_fields.amount = "999999999999";
  assert.throws(() => verifyEs256Jws(tamperedBundle, jwks), /verification failed/);
  console.log("[D8 WALK] Verified payload tampering is detected and rejected!");

  await page.screenshot({ path: SCREENSHOTS.export });

  // Close Export Modal
  const closeModalBtn = page.locator('button[data-action="close-export-modal"]');
  await closeModalBtn.click();

  // Verify Access Log shows history
  const logRes = await fetch(`${origin}/api/compliance/access-log`, {
    headers: cookieVal ? { Cookie: `haze_audit_session=${cookieVal}` } : {},
  });
  assert.ok(logRes.ok, "Access log endpoint must succeed");
  const logData = await logRes.json();
  assert.ok(logData.entries?.length >= 2, "Access log must contain disclosure and export entries");

  // C. Mobile Responsiveness Test (390×844)
  await page.setViewportSize({ width: 390, height: 844 });
  await sleep(500);
  await page.screenshot({ path: SCREENSHOTS.mobile });
  const hasHorizontalScroll = await page.evaluate(() => document.body.scrollWidth > window.innerWidth);
  assert.equal(hasHorizontalScroll, false, "Mobile viewport must not have horizontal overflow");

  // D. Negative Security Checks
  // 1. Unauthenticated API request fails closed (401)
  const unauthApiRes = await fetch(`${origin}/api/compliance/cases`, { method: "GET" });
  assert.equal(unauthApiRes.status, 401, "Unauthenticated request must return 401 Unauthorized");

  // 2. Prohibited workspaces (/admin, /governance) remain forbidden
  const adminPage = await authContext.newPage();
  await adminPage.goto(`${origin}/admin`, { waitUntil: "domcontentloaded" });
  const adminBanner = await adminPage.textContent('.haze-banner[role="alert"]');
  assert.match(adminBanner, /This workspace is not authorized|FORBIDDEN/);
  await adminPage.close();

  const govPage = await authContext.newPage();
  await govPage.goto(`${origin}/governance`, { waitUntil: "domcontentloaded" });
  const govBanner = await govPage.textContent('.haze-banner[role="alert"]');
  assert.match(govBanner, /This workspace is not authorized|FORBIDDEN/);
  await govPage.close();

  // 3. Logout invalidates session
  const logoutRes = await fetch(`${origin}/api/compliance/logout`, {
    method: "POST",
    headers: cookieVal ? { Cookie: `haze_audit_session=${cookieVal}` } : {},
  });
  assert.ok(logoutRes.ok, "Logout must succeed");

  const postLogoutRes = await fetch(`${origin}/api/compliance/cases`, {
    headers: cookieVal ? { Cookie: `haze_audit_session=${cookieVal}` } : {},
  });
  assert.equal(postLogoutRes.status, 401, "Subsequent request after logout must return 401");

  // 4. Final auditor transaction count check (strictly unchanged)
  const txCountFinal = await rpc("eth_getTransactionCount", [auditorAddress, "latest"]);
  assert.equal(txCountInitial, txCountFinal, "Auditor on-chain transaction count must not change");

  // E. Compile and Save Production Evidence JSON Manifest
  const evidenceManifest = {
    releaseMilestone: "D8",
    origin,
    network: "Avalanche Fuji",
    chainId: FUJI_CHAIN_ID,
    caseId,
    transactionHash,
    confirmations: confirmationCount,
    receiptStatus: "0x1",
    grantedFields: GRANTED_FIELDS,
    deniedFields: DENIED_FIELDS,
    auditorAddress,
    txCountBefore: txCountInitial,
    txCountAfter: txCountFinal,
    signingKeyId: exportBundle.signing_key_id,
    checksCount: 6,
    screenshots: {
      login: "d8-audit-production-login.png",
      disclosure: "d8-audit-production-disclosure.png",
      export: "d8-audit-production-export.png",
      mobile: "d8-audit-production-mobile.png",
    },
    verificationTimestamp: new Date().toISOString(),
    status: "PASS",
  };

  writeFileSync(EVIDENCE_PATH, JSON.stringify(evidenceManifest, null, 2), "utf8");

  if (existsSync(SESSION_STATE_PATH)) {
    rmSync(SESSION_STATE_PATH, { force: true });
  }

  await authContext.close();
  await browser.close();

  console.log(`[D8 WALK] Evidence recorded at ${EVIDENCE_PATH}`);
  return evidenceManifest;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  runProductionAuditWalk()
    .then((manifest) => {
      console.log("D8 Production Playwright Verification complete:", manifest);
      process.exit(0);
    })
    .catch((err) => {
      console.error("D8 Production Playwright Verification failed:", err);
      process.exit(1);
    });
}
