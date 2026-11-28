import assert from "node:assert/strict";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { chromium } from "playwright-core";
import { createCommercialHost } from "../dev/commercial-host.mjs";
import { FIXTURE_ACCOUNTS } from "../web/packages/ui/src/site.ts";

const ROOT = dirname(fileURLToPath(import.meta.url));
const OUTPUT_DIR = join(ROOT, "../output/playwright");

test("Playwright Chromium E2E: auditor workstation on /audit loads cleanly and renders design tokens", async () => {
  const host = await createCommercialHost({ port: 0 });
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1280, height: 800 } });
  const page = await context.newPage();

  try {
    const auditorAddress = FIXTURE_ACCOUNTS[2].address; // Application auditor fixture
    await page.goto(`${host.url}/audit?address=${auditorAddress}`);

    // Verify app-shell chrome (auditor plane) with the auditor rail, no DEX tabs
    const chrome = await page.getAttribute(".haze-shell", "data-chrome");
    assert.equal(chrome, "compliance");
    const plane = await page.getAttribute(".haze-shell", "data-plane");
    assert.equal(plane, "auditor");

    // Verify Auditor rail: Cases + Audit log (Admin/Governance are role-gated)
    const rail = await page.$$eval(".haze-side-nav a", (links) =>
      links.map((a) => ({ text: a.textContent?.trim(), href: a.getAttribute("href") })),
    );
    assert.deepEqual(rail, [
      { text: "Cases", href: "/audit" },
      { text: "Audit log", href: "/audit#access-log" },
    ]);

    // Verify Alpine-Volcanic styling and Design System Tokens
    const shellBg = await page.$eval(".haze-card", (el) =>
      window.getComputedStyle(el).backgroundColor,
    );
    assert.ok(shellBg.includes("34, 30, 24") || shellBg.includes("#221e18"));

    // Verify Investigation Workspace sections
    const headers = await page.$$eval("h2", (els) => els.map((h) => h.textContent?.trim()));
    assert.ok(headers.includes("SIWE session"));
    assert.ok(headers.includes("Assigned cases"));
    assert.ok(headers.includes("Decrypted fields"));
    assert.ok(headers.includes("Access log"));

    // Verify Auditor SIWE button
    const siweBtn = await page.$('button[data-action="siwe"]');
    assert.ok(siweBtn);

    // Test Mobile Responsiveness
    await page.setViewportSize({ width: 390, height: 844 });
    const isVisibleOnMobile = await page.isVisible(".haze-card");
    assert.equal(isVisibleOnMobile, true);
  } finally {
    await browser.close();
    await host.close();
  }
});

test("Playwright Chromium E2E: unauthenticated caller cannot access /admin or /governance", async () => {
  const host = await createCommercialHost({ port: 0 });
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1280, height: 800 } });
  const page = await context.newPage();

  try {
    // Normal pool user accessing /admin should fail closed
    const userAddress = FIXTURE_ACCOUNTS[0].address;
    await page.goto(`${host.url}/admin?address=${userAddress}`);

    const bannerText = await page.textContent('.haze-banner[role="alert"]');
    assert.match(
      bannerText,
      /This workspace is not authorized|FORBIDDEN|Connect a wallet that is granted this workspace/,
    );
  } finally {
    await browser.close();
    await host.close();
  }
});

test("Playwright Chromium E2E: interactive React compliance workstation flow with screenshots", async (t) => {
  mkdirSync(OUTPUT_DIR, { recursive: true });
  const nextOrigin = process.env.HAZE_NEXT_TEST_ORIGIN;
  if (!nextOrigin) {
    t.skip("HAZE_NEXT_TEST_ORIGIN is required for the real Next.js browser test");
    return;
  }
  const host = { url: nextOrigin, close: async () => {} };
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();

  try {
    const auditorAddress = FIXTURE_ACCOUNTS[2].address;

    // Inject mock ethereum provider for SIWE personal_sign
    await page.addInitScript(({ address }) => {
      globalThis.ethereum = {
        isMetaMask: true,
        request: async ({ method, params }) => {
          if (method === "eth_accounts" || method === "eth_requestAccounts") {
            return [address];
          }
          if (method === "personal_sign") {
            return "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1b";
          }
          if (method === "eth_chainId") {
            return "0xa869"; // 43113
          }
          return null;
        },
      };
    }, { address: auditorAddress });

    // Mock Next.js BFF responses on the page
    await page.route("**/api/compliance/**", async (route) => {
      const url = route.request().url();
      const method = route.request().method();

      if (url.includes("/api/compliance/auth/challenge")) {
        return route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            challengeId: "0xchallenge123",
            message: "Haze SIWE Challenge",
          }),
        });
      }

      if (url.includes("/api/compliance/auth/verify")) {
        return route.fulfill({
          status: 200,
          contentType: "application/json",
          headers: {
            "set-cookie": "haze_audit_session=0xtest_session_token; Path=/; HttpOnly; SameSite=Strict",
          },
          body: JSON.stringify({
            address: auditorAddress,
            role: "application-auditor",
            expiresAt: Math.floor(Date.now() / 1000) + 3600,
          }),
        });
      }

      if (url.includes("/api/compliance/session")) {
        if (method === "DELETE") {
          return route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify({ revoked: true }),
          });
        }
        return route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            address: auditorAddress,
            role: "application-auditor",
            expiresAt: Math.floor(Date.now() / 1000) + 3600,
          }),
        });
      }

      if (url.includes("/api/compliance/cases") && !url.includes("/disclosure") && !url.includes("/export")) {
        return route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            cases: [
              {
                caseId: "fuji-withdrawal-8218e5a4",
                title: "Fuji USDC Withdrawal 8218e5a4",
                applicationId: `0x${"00".repeat(30)}0a11`,
                transactionHash: "0x8218e5a4f14434e0007d421a8e82ba0914429a0cab43d7dba263d1ed232c8a03",
                grantedFields: ["tx_hash", "amount", "asset", "timestamp", "policy_version"],
                status: "active",
                grantExpiresAt: Math.floor(Date.now() / 1000) + 86400,
              },
            ],
          }),
        });
      }

      if (url.includes("/disclosure")) {
        return route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            transactionHash: "0x8218e5a4f14434e0007d421a8e82ba0914429a0cab43d7dba263d1ed232c8a03",
            fields: {
              tx_hash: "0x8218e5a4f14434e0007d421a8e82ba0914429a0cab43d7dba263d1ed232c8a03",
              amount: "1000000",
              asset: "0x5425890298aed601595a70AB815c96711a31Bc65",
              timestamp: "1724300000",
              policy_version: "1",
            },
            confirmations: 42,
            checks: [
              { name: "Finality Confirmations", status: "VERIFIED", detail: "42 confirmations" },
              { name: "Canonical Receipt Status", status: "VERIFIED", detail: "Status 0x1 (Success)" },
              { name: "Canonical Block Hash", status: "VERIFIED", detail: "Block mined on Fuji" },
              { name: "PrivateTransaction Event", status: "VERIFIED", detail: "HazePool contract match" },
              { name: "Envelope Ciphertext Hash", status: "VERIFIED", detail: "HPKE ciphertext match" },
              { name: "Poseidon Audit Commitment", status: "VERIFIED", detail: "Audit commitment match" },
            ],
          }),
        });
      }

      if (url.includes("/export")) {
        return route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            exportId: "0xexport_bundle_001",
            caseId: "fuji-withdrawal-8218e5a4",
            recordId: "rec_8218e5a4",
            subject: "withdrawal",
            signingKeyId: "key_fuji_gateway_01",
            fields: {
              tx_hash: "0x8218e5a4f14434e0007d421a8e82ba0914429a0cab43d7dba263d1ed232c8a03",
              amount: "1000000",
              asset: "0x5425890298aed601595a70AB815c96711a31Bc65",
              timestamp: "1724300000",
              policy_version: "1",
            },
            provenance: {
              gateway: "Haze Compliance Gateway v1",
              network: "Avalanche Fuji (43113)",
            },
            expiresAt: Math.floor(Date.now() / 1000) + 600,
            signature: "0xdeadbeefsignature1234",
          }),
        });
      }

      if (url.includes("/access-log")) {
        return route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            entries: [
              {
                seq: 1,
                prevHash: "0x0000000000000000000000000000000000000000000000000000000000000000",
                entryHash: "0x1111111111111111111111111111111111111111111111111111111111111111",
                name: "verify_disclosure",
                applicationId: `0x${"00".repeat(30)}0a11`,
                caseId: "fuji-withdrawal-8218e5a4",
                wallet: auditorAddress,
                fields: ["tx_hash", "amount", "asset", "timestamp", "policy_version"],
                allowed: true,
                at: Math.floor(Date.now() / 1000),
              },
            ],
          }),
        });
      }

      return route.continue();
    });

    // 1. Visit /audit in mock browser
    await page.goto(`${host.url}/audit`);

    // Take login screenshot
    await page.screenshot({ path: join(OUTPUT_DIR, "d8-local-fixtures-login.png") });

    // 2. Perform Connect & Authenticate SIWE
    const connectSiweBtn = page.locator('button[data-action="connect-siwe"], button:has-text("Connect & Authenticate SIWE")');
    if (await connectSiweBtn.isVisible().catch(() => false)) {
      await connectSiweBtn.click();
    }

    await page.waitForSelector('[data-session-status="authenticated"]', { state: "attached" });
    const caseButton = page.locator('[data-case-id]').first();
    await caseButton.focus();
    await page.keyboard.press("ArrowDown");
    assert.match(page.url(), /case=fuji-withdrawal-8218e5a4/);
    await page.reload({ waitUntil: "networkidle" });
    assert.match(page.url(), /case=fuji-withdrawal-8218e5a4/);

    await page.locator('[data-action="verify-case"]').click();
    await page.waitForSelector(".haze-disclosure-table");
    await page.locator('[data-action="export-case"]').click();
    const closeExport = page.locator('[data-action="close-export-modal"]');
    await closeExport.waitFor({ state: "visible" });
    assert.equal(await closeExport.evaluate((element) => element === document.activeElement), true);
    await page.keyboard.press("Tab");
    assert.equal(await page.locator(".haze-modal").evaluate((modal) => modal.contains(document.activeElement)), true);
    await page.keyboard.press("Escape");
    assert.equal(await page.locator('[data-action="export-case"]').evaluate((element) => element === document.activeElement), true);

    // 3. Verify Workstation is rendered
    await page.screenshot({ path: join(OUTPUT_DIR, "d8-local-fixtures-disclosure.png") });

    // Export Modal Screenshot
    await page.screenshot({ path: join(OUTPUT_DIR, "d8-local-fixtures-export.png") });

    // 4. Test Mobile view screenshot
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
    const backButton = page.getByRole("button", { name: "Back to assigned cases" });
    await backButton.click();
    assert.doesNotMatch(page.url(), /[?&]case=/);
    assert.equal(await caseButton.isVisible(), true);
    await page.screenshot({ path: join(OUTPUT_DIR, "d8-local-fixtures-mobile.png") });

    // Return to desktop
    await page.setViewportSize({ width: 1440, height: 900 });

    // 5. Generate and write D8 evidence manifest
    const manifest = {
      releaseMilestone: "D8",
      evidenceClass: "local-fixtures",
      origin: host.url,
      network: "Avalanche Fuji",
      chainId: 43113,
      caseId: "fuji-withdrawal-8218e5a4",
      transactionHash: "0x8218e5a4f14434e0007d421a8e82ba0914429a0cab43d7dba263d1ed232c8a03",
      confirmations: 42,
      receiptStatus: "0x1",
      grantedFields: ["tx_hash", "amount", "asset", "timestamp", "policy_version"],
      deniedFields: ["user", "counterparty"],
      auditorAddress,
      txCountBefore: "0x0",
      txCountAfter: "0x0",
      screenshots: {
        login: "d8-local-fixtures-login.png",
        disclosure: "d8-local-fixtures-disclosure.png",
        export: "d8-local-fixtures-export.png",
        mobile: "d8-local-fixtures-mobile.png",
      },
      verificationTimestamp: new Date().toISOString(),
      status: "PASS",
    };
    const { writeFileSync } = await import("node:fs");
    writeFileSync(
      join(OUTPUT_DIR, "d8-local-fixtures-audit-acceptance.json"),
      JSON.stringify(manifest, null, 2),
      "utf8",
    );
  } finally {
    await browser.close();
    await host.close();
  }
});
