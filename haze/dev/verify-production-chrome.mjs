import { chromium } from "playwright";
import { mkdirSync } from "node:fs";
import { join } from "node:path";

import { PRODUCTION_URL } from "./production-origin.mjs";

const PROD_URL = PRODUCTION_URL;
const OUTPUT_DIR = join(process.cwd(), "haze/output/playwright");
mkdirSync(OUTPUT_DIR, { recursive: true });

async function run() {
  console.log("Launching browser for live production verification...");
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1280, height: 900 },
  });
  const page = await context.newPage();

  console.log("Navigating to /shield on production...");
  await page.goto(`${PROD_URL}/shield`, { waitUntil: "networkidle" });
  await page.screenshot({ path: join(OUTPUT_DIR, "production-consumer-shield.png"), fullPage: true });

  console.log("Opening wallet overlay on production...");
  const connectBtn = page.locator('[data-action="connect"]').first();
  if (await connectBtn.isVisible()) {
    await connectBtn.click();
    await page.waitForTimeout(500);
    await page.screenshot({ path: join(OUTPUT_DIR, "production-consumer-wallet-overlay.png"), fullPage: true });
    // Close overlay
    const closeBtn = page.locator('.haze-overlay-header button').first();
    if (await closeBtn.isVisible()) await closeBtn.click();
  }

  console.log("Navigating to /withdraw on production...");
  await page.goto(`${PROD_URL}/withdraw`, { waitUntil: "networkidle" });
  await page.screenshot({ path: join(OUTPUT_DIR, "production-consumer-withdraw.png"), fullPage: true });

  console.log("Navigating to /audit on production...");
  await page.goto(`${PROD_URL}/audit`, { waitUntil: "networkidle" });
  await page.screenshot({ path: join(OUTPUT_DIR, "production-consumer-audit.png"), fullPage: true });

  await browser.close();
  console.log("Production screenshots captured successfully in haze/output/playwright/");
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
