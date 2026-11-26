/** Playwright desktop (1280px) and mobile (390px) density walk against deployed production.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";
import { PRODUCTION_URL } from "./production-origin.mjs";

const ROOT = dirname(fileURLToPath(import.meta.url));
const ORIGIN = process.env.HAZE_NEXT_ORIGIN ?? PRODUCTION_URL;
const OUT = join(ROOT, "../output/qa");

mkdirSync(join(OUT, "desktop"), { recursive: true });
mkdirSync(join(OUT, "mobile"), { recursive: true });

const ROUTES = [
  "/overview",
  "/shield",
  "/swap",
  "/send",
  "/withdraw",
  "/history",
  "/admin",
  "/compliance",
];

const VIEWPORTS = [
  { name: "desktop", width: 1280, height: 800, isMobile: false },
  { name: "mobile", width: 390, height: 844, isMobile: true },
];

console.log(`[DENSITY WALK] Auditing origin ${ORIGIN}...`);

const browser = await chromium.launch({ headless: true });
const results = {
  origin: ORIGIN,
  timestamp: new Date().toISOString(),
  viewports: {},
};

for (const vp of VIEWPORTS) {
  console.log(`\n[DENSITY WALK] Testing viewport: ${vp.name} (${vp.width}x${vp.height})...`);
  const context = await browser.newContext({
    viewport: { width: vp.width, height: vp.height },
    isMobile: vp.isMobile,
  });
  const page = await context.newPage();
  const vpResults = {};

  for (const route of ROUTES) {
    const url = `${ORIGIN}${route}`;
    await page.goto(url, { waitUntil: "networkidle" }).catch(async () => {
      await page.waitForLoadState("domcontentloaded");
    });

    const screenshotPath = join(OUT, vp.name, `${route.replace(/^\//, "") || "root"}.png`);
    await page.screenshot({ path: screenshotPath, fullPage: false });

    // Verify density CSS rules if elements exist
    const densityChecks = await page.evaluate(() => {
      const checks = {};
      const preview = document.querySelector(".haze-preview");
      if (preview) {
        const style = window.getComputedStyle(preview);
        checks.previewMarginBottom = style.marginBottom;
      }

      const textInput = document.querySelector("input:not(.haze-amount), .haze-field:not(.haze-amount-field) input, select");
      if (textInput) {
        const style = window.getComputedStyle(textInput);
        checks.textInputMinHeight = style.minHeight;
        checks.textInputPadding = `${style.paddingTop} ${style.paddingRight} ${style.paddingBottom} ${style.paddingLeft}`;
      }

      const amountInput = document.querySelector("input.haze-amount");
      if (amountInput) {
        const style = window.getComputedStyle(amountInput);
        checks.amountInputMinHeight = style.minHeight;
        checks.amountInputPadding = `${style.paddingTop} ${style.paddingRight} ${style.paddingBottom} ${style.paddingLeft}`;
      }

      const amountContainer = document.querySelector(".haze-amount-field");
      if (amountContainer) {
        const style = window.getComputedStyle(amountContainer);
        checks.amountContainerPadding = `${style.paddingTop} ${style.paddingRight} ${style.paddingBottom} ${style.paddingLeft}`;
      }
      // Check horizontal overflow
      checks.hasHorizontalOverflow = document.documentElement.scrollWidth > window.innerWidth;

      return checks;
    });

    console.log(`  ✓ ${route} -> ${screenshotPath} | checks:`, densityChecks);
    vpResults[route] = {
      status: "ok",
      screenshot: screenshotPath,
      checks: densityChecks,
    };
  }

  results.viewports[vp.name] = vpResults;
  await context.close();
}

await browser.close();

const reportPath = join(OUT, "density-walk-report.json");
writeFileSync(reportPath, JSON.stringify(results, null, 2) + "\n");
console.log(`\n[DENSITY WALK] Density audit complete! Report written to ${reportPath}`);
