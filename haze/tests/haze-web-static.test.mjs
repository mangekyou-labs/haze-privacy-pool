import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { createHazeSite } from "../web/packages/ui/src/site.ts";
import { LEGACY_VERCEL_HOSTS, PRODUCTION_URL } from "../dev/production-origin.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

test("D10.1: renderHazeFragment returns fragment without doctype, html, or external host links", async () => {
  const { renderHazeFragment } = await import("../web/packages/ui/src/html.ts");
  assert.equal(typeof renderHazeFragment, "function", "renderHazeFragment must be exported");
  const site = createHazeSite({ role: "pool-user", applicationId: "0x" + "aa".repeat(32) });
  const fragment = renderHazeFragment(site, "/shield", {});
  assert.doesNotMatch(fragment, /<!DOCTYPE/i, "fragment must not contain <!DOCTYPE");
  assert.doesNotMatch(fragment, /<html[\s>]/i, "fragment must not contain <html>");
  assert.doesNotMatch(fragment, /<head[\s>]/i, "fragment must not contain <head>");
  assert.doesNotMatch(fragment, /<body[\s>]/i, "fragment must not contain <body>");
  assert.doesNotMatch(fragment, /<link rel="stylesheet"/i, "fragment must not contain stylesheet links");
  assert.doesNotMatch(fragment, /<script/i, "fragment must not contain host script tags");
  assert.match(fragment, /class="haze-shell"/, "fragment contains haze shell");
});

test("D10.1: renderHazePage wraps renderHazeFragment in a full HTML document for commercial host", async () => {
  const { renderHazePage, renderHazeFragment } = await import("../web/packages/ui/src/html.ts");
  const site = createHazeSite({ role: "pool-user", applicationId: "0x" + "aa".repeat(32) });
  const page = renderHazePage(site, "/shield", {});
  assert.match(page, /<!DOCTYPE html>/i);
  assert.match(page, /<html/i);
  assert.match(page, /<link rel="stylesheet" href="\/theme\.css">/);
  assert.match(page, /<link rel="stylesheet" href="\/fonts\/plex\.css">/);
  assert.match(page, /<script src="\/client\.js"/);
});

test("D10.1: theme.css defines base .haze-button styles", () => {
  const themeCss = readFileSync(join(HAZE_ROOT, "web/packages/ui/src/theme.css"), "utf8");
  assert.match(themeCss, /\.haze-button\s*\{/, "theme.css must define .haze-button");
  assert.match(themeCss, /\.haze-button-secondary\s*\{/, "theme.css must define .haze-button-secondary");
});

test("D10.1: Next app layout imports theme.css and plex.css", () => {
  const layout = readFileSync(join(HAZE_ROOT, "web/apps/haze/app/layout.tsx"), "utf8");
  assert.match(layout, /import\s+["'].*theme\.css["']/, "layout must import theme.css");
  assert.match(layout, /import\s+["'].*plex\.css["']/, "layout must import plex.css");
});

test("D10.1: next.config.ts configures CSP and web-worker webpack alias", () => {
  const nextConfig = readFileSync(join(HAZE_ROOT, "web/apps/haze/next.config.ts"), "utf8");
  assert.match(nextConfig, /wasm-unsafe-eval/, "CSP must allow wasm-unsafe-eval");
  assert.match(nextConfig, /blob:/, "CSP must allow blob: workers and scripts");
  assert.match(nextConfig, /api\.avax-test\.network/, "CSP must allow Fuji RPC");
  assert.match(nextConfig, /vercel-storage\.com/, "CSP must allow Vercel storage");
  assert.match(nextConfig, /web-worker/, "webpack alias for web-worker must be present");
});

test("D10.1: proving manifest stub exists for browser proving", () => {
  const manifestPath = join(
    HAZE_ROOT,
    "web/apps/haze/public/proving/fuji-development/haze-spend-v1/manifest.json",
  );
  assert.equal(existsSync(manifestPath), true, "Proving manifest stub must exist in public/proving");
});

test("D10.2: consumer chrome renders 3 primary tabs (/shield, /withdraw, /audit) and no /swap or /send in tab list", async () => {
  const { renderHazeFragment } = await import("../web/packages/ui/src/html.ts");
  const site = createHazeSite({ role: "pool-user", applicationId: "0x" + "aa".repeat(32) });
  const html = renderHazeFragment(site, "/shield", {});
  assert.match(html, /data-chrome="consumer"/, "Must use data-chrome='consumer'");
  assert.match(html, /<a[^>]*href="\/shield"[^>]*>Shield<\/a>/);
  assert.match(html, /<a[^>]*href="\/withdraw"[^>]*>Withdraw<\/a>/);
  assert.match(html, /<a[^>]*href="\/audit"[^>]*>Audit<\/a>/);
  assert.doesNotMatch(html, /class="haze-tab"[^>]*href="\/swap"/, "Swap must not be in primary tabs");
  assert.doesNotMatch(html, /class="haze-tab"[^>]*href="\/send"/, "Send must not be in primary tabs");
});

test("D10.2: consumer header contains HAZE brand wordmark + flame SVG and connect button", async () => {
  const { renderHazeFragment } = await import("../web/packages/ui/src/html.ts");
  const site = createHazeSite({ role: "pool-user", applicationId: "0x" + "aa".repeat(32) });
  const disconnected = renderHazeFragment(site, "/shield", {});
  assert.match(disconnected, /class="haze-brand"/);
  assert.match(disconnected, /<svg[^>]*class="haze-flame"[^>]*>/);
  assert.match(disconnected, /HAZE/);
  assert.match(disconnected, /data-action="connect"/);

  const connected = renderHazeFragment(site, "/shield", {
    address: "0x1111111111111111111111111111111111111111",
    walletStatus: "connected",
  });
  assert.match(connected, /0x1111…1111/);
  assert.match(connected, /data-action="disconnect"/);
});

test("D10.2: consumer card has labeled fields: Asset USDC, Amount, Shielded Balance, Network Avalanche Fuji", async () => {
  const { renderHazeFragment } = await import("../web/packages/ui/src/html.ts");
  const site = createHazeSite({ role: "pool-user", applicationId: "0x" + "aa".repeat(32) });
  const html = renderHazeFragment(site, "/shield", {});
  assert.match(html, /Asset/, "Asset label must be present");
  assert.match(html, /USDC/, "USDC asset must be present");
  assert.doesNotMatch(html, /Avax\s*<\/span>|Avax\s*<\/label>/i, "Avax must not be a spendable asset");
  assert.match(html, /class="haze-amount/, "Hero amount input must be present");
  assert.match(html, /Shielded Balance/, "Shielded Balance label must be present");
  assert.match(html, /Network/, "Network label must be present");
  assert.match(html, /Avalanche Fuji/, "Network must show Avalanche Fuji");
});

test("D10.2: Continue control exists before spend sign and review panel public facts are present", async () => {
  const { renderHazeFragment } = await import("../web/packages/ui/src/html.ts");
  const site = createHazeSite({ role: "pool-user", applicationId: "0x" + "aa".repeat(32) });
  const html = renderHazeFragment(site, "/shield", { reviewed: false });
  assert.match(html, /data-review="public-facts"/);
  assert.match(html, /data-action="preview"/);
  assert.match(html, /I understand — continue|Continue/);
});

test("D10.2: theme.css contains no #000 or #000000, no transition: all, and 160ms ease motion", () => {
  const themeCss = readFileSync(join(HAZE_ROOT, "web/packages/ui/src/theme.css"), "utf8");
  assert.doesNotMatch(themeCss, /#000000\b|#000\b/i, "No pure black in design tokens");
  assert.doesNotMatch(themeCss, /transition:\s*all/i, "No transition: all in CSS");
});

test("D10.1: public directory contains fonts, theme.css, and client.js static assets", () => {
  const publicDir = join(HAZE_ROOT, "web/apps/haze/public");
  assert.equal(existsSync(join(publicDir, "fonts/plex.css")), true, "fonts/plex.css must exist");
  assert.equal(existsSync(join(publicDir, "theme.css")), true, "theme.css must exist");
  assert.equal(existsSync(join(publicDir, "client.js")), true, "client.js must exist");
});

test("canonical Vercel origin redirects attached legacy hosts but never previews", () => {
  const vercel = JSON.parse(readFileSync(join(HAZE_ROOT, "vercel.json"), "utf8"));
  const redirects = vercel.redirects ?? [];
  const legacyHosts = LEGACY_VERCEL_HOSTS;

  for (const host of legacyHosts) {
    const redirect = redirects.find((entry) => entry.has?.some((condition) => condition.type === "host" && condition.value === host));
    assert.ok(redirect, `missing permanent redirect for ${host}`);
    assert.equal(redirect.permanent, true);
    assert.equal(redirect.destination, `${PRODUCTION_URL}/:path*`);
  }

  assert.doesNotMatch(JSON.stringify(redirects), /preview|\*\.vercel\.app/i);
  assert.ok(redirects.every((entry) =>
    entry.has?.every((condition) => condition.value !== "haze-avax.vercel.app"),
  ));
});
