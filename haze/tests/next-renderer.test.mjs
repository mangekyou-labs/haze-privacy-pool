import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { createHazeSite } from "../web/packages/ui/src/site.ts";
import { renderHazeFragment, renderHazePage } from "../web/packages/ui/src/html.ts";

const site = createHazeSite({
  role: "pool-user",
  applicationId: `0x${"00".repeat(30)}0a11`,
});

test("Next layout imports only global application styles", () => {
  const layout = readFileSync(new URL("../web/apps/haze/app/layout.tsx", import.meta.url), "utf8");
  assert.match(layout, /packages\/ui\/src\/theme\.css/);
  assert.match(layout, /packages\/ui\/fonts\/plex\.css/);
  assert.doesNotMatch(layout, /dangerouslySetInnerHTML|<script\b/i);
});

test("Next CSP permits the framework bootstrap, WebAssembly proving, and Vercel Blob store proving artifacts", () => {
  const nextConfig = readFileSync(new URL("../web/apps/haze/next.config.ts", import.meta.url), "utf8");
  assert.match(nextConfig, /script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' 'unsafe-eval'/);
  assert.match(nextConfig, /connect-src[^;]*https:\/\/\*\.public\.blob\.vercel-storage\.com/);
  assert.match(nextConfig, /connect-src[^;]*https:\/\/\*\.vercel-storage\.com/);
});

test("Next fragment contains application markup without document or script elements", () => {
  const fragment = renderHazeFragment(site, "/shield", { mode: "fuji-browser" });
  assert.match(fragment, /class="haze-shell"/);
  assert.doesNotMatch(fragment, /<!doctype|<html\b|<head\b|<body\b|<script\b/i);
});

test("standalone renderer retains the complete document, stylesheets, and client scripts", () => {
  const document = renderHazePage(site, "/shield", { live: true });
  assert.match(document, /^<!DOCTYPE html>/);
  assert.match(document, /<html lang="en">/);
  assert.match(document, /<link rel="stylesheet" href="\/theme\.css">/);
  assert.match(document, /<link rel="stylesheet" href="\/fonts\/plex\.css">/);
  assert.match(document, /<script src="\/client\.js" defer><\/script>/);
  assert.match(document, /<script src="\/shield-live\.js" defer><\/script>/);
});

test("Fuji browser mode exposes one mount slot and no legacy transaction controls", () => {
  for (const path of ["/shield", "/withdraw"]) {
    const fragment = renderHazeFragment(site, path, { mode: "fuji-browser" });
    assert.equal(fragment.match(/id="fuji-browser-transaction-root"/g)?.length, 1);
    assert.match(fragment, /data-network>Fuji · 43113/);
    assert.doesNotMatch(fragment, /data-action="connect"|<form\b|KEYS_MISSING|operator-demo|<script\b/i);
  }
});
