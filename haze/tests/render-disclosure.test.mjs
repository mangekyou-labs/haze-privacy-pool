import assert from "node:assert/strict";
import test from "node:test";
import { DEFAULT_HAZE_AUDIT_PUBLIC_KEY, DEFAULT_HAZE_DISCLOSURE_ORIGIN, requestFujiDisclosure } from "../sdk/typescript/src/render-disclosure.ts";

test("DEFAULT_HAZE_DISCLOSURE_ORIGIN is the official Render disclosure origin", () => {
  assert.equal(DEFAULT_HAZE_DISCLOSURE_ORIGIN, "https://haze-fuji-disclosure-uegs.onrender.com");
});

test("DEFAULT_HAZE_AUDIT_PUBLIC_KEY is the Fuji v2 auditor key", () => {
  assert.equal(DEFAULT_HAZE_AUDIT_PUBLIC_KEY, "0x1b9b5de7274e874632960720219be873afa5fd0249347e3900763d8a774c2546");
});

test("Render cold starts use bounded retries and never a local fallback", async () => {
  const urls = []; let attempts = 0;
  const result = await requestFujiDisclosure({
    origin: "https://haze-disclosure.onrender.com", body: { transactionHash: "0x1" }, delaysMs: [0, 0], sleep: async () => {},
    fetch: async (url) => { urls.push(url); attempts += 1; return attempts < 3 ? new Response('{"code":"UNAVAILABLE"}', { status: 503 }) : Response.json({ fields: { amount: "1" } }); },
  });
  assert.deepEqual(result, { fields: { amount: "1" } });
  assert.equal(urls.length, 3); assert.ok(urls.every((url) => url.startsWith("https://haze-disclosure.onrender.com/")));
  await assert.rejects(() => requestFujiDisclosure({ origin: "http://localhost:10000", body: {}, fetch }), /INVALID_DISCLOSURE_ORIGIN/);
});

test("non-retryable stable errors surface immediately", async () => {
  let attempts = 0;
  await assert.rejects(() => requestFujiDisclosure({ origin: "https://api.example.com", body: {}, fetch: async () => { attempts += 1; return new Response('{"code":"UNAUTHORIZED_FIELD"}', { status: 400 }); } }), /UNAUTHORIZED_FIELD/);
  assert.equal(attempts, 1);
});
