import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { POST as challengeHandler } from "../web/apps/haze/app/api/compliance/auth/challenge/route.ts";
import { POST as verifyHandler } from "../web/apps/haze/app/api/compliance/auth/verify/route.ts";
import { GET as sessionGetHandler, DELETE as sessionDeleteHandler } from "../web/apps/haze/app/api/compliance/session/route.ts";
import { GET as casesHandler } from "../web/apps/haze/app/api/compliance/cases/route.ts";
import { POST as disclosureHandler } from "../web/apps/haze/app/api/compliance/cases/[caseId]/disclosure/route.ts";
import { POST as exportHandler } from "../web/apps/haze/app/api/compliance/cases/[caseId]/export/route.ts";
import { GET as accessLogHandler } from "../web/apps/haze/app/api/compliance/access-log/route.ts";

const APPLICATION_ID = `0x${"00".repeat(30)}0a11`;
const AUDITOR_WALLET = "0x5151515151515151515151515151515151515151";

test("Next.js compliance BFF routes exist and export standard HTTP handlers", () => {
  assert.equal(typeof challengeHandler, "function");
  assert.equal(typeof verifyHandler, "function");
  assert.equal(typeof sessionGetHandler, "function");
  assert.equal(typeof sessionDeleteHandler, "function");
  assert.equal(typeof casesHandler, "function");
  assert.equal(typeof disclosureHandler, "function");
  assert.equal(typeof exportHandler, "function");
  assert.equal(typeof accessLogHandler, "function");
});

test("BFF forwarder returns 503 when disclosure service is unreachable", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new Error("Connection refused");
  };

  try {
    const req = new Request("http://localhost:3000/api/compliance/auth/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        wallet: AUDITOR_WALLET,
        applicationId: APPLICATION_ID,
      }),
    });

    const res = await challengeHandler(req);
    assert.equal(res.status, 503);
    const json = await res.json();
    assert.equal(json.code, "UNAVAILABLE");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("BFF verify handler sets HttpOnly Secure session cookie on successful auth", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    return new Response(
      JSON.stringify({
        token: "0xsecret_session_token_1234",
        address: AUDITOR_WALLET,
        applicationId: APPLICATION_ID,
        role: "application-auditor",
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  };

  try {
    const req = new Request("http://localhost:3000/api/compliance/auth/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        challengeId: "0xchallenge123",
        message: "SIWE message",
        signature: "0xsignature123",
      }),
    });

    const res = await verifyHandler(req);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.address, AUDITOR_WALLET);
    assert.equal(body.role, "application-auditor");
    assert.equal(body.token, undefined); // Token is not exposed in body

    const setCookie = res.headers.get("set-cookie");
    assert.ok(setCookie);
    assert.match(setCookie, /haze_audit_session=0xsecret_session_token_1234/);
    assert.match(setCookie, /HttpOnly/i);
    assert.match(setCookie, /SameSite=Strict/i);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Audit workstation mounting renders full-width compliance card without pool tabs or dex balances", async () => {
  const { renderHazeFragment } = await import("../web/packages/ui/src/html.ts");
  const { createHazeSite } = await import("../web/packages/ui/src/site.ts");

  const site = createHazeSite({
    role: "application-auditor",
    applicationId: APPLICATION_ID,
  });

  const html = renderHazeFragment(site, "/audit", { mode: "fuji-browser" });
  assert.match(html, /id="haze-audit-workstation-root"/);
  assert.match(html, /data-card="compliance-audit"/);
  assert.match(html, /data-network="avalanche"[^>]*>Avalanche/);
  assert.doesNotMatch(html, /Fuji · 43113/);
  // Must NOT render pool tabs or dex balances in fuji-browser audit mode
  assert.doesNotMatch(html, /class="haze-dex-tabs"/);
  assert.doesNotMatch(html, /class="haze-balances"/);
  assert.doesNotMatch(html, /Connect a wallet that is granted this workspace/);
});

test("GET /api/compliance/session without a session cookie returns 401 and does not call upstream", async () => {
  let fetchCalled = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    fetchCalled += 1;
    return new Response(JSON.stringify({ address: AUDITOR_WALLET }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  };
  try {
    const res = await sessionGetHandler(new Request("http://localhost:3000/api/compliance/session"));
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.code, "UNAUTHENTICATED");
    assert.equal(fetchCalled, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("GET /api/compliance/session with cookie aborts hung disclosure fetch as 503 UNAVAILABLE", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (_url, init) =>
    new Promise((_resolve, reject) => {
      assert.ok(init?.signal, "disclosure fetch must pass AbortSignal.timeout");
      // AbortSignal.timeout uses an unref'd timer. A real hung fetch holds an open
      // socket that keeps the event loop alive; this mock must do the same, or
      // Node exits with the test promise still pending.
      const socket = setInterval(() => {}, 1_000);
      init.signal.addEventListener("abort", () => {
        clearInterval(socket);
        const err = new Error("The operation was aborted");
        err.name = "AbortError";
        reject(err);
      });
    });
  try {
    const req = new Request("http://localhost:3000/api/compliance/session", {
      headers: { cookie: "haze_audit_session=0xstale_token" },
    });
    const res = await sessionGetHandler(req);
    assert.equal(res.status, 503);
    const body = await res.json();
    assert.equal(body.code, "UNAVAILABLE");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("auditor workstation reports loading as a distinct session status and gates SIWE", async () => {
  const client = readFileSync(
    new URL("../web/apps/haze/app/[route]/audit-browser-client.tsx", import.meta.url),
    "utf8",
  );
  assert.match(client, /data-session-status=\{sessionLoading \? "loading" : session \? "authenticated" : "unauthenticated"\}/);
  assert.match(client, /data-session-loading/);
  assert.match(client, /AbortSignal\.timeout\(8_000\)/);
  assert.match(client, /sessionLoading \? \(/);
  assert.match(client, /data-action="connect-siwe"/);
});

test("Disclosure responses contain only the 5 granted fields and strictly redact user and counterparty", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => Response.json({
    transactionHash: `0x${"82".repeat(32)}`,
    authorizedUser: "0xsecret-user",
    fields: { tx_hash: `0x${"82".repeat(32)}`, amount: "1000000", asset: "USDC", timestamp: "1700000000", policy_version: "1", user: "alice", counterparty: "bob", memo: "secret" },
  });
  try {
    const response = await disclosureHandler(new Request("http://localhost/api/compliance/cases/runtime/disclosure", { method: "POST" }), { params: Promise.resolve({ caseId: "runtime" }) });
    const payload = await response.json();
    assert.deepEqual(Object.keys(payload.fields).sort(), ["amount", "asset", "policy_version", "timestamp", "tx_hash"]);
    assert.equal(JSON.stringify(payload).includes("secret-user"), false);
    assert.equal(JSON.stringify(payload).includes("alice"), false);
    assert.equal(JSON.stringify(payload).includes("bob"), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
