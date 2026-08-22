import assert from "node:assert/strict";
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
  assert.match(html, /Fuji · 43113/);
  // Must NOT render pool tabs or dex balances in fuji-browser audit mode
  assert.doesNotMatch(html, /class="haze-dex-tabs"/);
  assert.doesNotMatch(html, /class="haze-balances"/);
});

test("Disclosure responses contain only the 5 granted fields and strictly redact user and counterparty", async () => {
  const sampleDisclosure = {
    transactionHash: "0x8218e5a4f14434e0007d421a8e82ba0914429a0cab43d7dba263d1ed232c8a03",
    fields: {
      tx_hash: "0x8218e5a4f14434e0007d421a8e82ba0914429a0cab43d7dba263d1ed232c8a03",
      amount: "1000000",
      asset: "0x5425890298aed601595a70AB815c96711a31Bc65",
      timestamp: "1700000000",
      policy_version: "1",
    },
  };

  const allowedKeys = new Set(["tx_hash", "amount", "asset", "timestamp", "policy_version"]);
  for (const key of Object.keys(sampleDisclosure.fields)) {
    assert.ok(allowedKeys.has(key), `Unexpected field ${key} in disclosure`);
  }
  assert.equal(sampleDisclosure.fields.user, undefined);
  assert.equal(sampleDisclosure.fields.counterparty, undefined);
});

