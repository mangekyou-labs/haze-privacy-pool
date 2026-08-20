import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { createHost, fujiGate } from "../dev/host.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const WALLET = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf";

async function withHost(fn, options = {}) {
  const host = await createHost({
    profile: "local",
    hostname: "127.0.0.1",
    port: 0,
    ...options,
  });
  try {
    return await fn(host);
  } finally {
    await host.close();
  }
}

async function json(host, path, body, method = "POST") {
  const response = await fetch(new URL(path, host.url), {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = { raw: text };
  }
  return { response, body: parsed, text };
}

test("hosted UI lives in haze/dev and does not add a fourth Node package", () => {
  const pkg = JSON.parse(readFileSync(join(HAZE_ROOT, "package.json"), "utf8"));
  assert.deepEqual(pkg.workspaces, ["apps/*", "sdk/typescript", "web/apps/*", "web/packages/*"]);
  assert.equal(pkg.scripts.host, "node --experimental-strip-types dev/host.mjs");
  assert.equal(existsSync(join(HAZE_ROOT, "dev/host.mjs")), true);
});

test("fuji profile fail-closes when broadcast addresses and proving keys are missing", () => {
  const gate = fujiGate();
  assert.equal(gate.ready, false);
  assert.ok(gate.reasons.includes("broadcast:false"));
  assert.ok(gate.reasons.includes("KEYS_MISSING"));
  assert.ok(gate.reasons.includes("missing-HazePool"));
  assert.equal(gate.deployment.chainId, 43113);
  assert.equal(gate.deployment.usdc.toLowerCase(), "0x5425890298aed601595a70ab815c96711a31bc65");
});

test("createHost fuji throws the same fail-closed gate", async () => {
  await assert.rejects(() => createHost({ profile: "fuji", port: 0 }), (error) => {
    assert.equal(error.code, "FUJI_NOT_READY");
    assert.ok(error.reasons.includes("KEYS_MISSING"));
    return true;
  });
});

test("local host serves the alpine-volcanic DEX with CSP and a skip link", async () => {
  await withHost(async (host) => {
    const response = await fetch(new URL("/shield", host.url));
    const html = await response.text();
    assert.equal(response.status, 200);
    assert.match(response.headers.get("content-security-policy") ?? "", /default-src 'self'/);
    assert.match(html, /Skip to content/);
    assert.match(html, /IBM Plex Sans/);
    assert.match(html, /#16130f/i);
    assert.match(html, /Sign and submit/);
    assert.match(html, /Connect wallet/);
    assert.match(html, /window.ethereum|eth_requestAccounts/);
    assert.doesNotMatch(html, /stellar|soroban|freighter/i);
    assert.doesNotMatch(html, /0x0000000000000000000000000000000000000000000000000000000000000001/);
  });
});

test("local DEX connect, public preview, shield, and private note stay in-process", async () => {
  await withHost(async (host) => {
    const wrong = await json(host, "/api/connect", { address: WALLET, chainId: 1 });
    assert.equal(wrong.body.walletStatus, "wrong-chain");

    const connected = await json(host, "/api/connect", { address: WALLET, chainId: 43113 });
    assert.equal(connected.body.walletStatus, "connected");
    assert.equal(connected.body.role, "pool-user");

    const preview = await json(host, "/api/preview", { kind: "direct-shield" });
    assert.equal(preview.body.canSign, true);
    assert.ok(preview.body.warnings.some((item) => item.fact === "deposit-amount"));
    assert.ok(preview.body.warnings.every((item) => item.visibility === "public"));
    const previewPage = await (await fetch(new URL("/shield", host.url))).text();
    assert.match(previewPage, /<button[^>]*data-action="run"[^>]*>\s*Sign and submit/);

    const run = await json(host, "/api/run", { kind: "direct-shield" });
    assert.equal(run.body.phase, "finalized");
    assert.match(run.body.txHash ?? "", /^0x[0-9a-fA-F]{64}$/);
    assert.equal(run.body.notes[0].visibility, "private");

    const page = await (await fetch(new URL("/history", host.url))).text();
    assert.match(page, /private/i);
    assert.match(page, /0x[0-9a-fA-F]{64}/);
    assert.match(page, /local in-process/);
  });
});

test("hosted DEX rejects a foreign haze1 address and early emergency execute", async () => {
  await withHost(async (host) => {
    await json(host, "/api/connect", { address: WALLET, chainId: 43113 });
    await json(host, "/api/preview", { kind: "private-send" });
    const foreign = await json(host, "/api/run", { kind: "private-send", recipient: "foreign" });
    assert.equal(foreign.body.code, "APPLICATION_MISMATCH");

    await json(host, "/api/preview", { kind: "emergency-exit" });
    const requested = await json(host, "/api/run", { kind: "emergency-exit", step: "request" });
    assert.ok(requested.body.requestId);
    const early = await json(host, "/api/run", { kind: "emergency-exit", step: "execute" });
    assert.equal(early.body.code, "TIMELOCK");
  });
});

test("hosted wipe then recover restores the same spendable note", async () => {
  await withHost(async (host) => {
    await json(host, "/api/connect", { address: WALLET, chainId: 43113 });
    const recovered = await json(host, "/api/recover", {});
    assert.equal(recovered.body.notes.length, 1);
    const commitment = recovered.body.notes[0].commitment;
    await json(host, "/api/wipe", {});
    const wiped = await json(host, "/api/state", undefined, "GET");
    assert.equal(wiped.body.notes.length, 0);
    const again = await json(host, "/api/recover", {});
    assert.equal(again.body.notes[0].commitment, commitment);
  });
});

test("portal routes reject a pool-user and accept isolated admin, auditor, and governance flows", async () => {
  await withHost(async (host) => {
    await json(host, "/api/connect", { address: WALLET, chainId: 43113 });
    const denied = await fetch(new URL("/admin", host.url));
    const deniedHtml = await denied.text();
    assert.equal(denied.status, 403);
    assert.match(deniedHtml, /FORBIDDEN/);

    const adminSign = await json(host, "/api/portal/signin", { role: "application-admin" });
    assert.equal(adminSign.body.ok, true);
    const adminPage = await fetch(new URL("/admin", host.url));
    const adminHtml = await adminPage.text();
    assert.equal(adminPage.status, 200);
    assert.match(adminHtml, /Application administration/);
    assert.doesNotMatch(adminHtml, /FORBIDDEN/);
    const registered = await json(host, "/api/portal/manifest", {});
    assert.equal(registered.response.status, 200);
    assert.match(registered.body.manifestHash ?? "", /^0x/i);
    const delegated = await json(host, "/api/portal/delegate", {});
    assert.equal(delegated.body.revoked, false);

    const auditor = await json(host, "/api/portal/signin", { role: "application-auditor" });
    assert.equal(auditor.body.ok, true);
    const auditPage = await fetch(new URL("/audit", host.url));
    const auditHtml = await auditPage.text();
    assert.equal(auditPage.status, 200);
    assert.match(auditHtml, /Investigation/);
    assert.doesNotMatch(auditHtml, /FORBIDDEN/);
    const siwe = await json(host, "/api/portal/siwe/start", {});
    assert.ok(siwe.body.nonce);
    await json(host, "/api/portal/siwe/complete", { nonce: siwe.body.nonce });
    const exported = await json(host, "/api/portal/export", { fields: ["commitment"] });
    assert.equal(exported.response.status, 200);
    const overreach = await json(host, "/api/portal/export", { fields: ["plaintext"] });
    assert.equal(overreach.body.code, "UNAUTHORIZED");

    const gov = await json(host, "/api/portal/signin", { role: "super-auditor" });
    assert.equal(gov.body.ok, true);
    const govPage = await fetch(new URL("/governance", host.url));
    const govHtml = await govPage.text();
    assert.equal(govPage.status, 200);
    assert.match(govHtml, /Haze governance/);
    assert.doesNotMatch(govHtml, /FORBIDDEN/);
    const preview = await json(host, "/api/governance/preview", {});
    assert.ok(preview.body.id);
    const early = await json(host, "/api/governance/execute", { id: preview.body.id });
    assert.equal(early.body.code, "TIMELOCK");
  });
});

test("glossary and mobile layout stay public-copy safe", async () => {
  await withHost(async (host) => {
    const glossary = await (await fetch(new URL("/glossary", host.url))).text();
    assert.match(glossary, /visible on chain/i);
    assert.match(glossary, /Public deposit amount/);
    assert.doesNotMatch(glossary, /private swap/i);
    const mobile = await fetch(new URL("/shield?width=390", host.url));
    const html = await mobile.text();
    assert.match(html, /data-layout="stack"/);
  });
});
