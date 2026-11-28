import assert from "node:assert/strict";
import test from "node:test";
import { renderHazePage } from "../web/packages/ui/src/html.ts";
import { createHazeSite } from "../web/packages/ui/src/site.ts";
import {
  ComplianceMemoryStore,
  DEDICATED_AUDITOR,
  FUJI_CHAIN_ID,
  LIVE_APP_ID,
  LIVE_POSEIDON_POOL,
  REQUIRED_CONFIRMATIONS,
} from "../sdk/typescript/src/compliance-service.ts";

test("compliance portal renders the audit workspace with session, cases, decrypted fields, and access log", () => {
  const site = createHazeSite({ role: "application-auditor", applicationId: LIVE_APP_ID });
  const html = renderHazePage(site, "/audit", {
    audit: {
      boundWallet: DEDICATED_AUDITOR,
      cases: [{ caseId: "case-1", title: "Fuji Withdrawal 0xaaaa…aaaa" }],
      access: [
        { action: "login", allowed: true },
        { action: "export", allowed: false },
      ],
    },
  });

  assert.match(html, /data-workspace="audit"/);
  assert.match(html, /SIWE session/);
  assert.match(html, /Assigned cases/);
  assert.match(html, /Decrypted fields/);
  assert.match(html, /Access log/);
  assert.match(html, new RegExp(DEDICATED_AUDITOR, "i"));
  assert.match(html, /case-1/);
  assert.match(html, /login allowed/);
  assert.match(html, /export denied/);
});

test("disclosed record displays exactly the 5 granted fields and zero user/counterparty leaks", () => {
  const GRANTED = ["amount", "asset", "policy_version", "timestamp", "tx_hash"];

  // The store discloses only the 5 granted fields for a ready case.
  const store = new ComplianceMemoryStore();
  const txHash = "0x" + "bb".repeat(32);
  const caseItem = store.upsertWithdrawalCase({
    chainId: FUJI_CHAIN_ID,
    pool: LIVE_POSEIDON_POOL,
    applicationId: LIVE_APP_ID,
    transactionHash: txHash,
    logIndex: 0,
    blockNumber: 5000,
    currentBlockNumber: 5000 + REQUIRED_CONFIRMATIONS + 1,
    witnessData: {
      auditRecord: {
        facts: { publicAmount: 2_500_000, timestamp: 1724000000, applicationPolicyVersion: 1 },
      },
    },
  });
  assert.equal(caseItem.caseState, "ready");
  const disclosure = store.discloseCase(caseItem.caseId, DEDICATED_AUDITOR);
  assert.deepEqual(Object.keys(disclosure.fields).sort(), GRANTED);

  // The workspace renders those rows and nothing else.
  const site = createHazeSite({ role: "application-auditor", applicationId: LIVE_APP_ID });
  const html = renderHazePage(site, "/audit", {
    audit: {
      boundWallet: DEDICATED_AUDITOR,
      cases: [{ caseId: caseItem.caseId, title: "Fuji Withdrawal 0xbbbb…bbbb" }],
      rows: Object.entries(disclosure.fields).map(([field, value]) => ({ field, value: String(value) })),
    },
  });

  const rendered = [...html.matchAll(/data-audit-row data-field="([^"]+)"/g)].map((m) => m[1]).sort();
  assert.deepEqual(rendered, GRANTED);
  assert.doesNotMatch(html, /data-field="user"/i);
  assert.doesNotMatch(html, /data-field="counterparty"/i);
  assert.doesNotMatch(html, /data-field="memo"/i);
});

test("/admin and /governance remain fail-closed without valid administrative/governance sessions", () => {
  const poolUserSite = createHazeSite({ role: "pool-user", applicationId: LIVE_APP_ID });
  assert.equal(poolUserSite.decide("/admin").ok, false);
  assert.equal(poolUserSite.decide("/admin").code, "FORBIDDEN");
  assert.equal(poolUserSite.decide("/governance").ok, false);
  assert.equal(poolUserSite.decide("/governance").code, "FORBIDDEN");

  const auditorSite = createHazeSite({ role: "application-auditor", applicationId: LIVE_APP_ID });
  assert.equal(auditorSite.decide("/admin").ok, false);
  assert.equal(auditorSite.decide("/admin").code, "FORBIDDEN");
  assert.equal(auditorSite.decide("/governance").ok, false);
  assert.equal(auditorSite.decide("/governance").code, "FORBIDDEN");
  assert.equal(auditorSite.decide("/audit").ok, true);
});

test("audit workspace export requests only the granted commitment field", () => {
  const site = createHazeSite({ role: "application-auditor", applicationId: LIVE_APP_ID });
  const html = renderHazePage(site, "/audit", {
    audit: {
      boundWallet: DEDICATED_AUDITOR,
      cases: [{ caseId: "case-1", title: "Review" }],
    },
  });

  assert.match(html, /data-action="export" data-field="commitment">Export granted fields</);
});
