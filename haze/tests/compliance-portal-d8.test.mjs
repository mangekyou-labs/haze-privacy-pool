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

test("compliance portal renders 3-column desktop workstation layout with case rail, record panel, and integrity rail", () => {
  const site = createHazeSite({ role: "application-auditor", applicationId: LIVE_APP_ID });
  const txHash = "0x" + "aa".repeat(32);
  const html = renderHazePage(site, "/audit", {
    audit: {
      boundWallet: DEDICATED_AUDITOR,
      cases: [
        {
          caseId: "case-1",
          title: "Fuji Withdrawal 0xaaaa…aaaa",
          transactionHash: txHash,
          caseState: "ready",
          confirmationCount: 12,
          requiredConfirmations: 12,
          canonicalBlockIdentity: "Block #1000 (12/12 confs)",
          readiness: true,
          fields: ["tx_hash", "amount", "asset", "timestamp", "policy_version"],
        },
      ],
      selectedCaseId: "case-1",
      access: [
        { action: "login", allowed: true, timestamp: 1724000000 },
        { action: "verify", allowed: true, caseId: "case-1", timestamp: 1724000010 },
      ],
      chainVerified: true,
      headHash: "0x" + "99".repeat(32),
    },
  });

  assert.match(html, /class="haze-workstation"/);
  assert.match(html, /class="haze-rail-cases"/);
  assert.match(html, /class="haze-panel-record"/);
  assert.match(html, /class="haze-rail-integrity"/);
  assert.match(html, /Assigned Cases/);
  assert.match(html, /Integrity Panel/);
  assert.match(html, /Access History/);
  assert.match(html, /12 confirmations \(12\/12\)/);
  assert.match(html, /data-chain-verified="true"/);
  assert.match(html, /Chain integrity: Verified/);
});

test("disclosed record displays exactly the 5 granted fields and zero user/counterparty leaks", () => {
  const site = createHazeSite({ role: "application-auditor", applicationId: LIVE_APP_ID });
  const txHash = "0x" + "bb".repeat(32);
  const html = renderHazePage(site, "/audit", {
    audit: {
      boundWallet: DEDICATED_AUDITOR,
      cases: [
        {
          caseId: "case-disclosed",
          title: "Fuji Withdrawal 0xbbbb…bbbb",
          transactionHash: txHash,
          caseState: "verified",
          confirmationCount: 15,
          requiredConfirmations: 12,
          readiness: true,
          disclosedRecord: {
            tx_hash: txHash,
            amount: "1.00 USDC",
            asset: "USDC",
            timestamp: "2026-08-22T10:00:00Z",
            policy_version: 1,
          },
        },
      ],
      selectedCaseId: "case-disclosed",
    },
  });

  assert.match(html, /data-disclosed="true"/);
  assert.match(html, /data-field="tx_hash"/);
  assert.match(html, /data-field="amount"/);
  assert.match(html, /data-field="asset"/);
  assert.match(html, /data-field="timestamp"/);
  assert.match(html, /data-field="policy_version"/);

  // Assert absence of user, counterparty, or raw field selectors
  assert.doesNotMatch(html, /data-field="user"/i);
  assert.doesNotMatch(html, /data-field="counterparty"/i);
  assert.doesNotMatch(html, /name="fields"/);
  assert.doesNotMatch(html, /Export overreach/);
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

test("export review modal renders canonical JSON and download trigger", () => {
  const site = createHazeSite({ role: "application-auditor", applicationId: LIVE_APP_ID });
  const exportPayload = {
    case_id: "case-1",
    transaction_hash: "0x" + "cc".repeat(32),
    fields: {
      tx_hash: "0x" + "cc".repeat(32),
      amount: "1.00 USDC",
      asset: "USDC",
      timestamp: "2026-08-22T10:00:00Z",
      policy_version: 1,
    },
    signing_key_id: "haze-fuji-compliance-signer-v1",
    signature: "0x" + "11".repeat(32),
    provenance: { chain_id: 43113, pool: LIVE_POSEIDON_POOL, application_id: LIVE_APP_ID, block_number: 1234, finalized: true },
    timestamp: 1724000000,
  };

  const html = renderHazePage(site, "/audit", {
    audit: {
      boundWallet: DEDICATED_AUDITOR,
      cases: [{ caseId: "case-1", title: "Review", caseState: "verified" }],
      exportModal: {
        caseId: "case-1",
        json: JSON.stringify(exportPayload, null, 2),
      },
    },
  });

  assert.match(html, /class="haze-modal-backdrop"/);
  assert.match(html, /class="haze-modal-dialog"/);
  assert.match(html, /Signed Export Review/);
  assert.match(html, /data-action="download-export"/);
  assert.match(html, /haze-fuji-compliance-signer-v1/);
});
