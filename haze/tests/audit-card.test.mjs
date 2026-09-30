import assert from "node:assert/strict";
import test from "node:test";
import { renderHazeFragment } from "../web/packages/ui/src/html.ts";
import { createHazeSite } from "../web/packages/ui/src/site.ts";
import { LIVE_APP_ID, DEDICATED_AUDITOR } from "../sdk/typescript/src/compliance-service.ts";

test("D10.4: disconnected /audit renders centered consumer card matching screenshot", () => {
  const site = createHazeSite({ role: "pool-user", applicationId: LIVE_APP_ID });
  const html = renderHazeFragment(site, "/audit", {});

  assert.match(html, /data-chrome="consumer"/, "Must use consumer chrome");
  assert.match(html, /<a[^>]*href="\/audit"[^>]*aria-current="page"/, "Audit tab is active");
  assert.match(html, /Case ID/, "Case ID field must be present");
  assert.match(html, /Case File|Download Case File/, "Case File control must be present");
  assert.doesNotMatch(html, /<input[^>]*type="file"/i, "Must NOT have file upload input");
  assert.match(html, /data-action="siwe"|data-action="connect"/, "SIWE / Connect button must be present");
});

test("D10.4: connected auditor has Case ID picker and signed export Case File download", () => {
  const site = createHazeSite({ role: "application-auditor", applicationId: LIVE_APP_ID });
  const html = renderHazeFragment(site, "/audit", {
    audit: {
      boundWallet: DEDICATED_AUDITOR,
      cases: [
        {
          caseId: "case-101",
          title: "Fuji Case 101",
          caseState: "ready",
          disclosedRecord: {
            tx_hash: "0x" + "aa".repeat(32),
            amount: "1000.00 USDC",
            asset: "USDC",
            timestamp: "2026-08-26 12:00:00",
            policy_version: "28",
          },
        },
      ],
      selectedCaseId: "case-101",
    },
  });

  assert.match(html, /case-101/, "Assigned case must be listed");
  assert.match(html, /data-action="export-review"|data-action="export"/, "Case File export button must be present");
  assert.doesNotMatch(html, /<input[^>]*type="file"/i, "Must NOT have file upload input");
});
