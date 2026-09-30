import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { PRODUCTION_URL } from "../dev/production-origin.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

test("D8 runner contract requires Dappwright fresh Fuji deposit->recovery->withdraw journey", async () => {
  const { planD8ProductionJourney } = await import("../dev/d8-production-runner.mjs");

  // Reject missing production URL or preview/localhost origins for final acceptance
  assert.throws(
    () => planD8ProductionJourney({ productionUrl: "http://localhost:3000" }),
    (err) => err.code === "PRODUCTION_ORIGIN_REQUIRED",
  );

  assert.throws(
    () => planD8ProductionJourney({ productionUrl: "https://haze-preview.vercel.app" }),
    (err) => err.code === "PRODUCTION_ORIGIN_REQUIRED",
  );

  // Reject playwright-core fallback
  assert.throws(
    () => planD8ProductionJourney({ runner: "playwright-core" }),
    (err) => err.code === "PLAYWRIGHT_CLI_REQUIRED",
  );

  // Reject hardcoded seeded hashes
  assert.throws(
    () => planD8ProductionJourney({ fixedHash: "0x821890298aed601595a70ab815c96711a31bc65" }),
    (err) => err.code === "FRESH_HASH_REQUIRED",
  );

  const plan = planD8ProductionJourney({
    productionUrl: PRODUCTION_URL,
    chainId: 43113,
    runner: "playwright-cli",
  });

  assert.equal(plan.ok, true);
  assert.equal(plan.productionUrl, PRODUCTION_URL);
  assert.equal(plan.chainId, 43113);
  assert.deepEqual(plan.walletSteps, [
    "connect_operator",
    "deposit_1_usdc",
    "verify_deposit_receipt",
    "reload_verify_note_recovery",
    "withdraw_same_note",
    "verify_withdraw_receipt",
    "stop_chain_transactions",
    "auditor_siwe_auth",
    "assert_auditor_tx_count_unchanged",
  ]);
  assert.deepEqual(plan.portalSteps, [
    "load_auditor_session",
    "open_production_audit",
    "verify_origin_and_chain",
    "assert_only_same_origin_traffic",
    "wait_ingested_case_matching_fresh_withdraw",
    "observe_confirmations_to_12",
    "verify_and_disclose",
    "assert_integrity_and_5_fields",
    "assert_no_identity_leaks",
    "export_review_download_verify_signature",
    "verify_access_history_and_hash_chain",
    "mobile_390x844_no_overflow",
    "logout_assert_data_cleared",
    "fail_closed_unauthenticated_and_admin_governance",
  ]);
});

test("D8 runner defaults to the canonical production origin", async () => {
  const { planD8ProductionJourney } = await import("../dev/d8-production-runner.mjs");
  const plan = planD8ProductionJourney({ chainId: 43113, runner: "playwright-cli" });
  assert.equal(plan.productionUrl, PRODUCTION_URL);
});
