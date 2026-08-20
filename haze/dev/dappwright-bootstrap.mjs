/** Local MetaMask bootstrap planner. Does not launch a browser from npm test. */

import { readFileSync, writeFileSync } from "node:fs";
import { FIXTURE_ACCOUNTS, grantForAddress } from "../web/packages/ui/src/site.ts";
import { occupiedLiveLeaves } from "./operator-circuit-live.mjs";

export { FIXTURE_ACCOUNTS, grantForAddress };

export const LOCAL_TEST_SEED = "test test test test test test test test test test test junk";

export function planDappwrightBootstrap(input = {}) {
  if (input.writeFujiV1 === true) {
    return { ok: false, reason: "FUJI_V1_IMMUTABLE" };
  }
  if (input.seed && input.seed !== LOCAL_TEST_SEED) {
    return { ok: false, reason: "PRODUCTION_SEED_REFUSED" };
  }
  if (input.live === true && !input.sidecar) {
    return { ok: false, reason: "SIDECAR_MISSING" };
  }
  if (input.live === true && input.sidecar?.broadcast !== true) {
    return { ok: false, reason: "LIVE_BROADCAST_CLOSED" };
  }

  const chainId = input.live === true ? 43113 : Number(input.chainId ?? 31337);
  return {
    ok: true,
    seed: LOCAL_TEST_SEED,
    cdp: input.cdp ?? "http://127.0.0.1:9222",
    chainId,
    launchMetaMask: input.launch === true,
    accounts: FIXTURE_ACCOUNTS,
    commercialUrl: input.commercialUrl ?? "http://127.0.0.1:3010",
    notes: [
      "Fixed local Anvil/dappwright seed only.",
      "Does not write haze/deployments/fuji-v1.json.",
      "Does not launch MetaMask from npm test.",
    ],
  };
}

export function recordLiveOperatorOverlay(input = {}) {
  if (input.writeFujiV1 === true) {
    return { ok: false, reason: "FUJI_V1_IMMUTABLE" };
  }
  if (input.shieldReceipt?.status !== "0x1" || input.withdrawReceipt?.status !== "0x1") {
    return { ok: false, reason: "RECEIPT_REVERTED" };
  }
  const overlay = JSON.parse(readFileSync(input.overlayPath, "utf8"));
  const nextIndex = occupiedLiveLeaves(overlay).length + 1;
  overlay.transactions = {
    ...(overlay.transactions ?? {}),
    websiteOperatorShield: input.shield,
    websiteOperatorWithdraw: input.withdraw,
    websiteOperatorHost: input.host,
    nextIndex,
  };
  writeFileSync(input.overlayPath, `${JSON.stringify(overlay, null, 2)}\n`);
  return { ok: true, nextIndex };
}

export function planDappwrightLiveOperator(input = {}) {
  if (input.writeFujiV1 === true) {
    return { ok: false, reason: "FUJI_V1_IMMUTABLE" };
  }
  if (input.productionCeremonyApproved === true) {
    return { ok: false, reason: "KEYS_MISSING" };
  }
  if (input.zkeyExists !== true) {
    return { ok: false, reason: "KEYS_MISSING" };
  }
  if (!input.sidecar) {
    return { ok: false, reason: "SIDECAR_MISSING" };
  }
  if (input.sidecar.broadcast !== true) {
    return { ok: false, reason: "LIVE_BROADCAST_CLOSED" };
  }
  return {
    ok: true,
    seed: LOCAL_TEST_SEED,
    chainId: 43113,
    actions: ["shield", "withdraw"],
    script: "dappwright:live-operator",
    commercialUrl: input.commercialUrl ?? "http://127.0.0.1:3014",
    launchFromNpmTest: false,
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const plan = planDappwrightBootstrap({
    launch: process.argv.includes("--launch"),
    live: process.argv.includes("--live"),
  });
  console.log(JSON.stringify(plan, null, 2));
  if (!plan.ok) {
    process.exitCode = 1;
  } else if (plan.launchMetaMask) {
    console.log("In-process MetaMask launch is not the acceptance path.");
    console.log("Run: npm run qa:wallet:setup --prefix haze");
    console.log("Then: npm run qa:cli --prefix haze -- --config .playwright/cli.config.json open \"$DAPP_URL\" --headed");
  }
}
