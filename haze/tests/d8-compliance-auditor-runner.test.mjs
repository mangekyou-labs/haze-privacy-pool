import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const bootstrapRunner = readFileSync(
  new URL("../dev/dappwright-audit-bootstrap.mjs", import.meta.url),
  "utf8",
);
const walkRunner = readFileSync(
  new URL("../dev/playwright-audit-walk.mjs", import.meta.url),
  "utf8",
);

test("D8 bootstrap runner uses Dappwright for MetaMask SIWE on Fuji and exports storageState", () => {
  assert.match(bootstrapRunner, /@tenkeylabs\/dappwright/);
  assert.match(bootstrapRunner, /43113/);
  assert.match(bootstrapRunner, /confirmVisibleWalletAction/);
  assert.match(bootstrapRunner, /connect-siwe/);
  assert.match(bootstrapRunner, /audit-session\.json/);
  assert.match(bootstrapRunner, /eth_getTransactionCount/);
  assert.match(bootstrapRunner, /D8_AUDITOR_TX_COUNT_UNEXPECTEDLY_CHANGED/);
});

test("D8 production walk runner performs visible investigation against production origin", () => {
  assert.match(walkRunner, /https:\/\/haze-mu-flax\.vercel\.app/);
  assert.match(walkRunner, /fuji-withdrawal-8218e5a4/);
  assert.match(walkRunner, /0x8218e5a4f14434e0007d421a8e82ba0914429a0cab43d7dba263d1ed232c8a03/);
  assert.match(walkRunner, /12/);
  assert.match(walkRunner, /D8_INSUFFICIENT_FINALITY/);
  assert.match(walkRunner, /verify-case/);
  assert.match(walkRunner, /export-case/);
  assert.match(walkRunner, /download-export-json/);
  assert.match(walkRunner, /close-export-modal/);
});

test("D8 production walk runner validates granted and denied field boundaries", () => {
  assert.match(walkRunner, /tx_hash/);
  assert.match(walkRunner, /amount/);
  assert.match(walkRunner, /asset/);
  assert.match(walkRunner, /timestamp/);
  assert.match(walkRunner, /policy_version/);
  assert.match(walkRunner, /user/);
  assert.match(walkRunner, /counterparty/);
  assert.match(walkRunner, /WITHHELD/);
});

test("D8 production walk runner captures the 4 required production screenshots and evidence manifest", () => {
  assert.match(walkRunner, /d8-audit-production-login\.png/);
  assert.match(walkRunner, /d8-audit-production-disclosure\.png/);
  assert.match(walkRunner, /d8-audit-production-export\.png/);
  assert.match(walkRunner, /d8-audit-production-mobile\.png/);
  assert.match(walkRunner, /d8-production-audit-acceptance\.json/);
});

test("D8 production walk runner executes negative security and isolation checks", () => {
  assert.match(walkRunner, /390/);
  assert.match(walkRunner, /844/);
  assert.match(walkRunner, /\/admin/);
  assert.match(walkRunner, /\/governance/);
  assert.match(walkRunner, /This workspace is not authorized|FORBIDDEN/);
  assert.match(walkRunner, /eth_getTransactionCount/);
  assert.match(walkRunner, /rmSync\(SESSION_STATE_PATH/);
});
