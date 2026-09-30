import assert from "node:assert/strict";
import test from "node:test";
import { secp256k1 } from "@noble/curves/secp256k1";

import {
  ComplianceMemoryStore,
  FUJI_CHAIN_ID,
  LIVE_APP_ID,
  LIVE_POSEIDON_POOL,
  REQUIRED_CONFIRMATIONS,
  DEDICATED_AUDITOR,
} from "../sdk/typescript/src/compliance-service.ts";
import { keccak256 } from "../sdk/typescript/src/keccak.ts";
import { PRODUCTION_HOST, PRODUCTION_URL } from "../dev/production-origin.mjs";

const POOL = LIVE_POSEIDON_POOL;
const APP = LIVE_APP_ID;
const AUDITOR = DEDICATED_AUDITOR;

function addressOf(keyHex) {
  const pub = secp256k1.getPublicKey(Buffer.from(keyHex.slice(2), "hex"), false);
  const hash = keccak256(pub.subarray(1));
  return "0x" + hash.subarray(12).toString("hex");
}

function personalSign(message, keyHex) {
  const prefixed = "\x19Ethereum Signed Message:\n" + message.length + message;
  const digest = keccak256(Buffer.from(prefixed, "utf8"));
  const privateKey = Buffer.from(keyHex.slice(2), "hex");
  const signed = secp256k1.sign(digest, privateKey, { prehash: false });
  const low = signed.normalizeS();
  const recovery = signed.recovery === undefined ? 0 : signed.recovery;
  const flipped = signed.hasHighS() ? recovery ^ 1 : recovery;
  const out = Buffer.alloc(65);
  Buffer.from(low.toCompactRawBytes()).copy(out);
  out[64] = flipped;
  return "0x" + out.toString("hex");
}

function siweMessage(challenge) {
  // The server-issued challenge carries the exact message the wallet signs;
  // fall back to the legacy client construction only if absent.
  return (
    challenge.message ??
    `${challenge.statement}\n\nURI: https://${challenge.domain}/audit\nVersion: 1\nChain ID: ${challenge.chainId}\nNonce: ${challenge.nonce}\nIssued At: ${new Date().toISOString()}`
  );
}

test("store must not fabricate chain identity: case preserves chainId, pool, logIndex, blockNumber, confirmations, assignedAuditor", () => {
  const store = new ComplianceMemoryStore();
  const txHash = "0x" + "66".repeat(32);
  const blockNumber = 12345;
  const logIndex = 7;

  const caseItem = store.upsertWithdrawalCase({
    chainId: FUJI_CHAIN_ID,
    pool: POOL,
    applicationId: APP,
    transactionHash: txHash,
    logIndex,
    blockNumber,
    currentBlockNumber: blockNumber + 5,
  });

  assert.equal(caseItem.chainId, FUJI_CHAIN_ID);
  assert.equal(caseItem.pool, POOL.toLowerCase());
  assert.equal(caseItem.logIndex, logIndex);
  assert.equal(caseItem.blockNumber, blockNumber);
  assert.equal(caseItem.confirmationCount, 6);
  assert.equal(caseItem.assignedAuditor, AUDITOR.toLowerCase());
  assert.notEqual(caseItem.blockNumber, 0);
  assert.notEqual(caseItem.confirmationCount, REQUIRED_CONFIRMATIONS + 10);
});

test("store must not fabricate disclosure amount: uses stored witness amount/asset when present", () => {
  const store = new ComplianceMemoryStore();
  const txHash = "0x" + "77".repeat(32);
  const blockNumber = 5000;

  const caseItem = store.upsertWithdrawalCase({
    chainId: FUJI_CHAIN_ID,
    pool: POOL,
    applicationId: APP,
    transactionHash: txHash,
    logIndex: 0,
    blockNumber,
    currentBlockNumber: blockNumber + 13,
    witnessData: {
      auditRecord: {
        facts: {
          publicAmount: 2_500_000,
          timestamp: 1724000000,
          applicationPolicyVersion: 1,
        },
      },
    },
  });

  assert.equal(caseItem.caseState, "ready");
  const disclosure = store.discloseCase(caseItem.caseId, AUDITOR);
  assert.equal(disclosure.fields.amount, "2.50 USDC");
  assert.equal(disclosure.fields.asset, "USDC");
  assert.notEqual(disclosure.fields.amount, "1.000000 USDC");
});

test("store must reject a SIWE signature that does not ecrecover to the challenge wallet", () => {
  const store = new ComplianceMemoryStore();
  const wallet = addressOf("0x" + "02".repeat(32));
  const challenge = store.createSiweChallenge(wallet, PRODUCTION_HOST);
  const message = siweMessage(challenge);

  const goodSig = personalSign(message, "0x" + "02".repeat(32));
  const session = store.verifySiweChallenge(challenge.nonce, wallet, goodSig);
  assert.equal(session.address, wallet.toLowerCase());
  assert.equal(session.role, "application-auditor");

  const store2 = new ComplianceMemoryStore();
  const challenge2 = store2.createSiweChallenge(wallet, PRODUCTION_HOST);
  const message2 = siweMessage(challenge2);
  const badSig = personalSign(message2, "0x" + "03".repeat(32));
  assert.throws(
    () => store2.verifySiweChallenge(challenge2.nonce, wallet, badSig),
    (err) => err.code === "UNAUTHORIZED" || err.message === "UNAUTHORIZED",
  );
});

test("store must reject a truncated/garbage SIWE signature (not merely length)", () => {
  const store = new ComplianceMemoryStore();
  const wallet = addressOf("0x" + "04".repeat(32));
  const challenge = store.createSiweChallenge(wallet, PRODUCTION_HOST);

  const dummy = "0x" + "bb".repeat(65);
  assert.throws(
    () => store.verifySiweChallenge(challenge.nonce, wallet, dummy),
    (err) => err.code === "UNAUTHORIZED" || err.message === "UNAUTHORIZED",
  );
});

test("runner must not ship a fake execute path that accepts seeded hashes or dummy SIWE", async () => {
  const mod = await import("../dev/d8-production-runner.mjs");

  const plan = mod.planD8ProductionJourney({
    productionUrl: PRODUCTION_URL,
    chainId: 43113,
    runner: "playwright-cli",
  });
  assert.equal(plan.ok, true);

  // The fake executor (which defaulted to seeded 0x0aee… and dummy SIWE) must be gone.
  assert.equal(typeof mod.executeD8ProductionJourney, "undefined");
});

test("SIWE binds canonical production requests to the page host even when env has a stale host", () => {
  const previous = process.env.HAZE_COMPLIANCE_DOMAIN;
  process.env.HAZE_COMPLIANCE_DOMAIN = "haze-finance.vercel.app";
  try {
    const store = new ComplianceMemoryStore();
    const wallet = addressOf("0x" + "05".repeat(32));
    const challenge = store.createSiweChallenge(wallet, `${PRODUCTION_HOST}:443`);
    assert.equal(challenge.domain, PRODUCTION_HOST);
    assert.match(challenge.message, new RegExp(`URI: https://${PRODUCTION_HOST}/audit`));
  } finally {
    if (previous === undefined) delete process.env.HAZE_COMPLIANCE_DOMAIN;
    else process.env.HAZE_COMPLIANCE_DOMAIN = previous;
  }
});
