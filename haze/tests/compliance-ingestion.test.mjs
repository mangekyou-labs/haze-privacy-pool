import assert from "node:assert/strict";
import test from "node:test";
import {
  ComplianceMemoryStore,
  FUJI_CHAIN_ID,
  LIVE_APP_ID,
  LIVE_POSEIDON_POOL,
  REQUIRED_CONFIRMATIONS,
  DEDICATED_AUDITOR,
  verifyExportSignature,
} from "../sdk/typescript/src/compliance-service.ts";

test("dynamic ingestion upserts withdrawal cases idempotently and assigns dedicated auditor", () => {
  const store = new ComplianceMemoryStore();
  const txHash = "0x" + "11".repeat(32);
  const blockNumber = 100;
  const currentBlock = 105;

  const case1 = store.upsertWithdrawalCase({
    chainId: FUJI_CHAIN_ID,
    pool: LIVE_POSEIDON_POOL,
    applicationId: LIVE_APP_ID,
    transactionHash: txHash,
    logIndex: 2,
    blockNumber,
    currentBlockNumber: currentBlock,
  });

  assert.equal(case1.chainId, FUJI_CHAIN_ID);
  assert.equal(case1.transactionHash, txHash.toLowerCase());
  assert.equal(case1.logIndex, 2);
  assert.equal(case1.assignedAuditor, DEDICATED_AUDITOR.toLowerCase());
  assert.equal(case1.confirmationCount, 6); // 105 - 100 + 1
  assert.equal(case1.caseState, "confirming");
  assert.equal(case1.readiness, false);

  // Duplicate ingestion of same (chain_id, tx_hash, log_index) does not duplicate
  const case2 = store.upsertWithdrawalCase({
    chainId: FUJI_CHAIN_ID,
    pool: LIVE_POSEIDON_POOL,
    applicationId: LIVE_APP_ID,
    transactionHash: txHash,
    logIndex: 2,
    blockNumber,
    currentBlockNumber: currentBlock,
  });

  assert.equal(case1.caseId, case2.caseId);
  const assigned = store.listAssignedCases(DEDICATED_AUDITOR, LIVE_APP_ID);
  assert.equal(assigned.length, 1);
});

test("confirmation progression transitions case from confirming to ready at 12 confirmations", () => {
  const store = new ComplianceMemoryStore();
  const txHash = "0x" + "22".repeat(32);
  const blockNumber = 1000;

  // 1 confirmation
  const caseItem = store.upsertWithdrawalCase({
    chainId: FUJI_CHAIN_ID,
    pool: LIVE_POSEIDON_POOL,
    applicationId: LIVE_APP_ID,
    transactionHash: txHash,
    logIndex: 0,
    blockNumber,
    currentBlockNumber: 1000,
  });
  assert.equal(caseItem.caseState, "confirming");
  assert.equal(caseItem.confirmationCount, 1);
  assert.equal(caseItem.readiness, false);

  // Advance blocks to 11 confirmations (block 1010)
  store.updateConfirmations(1010);
  assert.equal(caseItem.confirmationCount, 11);
  assert.equal(caseItem.caseState, "confirming");
  assert.equal(caseItem.readiness, false);

  // Advance blocks to 12 confirmations (block 1011)
  store.updateConfirmations(1011);
  assert.equal(caseItem.confirmationCount, 12);
  assert.equal(caseItem.caseState, "ready");
  assert.equal(caseItem.readiness, true);
});

test("pre-finality reorg marks observation reorged and blocks disclosure and export", () => {
  const store = new ComplianceMemoryStore();
  const txHash = "0x" + "33".repeat(32);
  const blockNumber = 500;

  store.upsertWithdrawalCase({
    chainId: FUJI_CHAIN_ID,
    pool: LIVE_POSEIDON_POOL,
    applicationId: LIVE_APP_ID,
    transactionHash: txHash,
    logIndex: 1,
    blockNumber,
    currentBlockNumber: 505,
  });

  const reorged = store.markReorged(FUJI_CHAIN_ID, txHash, 1);
  assert.notEqual(reorged, null);
  assert.equal(reorged?.caseState, "reorged");
  assert.equal(reorged?.readiness, false);

  // Attempting disclosure fails closed
  assert.throws(
    () => store.discloseCase(reorged.caseId, DEDICATED_AUDITOR),
    (err) => err.code === "CASE_REORGED",
  );

  // Attempting export fails closed
  assert.throws(
    () => store.exportCase(reorged.caseId, DEDICATED_AUDITOR),
    (err) => err.code === "UNAUTHORIZED",
  );
});

test("disclosure reveals exactly the 5 granted fields with no identity leaks", () => {
  const store = new ComplianceMemoryStore();
  const txHash = "0x" + "44".repeat(32);
  const blockNumber = 2000;

  const caseItem = store.upsertWithdrawalCase({
    chainId: FUJI_CHAIN_ID,
    pool: LIVE_POSEIDON_POOL,
    applicationId: LIVE_APP_ID,
    transactionHash: txHash,
    logIndex: 0,
    blockNumber,
    currentBlockNumber: 2020, // 21 confirmations >= 12
    witnessData: {
      auditRecord: {
        facts: {
          publicAmount: 1_000_000,
          timestamp: 1724000000,
          applicationPolicyVersion: 1,
          authorizedUser: "0xuserSecret",
          publicRecipient: "0xrecipientSecret",
        },
      },
    },
  });

  assert.equal(caseItem.caseState, "ready");
  const disclosure = store.discloseCase(caseItem.caseId, DEDICATED_AUDITOR);

  assert.equal(disclosure.caseId, caseItem.caseId);
  assert.equal(disclosure.transactionHash, txHash.toLowerCase());

  // Exactly the 5 granted fields
  assert.deepEqual(Object.keys(disclosure.fields).sort(), [
    "amount",
    "asset",
    "policy_version",
    "timestamp",
    "tx_hash",
  ]);

  assert.equal(disclosure.fields.amount, "1.00 USDC");
  assert.equal(disclosure.fields.asset, "USDC");
  assert.equal(disclosure.fields.policy_version, 1);
  assert.equal(disclosure.fields.tx_hash, txHash.toLowerCase());

  // Assert user and counterparty are strictly absent
  assert.equal(disclosure.fields.user, undefined);
  assert.equal(disclosure.fields.counterparty, undefined);
  assert.equal(disclosure.fields.authorizedUser, undefined);
  assert.equal(disclosure.fields.publicRecipient, undefined);
  assert.doesNotMatch(JSON.stringify(disclosure), /userSecret|recipientSecret/);
});

test("canonical export produces verifiable signature and updates access log chain", () => {
  const store = new ComplianceMemoryStore();
  const txHash = "0x" + "55".repeat(32);
  const blockNumber = 3000;

  const caseItem = store.upsertWithdrawalCase({
    chainId: FUJI_CHAIN_ID,
    pool: LIVE_POSEIDON_POOL,
    applicationId: LIVE_APP_ID,
    transactionHash: txHash,
    logIndex: 0,
    blockNumber,
    currentBlockNumber: 3015,
    witnessData: {
      auditRecord: {
        facts: {
          publicAmount: 1_000_000,
          timestamp: 1724000000,
          applicationPolicyVersion: 1,
        },
      },
    },
  });

  const exportResult = store.exportCase(caseItem.caseId, DEDICATED_AUDITOR);
  assert.equal(exportResult.case_id, caseItem.caseId);
  assert.equal(exportResult.transaction_hash, txHash.toLowerCase());
  assert.equal(typeof exportResult.signature, "string");
  assert.equal(verifyExportSignature(exportResult), true);

  const accessLog = store.getAccessLog();
  assert.equal(accessLog.verified, true);
  assert.ok(accessLog.entries.length >= 2); // verify + export
});
