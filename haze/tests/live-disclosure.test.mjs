import assert from "node:assert/strict";
import test from "node:test";

import { keccakHex, uintWord } from "../sdk/typescript/src/abi.ts";
import { createDevelopmentAuditKeyManagement, discloseLiveWithdrawal, PRIVATE_TRANSACTION_TOPIC } from "../dev/live-disclosure.mjs";

const POOL = "0x1111111111111111111111111111111111111111";
const USER = "0x2222222222222222222222222222222222222222";
const APP = `0x${"aa".repeat(32)}`;
const POOL_VERSION = `0x${"bb".repeat(32)}`;
const USDC = "0x5425890298aed601595a70AB815c96711a31Bc65";

function word(value) {
  return uintWord(value);
}

function topic(value) {
  return `0x${Buffer.from(word(value)).toString("hex")}`;
}

function eventData(facts, auditHash, commitment) {
  const words = [
    word(facts.applicationPolicyVersion),
    word(facts.hazePolicyVersion),
    word(0),
    word(facts.inputNullifiers[0]),
    word(facts.inputNullifiers[1]),
    word(facts.outputCommitments[0]),
    word(facts.outputCommitments[1]),
    word(facts.publicAmount),
    word(facts.publicRecipient),
    word(facts.recipientCiphertextHashes[0]),
    word(facts.recipientCiphertextHashes[1]),
    word(commitment),
    word(auditHash),
    word(16 * 32),
    word(16 * 32),
    word(16 * 32),
  ];
  return `0x${Buffer.concat(words).toString("hex")}`;
}

async function fixturePlan() {
  const { buildLiveDepositWitness, buildLiveWithdrawWitness } = await import("../dev/operator-circuit-witness.mjs");
  // A deterministic synthetic note: the receipt and pool here are fakes, so the
  // test needs no real note from the gitignored ceremony-private folder.
  const stored = buildLiveDepositWitness({ pool: POOL, user: USER, applicationId: APP, poolVersion: POOL_VERSION });
  const witness = buildLiveWithdrawWitness({
    pool: POOL,
    user: USER,
    applicationId: APP,
    poolVersion: POOL_VERSION,
    note: stored.note,
    publicAmount: stored.note.value,
    publicRecipient: USER,
    actionReference: `0x${"01".repeat(32)}`,
  });
  const facts = witness.auditRecord.facts;
  const log = {
    address: POOL,
    topics: [PRIVATE_TRANSACTION_TOPIC, APP, topic(3), topic(USER)],
    data: eventData(facts, witness.envelopes.auditCiphertextHash, witness.circom.auditDataCommitment),
  };
  const plan = {
    pool: POOL,
    user: USER,
    applicationId: APP,
    poolVersion: POOL_VERSION,
    usdc: USDC,
    circuitPlan: witness,
    intent: {
      applicationId: APP,
      user: USER,
      pool: POOL,
      poolVersion: POOL_VERSION,
      action: 3,
      applicationPolicyVersion: 1,
      hazePolicyVersion: 1,
      publicAmount: facts.publicAmount,
      publicRecipient: USER,
      inputNullifier0: witness.circom.inputNullifier0,
      inputNullifier1: witness.circom.inputNullifier1,
      outputCommitment0: witness.circom.outputCommitment0,
      outputCommitment1: witness.circom.outputCommitment1,
      recipientCiphertextHash0: witness.envelopes.recipientCiphertextHash0,
      recipientCiphertextHash1: witness.envelopes.recipientCiphertextHash1,
      auditDataCommitment: witness.circom.auditDataCommitment,
      auditCiphertextHash: witness.envelopes.auditCiphertextHash,
    },
    authorization: { nonce: facts.actionReference },
    auditCiphertext: witness.envelopes.auditCiphertext,
  };
  return { plan, receipt: { status: "0x1", transactionHash: `0x${"99".repeat(32)}`, logs: [log] } };
}

test("completed withdrawal decrypts the scoped audit record and returns only requested redactions", async () => {
  const { plan, receipt } = await fixturePlan();
  const result = await discloseLiveWithdrawal({
    plan,
    receipt,
    fields: ["amount", "counterparty", "policy_version"],
    applicationId: APP,
    authorize: async () => true,
    keyManagement: createDevelopmentAuditKeyManagement({ applicationId: APP }),
  });
  assert.deepEqual(Object.keys(result.fields).sort(), ["amount", "counterparty", "policy_version"]);
  assert.equal(result.fields.amount, 1_000_000);
  assert.equal(result.fields.counterparty, USER);
  assert.equal(result.fields.policy_version, 1);
  assert.equal(result.auditAcceptance, true);
});

test("disclosure rejects wrong receipt, event binding, envelope hash, action reference, application, and commitment", async () => {
  const { plan, receipt } = await fixturePlan();
  const base = {
    plan,
    receipt,
    fields: ["amount"],
    applicationId: APP,
    authorize: async () => true,
    keyManagement: createDevelopmentAuditKeyManagement({ applicationId: APP }),
  };
  await assert.rejects(discloseLiveWithdrawal({ ...base, receipt: { ...receipt, status: "0x0" } }), { code: "RECEIPT_REVERTED" });
  await assert.rejects(discloseLiveWithdrawal({ ...base, applicationId: `0x${"ab".repeat(32)}` }), { code: "APPLICATION_MISMATCH" });
  await assert.rejects(discloseLiveWithdrawal({ ...base, plan: { ...plan, authorization: { nonce: `0x${"02".repeat(32)}` } } }), { code: "COMMITMENT_MISMATCH" });
  await assert.rejects(discloseLiveWithdrawal({ ...base, plan: { ...plan, intent: { ...plan.intent, auditDataCommitment: `0x${"03".repeat(32)}` } } }), { code: "COMMITMENT_MISMATCH" });
  await assert.rejects(discloseLiveWithdrawal({ ...base, plan: { ...plan, auditCiphertext: `0x${"00".repeat(100)}` } }), { code: "COMMITMENT_MISMATCH" });
  const noEvent = { ...receipt, logs: [] };
  await assert.rejects(discloseLiveWithdrawal({ ...base, receipt: noEvent }), { code: "EVENT_MISSING" });
});

test("disclosure is fail-closed for unauthorized fields, cross-application access, and KMS outages", async () => {
  const { plan, receipt } = await fixturePlan();
  const base = { plan, receipt, applicationId: APP, keyManagement: createDevelopmentAuditKeyManagement({ applicationId: APP }) };
  await assert.rejects(discloseLiveWithdrawal({ ...base, fields: ["case_tag"], authorize: async () => true }), { code: "UNAUTHORIZED" });
  await assert.rejects(discloseLiveWithdrawal({ ...base, fields: ["amount"], applicationId: `0x${"cc".repeat(32)}`, authorize: async () => true }), { code: "APPLICATION_MISMATCH" });
  await assert.rejects(discloseLiveWithdrawal({ ...base, fields: ["amount"], authorize: async () => false }), { code: "UNAUTHORIZED" });
  await assert.rejects(discloseLiveWithdrawal({ ...base, fields: ["amount"], authorize: async () => true, keyManagement: undefined }), { code: "KEYS_MISSING" });
  await assert.rejects(discloseLiveWithdrawal({
    ...base,
    fields: ["amount"],
    authorize: async () => true,
    keyManagement: { unwrapDataKey: async () => { throw Object.assign(new Error("down"), { code: "UNAVAILABLE" }); } },
  }), { code: "UNAVAILABLE" });
});
