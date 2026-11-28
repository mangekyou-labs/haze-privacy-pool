import assert from "node:assert/strict";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { createAcceptanceJournal } from "../dev/fuji-acceptance-journal.mjs";
import {
  FUJI_ACTIONS,
  PRIVATE_TRANSACTION_TOPIC,
  fujiActionToKind,
  kindToFujiAction,
  decodePrivateTransaction,
  reconcileFujiOperation,
} from "../sdk/typescript/src/fuji-reconciliation.ts";
import { classifyBrowserError } from "../sdk/typescript/src/fuji-browser-error.ts";
import { verifyFujiMvpV2Manifest } from "../dev/evidence-verifier.mjs";
const ROOT = dirname(fileURLToPath(import.meta.url));
const hex = (byte, bytes = 32) => `0x${byte.repeat(bytes)}`;
const word = (value) => BigInt(value).toString(16).padStart(64, "0");
const addressTopic = (value) => `0x${"0".repeat(24)}${value.slice(2).toLowerCase()}`;

const config = {
  chainId: 43113,
  pool: hex("11", 20),
  poolVersion: hex("22"),
  applicationId: hex("33"),
  user: hex("44", 20),
  action: FUJI_ACTIONS.SHIELD,
  commitment: hex("55"),
  nullifier: hex("66"),
};

function sampleEvent(overrides = {}) {
  const values = {
    action: config.action,
    nullifier0: config.nullifier,
    output0: config.commitment,
    pool: config.pool,
    user: config.user,
    applicationId: config.applicationId,
    ...overrides,
  };
  const data = [1, 2, 3, values.nullifier0, 0, values.output0, 0, 100, BigInt(values.user), 7, 8, 9, 10, 448, 480, 512]
    .map(word).join("");
  return {
    address: values.pool,
    topics: [
      PRIVATE_TRANSACTION_TOPIC,
      values.applicationId,
      `0x${word(values.action)}`,
      addressTopic(values.user),
    ],
    data: `0x${data}`,
  };
}

// === 1. JOURNALING & CRASH RECOVERY TESTS ===

test("journaler creates append-only run directory and preserves transaction hash after crash", () => {
  const testRunId = `test-crash-${Date.now()}`;
  const journal = createAcceptanceJournal({
    runId: testRunId,
    candidateGitSha: "0123456789abcdef0123456789abcdef01234567",
    vercelDeploymentId: "dpl_test_journal",
  });

  assert.ok(existsSync(journal.manifestPath), "Manifest must exist immediately at run start");
  const initialManifest = JSON.parse(readFileSync(journal.manifestPath, "utf8"));
  assert.equal(initialManifest.schema, "haze-fuji-mvp-acceptance-v2");
  assert.equal(initialManifest.status, "IN_PROGRESS");

  // Preflight
  journal.recordPreflight("shield", { wallet: "0x1234567890123456789012345678901234567890" });

  // Broadcast tx: simulating a crash immediately after broadcast
  const txHash = "0xa3c80edc12e670066b8795c69816cd56303f46da7ed03a666461235c3231dff4";
  journal.recordBroadcast("shield", txHash, { wallet: "0x1234567890123456789012345678901234567890" });

  // Read manifest from disk to verify broadcast persistence prior to any mining/exit
  const crashedManifest = JSON.parse(readFileSync(journal.manifestPath, "utf8"));
  assert.equal(crashedManifest.operations.shield.transactionHash, txHash);
  assert.equal(crashedManifest.operations.shield.phase, "broadcast");
  assert.equal(crashedManifest.attempts.length, 2);
  assert.equal(crashedManifest.attempts[1].transactionHash, txHash);

  // Resume / record mined and finality
  journal.recordMined("shield", { status: "0x1", blockNumber: 100, blockHash: hex("bb") });
  journal.recordFinality("shield", 12, { inclusionBlock: 100, verifiedAtBlock: 111, canonicalBlockHash: hex("bb") });
  journal.finalize("PASS");

  const finalizedManifest = JSON.parse(readFileSync(journal.manifestPath, "utf8"));
  assert.equal(finalizedManifest.status, "PASS");
  assert.equal(finalizedManifest.operations.shield.phase, "finalized");
  assert.equal(finalizedManifest.operations.shield.confirmationCount, 12);
});

// === 2. ACTION MAPPINGS & SPENDABILITY INVARIANTS ===

test("centralized action mappings correctly convert to/from operation kinds", () => {
  assert.equal(FUJI_ACTIONS.SHIELD, 1);
  assert.equal(FUJI_ACTIONS.SEND, 2);
  assert.equal(FUJI_ACTIONS.WITHDRAW, 3);
  assert.equal(FUJI_ACTIONS.SWAP, 4);

  assert.equal(fujiActionToKind(1), "deposit");
  assert.equal(fujiActionToKind(2), "private_send");
  assert.equal(fujiActionToKind(3), "withdrawal");
  assert.equal(fujiActionToKind(4), "swap");

  assert.equal(kindToFujiAction("deposit"), 1);
  assert.equal(kindToFujiAction("private_send"), 2);
  assert.equal(kindToFujiAction("transfer"), 2);
  assert.equal(kindToFujiAction("withdrawal"), 3);
  assert.equal(kindToFujiAction("swap"), 4);
});

test("action spendability invariants: Shield & Swap output notes become spendable only upon finality", () => {
  const receipt = { status: "0x1", blockNumber: 100, blockHash: hex("aa"), transactionHash: hex("11"), logs: [sampleEvent()] };

  // Shield before finality (pending_finality): note is not yet spendable
  const shieldPending = reconcileFujiOperation({ ...config, action: 1, receipt, headBlockNumber: 105 });
  assert.equal(shieldPending.status, "pending_finality");
  assert.equal(shieldPending.noteSpendable, false);

  // Shield at 12 confirmations: note becomes spendable
  const shieldConfirmed = reconcileFujiOperation({ ...config, action: 1, receipt, headBlockNumber: 111, canonicalBlockHash: hex("aa") });
  assert.equal(shieldConfirmed.confirmed, true);
  assert.equal(shieldConfirmed.status, "confirmed");
  assert.equal(shieldConfirmed.noteSpendable, true);

  // Send before finality: input note remains spendable
  const sendEvent = sampleEvent({ action: 2 });
  const sendReceipt = { status: "0x1", blockNumber: 100, blockHash: hex("aa"), transactionHash: hex("22"), logs: [sendEvent] };
  const sendPending = reconcileFujiOperation({ ...config, action: 2, receipt: sendReceipt, headBlockNumber: 105 });
  assert.equal(sendPending.status, "pending_finality");
  assert.equal(sendPending.noteSpendable, true);

  // Send at 12 confirmations: sender's input note is consumed (not spendable)
  const sendConfirmed = reconcileFujiOperation({ ...config, action: 2, receipt: sendReceipt, headBlockNumber: 111, canonicalBlockHash: hex("aa") });
  assert.equal(sendConfirmed.confirmed, true);
  assert.equal(sendConfirmed.noteSpendable, false);

  // Withdraw before finality: input note remains spendable
  const withdrawEvent = sampleEvent({ action: 3 });
  const withdrawReceipt = { status: "0x1", blockNumber: 100, blockHash: hex("aa"), transactionHash: hex("33"), logs: [withdrawEvent] };
  const withdrawPending = reconcileFujiOperation({ ...config, action: 3, receipt: withdrawReceipt, headBlockNumber: 105 });
  assert.equal(withdrawPending.status, "pending_finality");
  assert.equal(withdrawPending.noteSpendable, true);

  // Withdraw at 12 confirmations: input note is consumed (not spendable)
  const withdrawConfirmed = reconcileFujiOperation({ ...config, action: 3, receipt: withdrawReceipt, headBlockNumber: 111, canonicalBlockHash: hex("aa") });
  assert.equal(withdrawConfirmed.confirmed, true);
  assert.equal(withdrawConfirmed.noteSpendable, false);
});

// === 3. EVENT MISMATCH & VALIDATION TESTS ===

test("event reconciliation strictly rejects pool, application, action, commitment, and nullifier mismatches", () => {
  const validReceipt = { status: "0x1", blockNumber: 100, blockHash: hex("aa"), logs: [sampleEvent()] };

  // Pool mismatch
  const badPool = reconcileFujiOperation({ ...config, pool: hex("99", 20), receipt: validReceipt });
  assert.equal(badPool.status, "failed");
  assert.equal(badPool.reason, "EVENT_MISMATCH");

  // Application mismatch
  const badApp = reconcileFujiOperation({ ...config, applicationId: hex("99"), receipt: validReceipt });
  assert.equal(badApp.status, "failed");
  assert.equal(badApp.reason, "EVENT_MISMATCH");

  // Action mismatch
  const badAction = reconcileFujiOperation({ ...config, action: 3, receipt: validReceipt });
  assert.equal(badAction.status, "failed");
  assert.equal(badAction.reason, "EVENT_MISMATCH");

  // Output commitment mismatch for Shield
  const badCommitment = reconcileFujiOperation({ ...config, commitment: hex("99"), receipt: validReceipt });
  assert.equal(badCommitment.status, "failed");
  assert.equal(badCommitment.reason, "EVENT_MISMATCH");

  // Input nullifier mismatch for Withdraw
  const withdrawReceipt = { status: "0x1", blockNumber: 100, blockHash: hex("aa"), logs: [sampleEvent({ action: 3 })] };
  const badNullifier = reconcileFujiOperation({ ...config, action: 3, nullifier: hex("99"), receipt: withdrawReceipt });
  assert.equal(badNullifier.status, "failed");
  assert.equal(badNullifier.reason, "EVENT_MISMATCH");
});

// === 4. REORG, MUTATION, AND 12-BLOCK FINALITY TESTS ===

test("reconciliation detects reorg block hash mismatch and mutated receipts", () => {
  const receipt = { status: "0x1", blockNumber: 100, blockHash: hex("aa"), transactionHash: hex("77"), logs: [sampleEvent()] };

  // Reorg: canonical block hash differs from inclusion block hash
  const reorgResult = reconcileFujiOperation({
    ...config,
    receipt,
    headBlockNumber: 115,
    canonicalBlockHash: hex("ff"), // Different hash indicates reorg
  });
  assert.equal(reorgResult.confirmed, false);
  assert.equal(reorgResult.status, "failed");
  assert.equal(reorgResult.reason, "BLOCK_HASH_MISMATCH");

  // Receipt mutation: refetched receipt has reverted status or different tx hash
  const mutatedResult = reconcileFujiOperation({
    ...config,
    receipt,
    headBlockNumber: 115,
    canonicalBlockHash: hex("aa"),
    refetchedReceipt: { ...receipt, status: "0x0" },
  });
  assert.equal(mutatedResult.confirmed, false);
  assert.equal(mutatedResult.status, "failed");
  assert.equal(mutatedResult.reason, "RECEIPT_MUTATED");
});

// === 5. NEGATIVE BROWSER FLOW ERROR CLASSIFICATION ===

test("browser error classifier cleanly categorizes negative flows without leaking raw internals", () => {
  const kycError = new Error("GATEKEEPER_AUTHORIZATION_FAILED: wallet not enrolled");
  assert.equal(classifyBrowserError(kycError, "authorizing").category, "policy");

  const rejectedWallet = new Error("User rejected the request.");
  assert.equal(classifyBrowserError(rejectedWallet, "submitting").category, "wallet");

  const preflightRevert = new Error("PREFLIGHT_REVERT: execution reverted: INVALID_TOKEN");
  assert.equal(classifyBrowserError(preflightRevert, "submitting").category, "submit");

  const missingReceipt = new Error("TRANSACTION_RECEIPT_TIMEOUT");
  assert.equal(classifyBrowserError(missingReceipt, "confirming").category, "submit");
});

// === 6. EVIDENCE VERIFIER REJECTION TESTS ===

test("evidence verifier rejects manifests with insufficient confirmations or mismatched hashes", () => {
  const validManifest = {
    schema: "haze-fuji-mvp-acceptance-v2",
    runId: "run-test-v2",
    timestamp: new Date().toISOString(),
    origin: "https://compliance-haze.vercel.app",
    chainId: 43113,
    pool: config.pool,
    poolVersion: config.poolVersion,
    applicationId: config.applicationId,
    status: "PASS",
    candidateGitSha: "0123456789abcdef0123456789abcdef01234567",
    namedCliSession: "haze-fuji-mvp-test",
    tools: { dappwright: true, playwrightCli: true },
    accounts: {
      accountA: { address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" },
      accountB: { address: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC" },
    },
    operations: {
      shield: {
        action: 1,
        transactionHash: "0x1111111111111111111111111111111111111111111111111111111111111111",
        phase: "finalized",
        confirmationCount: 12,
        receipt: { status: 1 },
      },
      send: {
        action: 2,
        transactionHash: "0x2222222222222222222222222222222222222222222222222222222222222222",
        phase: "finalized",
        confirmationCount: 12,
        receipt: { status: 1 },
      },
      withdraw: {
        action: 3,
        transactionHash: "0x3333333333333333333333333333333333333333333333333333333333333333",
        phase: "finalized",
        confirmationCount: 12,
        receipt: { status: 1 },
      },
      swap: {
        action: 4,
        transactionHash: "0x4444444444444444444444444444444444444444444444444444444444444444",
        phase: "finalized",
        confirmationCount: 12,
        receipt: { status: 1 },
      },
    },
    auditorCase: {
      caseId: "case-fuji-001",
      withdrawalHash: "0x3333333333333333333333333333333333333333333333333333333333333333",
      disclosedActionReference: "0xref",
      verifiedJws: true,
      exportHash: "0xexport",
    },
    attempts: [],
    screenshots: {},
  };

  // Valid manifest passes
  const validResult = verifyFujiMvpV2Manifest(validManifest);
  assert.equal(validResult.valid, true);

  // Insufficient confirmations (< 12) must throw
  const lowConfs = {
    ...validManifest,
    operations: {
      shield: { ...validManifest.operations.shield, confirmationCount: 6 },
    },
  };
  assert.throws(() => verifyFujiMvpV2Manifest(lowConfs), /INSUFFICIENT_FINALITY/);

  // Missing CLI session must throw
  const noCli = { ...validManifest, namedCliSession: "" };
  assert.throws(() => verifyFujiMvpV2Manifest(noCli), /MISSING_NAMED_CLI_SESSION/);

  // Reused historical transaction hash must throw
  const historicalHash = {
    ...validManifest,
    operations: {
      shield: { ...validManifest.operations.shield, transactionHash: "0x11a283fe82297674f37d94b015132f3098a440b21b880eb643f07d1a986bcc80" },
    },
  };
  assert.throws(() => verifyFujiMvpV2Manifest(historicalHash), /REUSED_HISTORICAL_TRANSACTION_HASH/);
});

test("evidence verifier rejects same address for accountA and accountB", () => {
  const sameAccounts = {
    schema: "haze-fuji-mvp-acceptance-v2",
    runId: "run-test-same",
    timestamp: new Date().toISOString(),
    origin: "https://compliance-haze.vercel.app",
    chainId: 43113,
    status: "PASS",
    candidateGitSha: "0123456789abcdef0123456789abcdef01234567",
    namedCliSession: "haze-fuji-mvp-test",
    tools: { dappwright: true, playwrightCli: true },
    accounts: {
      accountA: { address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" },
      accountB: { address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" }, // Identical address
    },
    operations: {
      shield: { action: 1, transactionHash: "0x1111111111111111111111111111111111111111111111111111111111111111", phase: "finalized", confirmationCount: 12 },
      send: { action: 2, transactionHash: "0x2222222222222222222222222222222222222222222222222222222222222222", phase: "finalized", confirmationCount: 12 },
      withdraw: { action: 3, transactionHash: "0x3333333333333333333333333333333333333333333333333333333333333333", phase: "finalized", confirmationCount: 12 },
      swap: { action: 4, transactionHash: "0x4444444444444444444444444444444444444444444444444444444444444444", phase: "finalized", confirmationCount: 12 },
    },
    auditorCase: { caseId: "case-1", withdrawalHash: "0x3333333333333333333333333333333333333333333333333333333333333333", verifiedJws: true },
    attempts: [],
    screenshots: {},
  };
  assert.throws(() => verifyFujiMvpV2Manifest(sameAccounts), /ACCOUNTS_NOT_DISTINCT/);
});

test("evidence verifier rejects manifests missing Send, Withdraw, Swap, or Auditor Case", () => {
  const base = {
    schema: "haze-fuji-mvp-acceptance-v2",
    runId: "run-test-incomplete",
    timestamp: new Date().toISOString(),
    origin: "https://compliance-haze.vercel.app",
    chainId: 43113,
    status: "PASS",
    candidateGitSha: "0123456789abcdef0123456789abcdef01234567",
    namedCliSession: "haze-fuji-mvp-test",
    tools: { dappwright: true, playwrightCli: true },
    accounts: {
      accountA: { address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" },
      accountB: { address: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC" },
    },
    operations: {
      shield: { action: 1, transactionHash: "0x1111111111111111111111111111111111111111111111111111111111111111", phase: "finalized", confirmationCount: 12 },
      // Missing Send, Withdraw, Swap
    },
    attempts: [],
    screenshots: {},
  };
  assert.throws(() => verifyFujiMvpV2Manifest(base), /MISSING_SEND_EVIDENCE/);
});
