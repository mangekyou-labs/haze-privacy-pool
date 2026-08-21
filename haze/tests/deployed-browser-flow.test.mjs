import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import test from "node:test";
import {
  executeFujiBrowserTransaction,
  updateFujiMembershipRoot,
} from "../sdk/typescript/src/browser-fuji-flow.ts";
import { generateBrowserSecrets } from "../sdk/typescript/src/browser-prover.ts";
import { buildSealedBrowserWitness } from "../sdk/typescript/src/browser-witness-flow.ts";
import { planFujiWithdrawalDisclosure } from "../sdk/typescript/src/render-disclosure.ts";
import { buildLiveDepositWitness } from "../dev/operator-circuit-witness.mjs";

const HAZE = resolve(import.meta.dirname, "..");

function source(path) {
  return readFileSync(join(HAZE, path), "utf8");
}

test("the deployed route mounts the browser Fuji client without a live query hatch", () => {
  const route = source("web/apps/haze/app/[route]/page.tsx");
  assert.match(route, /FujiBrowserClient/);
  assert.doesNotMatch(route, /query\.live|live:\s*query\.live|\?live=1/);
});

test("the deployed client composes browser proving, vault, reconciliation, and disclosure", () => {
  const client = source("web/apps/haze/app/[route]/fuji-browser-client.tsx");
  assert.match(client, /browser-prover/);
  assert.match(client, /browser-operation-vault/);
  assert.match(client, /fuji-reconciliation/);
  assert.match(client, /render-disclosure/);
  assert.match(client, /new Worker\(new URL\([^)]*prover-worker/);
  assert.doesNotMatch(client, /\/api\/live-|localhost|127\.0\.0\.1|node:|\bBuffer\b|\bfs\b/);
});

test("the Next worker graph pins web-worker to its browser implementation", () => {
  const config = source("web/apps/haze/next.config.ts");
  assert.match(config, /web-worker.*cjs\/browser\.js/s);
  assert.doesNotMatch(config, /cjs\/node\.js/);
});

test("the browser flow exposes independent transaction and disclosure states", () => {
  const client = source("web/apps/haze/app/[route]/fuji-browser-client.tsx");
  assert.match(client, /data-transaction-status/);
  assert.match(client, /data-disclosure-status/);
  assert.match(client, /recoverFujiOperation/);
  assert.match(client, /markSubmittedBeforeBroadcast/);
});

test("membership update waits for success and binds the refetched policy version", async () => {
  const calls = [];
  const result = await updateFujiMembershipRoot({
    membershipRoot: `0x${"12".repeat(32)}`,
    applicationId: `0x${"34".repeat(32)}`,
    policyAuthority: "0xed37fd0d6f0f69236e7472b36796e133d20ecc32",
    wallet: "0xeD37FD0d6F0f69236E7472B36796e133D20EcC32",
    readApplication: async () => ({ membershipVersion: calls.length === 0 ? 7n : 8n, membershipRoot: calls.length === 0 ? "0xold" : `0x${"12".repeat(32)}` }),
    sendUpdate: async () => { calls.push("send"); return "0xupdate"; },
    waitReceipt: async () => { calls.push("receipt"); return { status: "0x1" }; },
  });
  assert.deepEqual(calls, ["send", "receipt"]);
  assert.equal(result.membershipVersion, 8n);
});

test("each browser operation generates six independent random values", () => {
  let value = 0;
  const secrets = generateBrowserSecrets({ getRandomValues(bytes) { bytes.fill(++value); return bytes; } });
  assert.deepEqual(Object.keys(secrets), ["noteSecret", "blinding", "actionReference", "auditSalt", "recipientHpkeSeed", "auditHpkeSeed"]);
  assert.equal(new Set(Object.values(secrets).map((bytes) => bytes[0])).size, 6);
});

test("browser witness seals real recipient and canonical audit envelopes with one action reference", () => {
  let random = 0;
  const result = buildSealedBrowserWitness({
    buildWitness: buildLiveDepositWitness,
    witnessInput: { pool: "0x00BEB0A5D709d0F093952fD374Dbbf3d0d21d550", user: "0xeD37FD0d6F0f69236E7472B36796e133D20EcC32", applicationId: `0x${"00".repeat(30)}0a11`, poolVersion: `0x${"00".repeat(30)}b001`, publicAmount: 1_000_000, applicationPolicyVersion: 8, hazePolicyVersion: 1 },
    chainId: 43113,
    pool: "0x00BEB0A5D709d0F093952fD374Dbbf3d0d21d550",
    poolVersion: `0x${"00".repeat(30)}b001`, applicationId: `0x${"00".repeat(30)}0a11`,
    auditPublicKey: Uint8Array.from("2a082bd0a097bda77158deadbecf043d15e5d09845bf8cfcd2d294d0b0a4ed04".match(/../g), (byte) => Number.parseInt(byte, 16)),
    auditKeyVersion: 1n, caseTag: new TextEncoder().encode("D7-BROWSER"),
    browserCrypto: { getRandomValues(bytes) { bytes.fill(++random); return bytes; } },
  });
  assert.equal(result.witness.actionReference, result.witness.auditFacts.actionReference);
  assert.equal(result.witness.envelopes.recipientCiphertextHash0, result.recipientEnvelope.hash);
  assert.equal(result.witness.envelopes.auditCiphertextHash, result.auditEnvelope.hash);
  assert.notEqual(result.witness.circom.auditDataCommitment, `0x${"00".repeat(32)}`);
});

test("browser transaction persists before broadcast, waits approval, preflights, and matches its event", async () => {
  const calls = [];
  const operation = { id: "op-1", kind: "deposit", state: "ready_to_submit", note: {}, transaction: {} };
  const result = await executeFujiBrowserTransaction({
    operation,
    approvalTransaction: { to: "0xusdc" },
    poolTransaction: { to: "0xpool" },
    send: async (transaction) => { calls.push(transaction.to === "0xusdc" ? "approval-send" : "pool-send"); return transaction.to === "0xusdc" ? "0xapproval" : "0xpool"; },
    waitReceipt: async (hash) => { calls.push(hash === "0xapproval" ? "approval-receipt" : "pool-receipt"); return { status: "0x1", logs: hash === "0xpool" ? [{}] : [] }; },
    preflight: async () => { calls.push("preflight"); },
    markSubmittedBeforeBroadcast: async (_id, transaction, broadcast) => { calls.push(`persist:${transaction.hash}`); return broadcast(); },
    recordSubmittedHash: async (_id, hash) => { calls.push(`hash:${hash}`); },
    reconcile: () => ({ confirmed: true, event: {} }),
  });
  assert.equal(result.confirmed, true);
  assert.deepEqual(calls, ["approval-send", "approval-receipt", "preflight", "persist:pending", "pool-send", "hash:0xpool", "pool-receipt"]);
});

test("browser withdrawal remains spendable when receipt or event reconciliation fails", async () => {
  for (const receipt of [undefined, { status: "0x0", logs: [] }, { status: "0x1", logs: [] }]) {
    const result = await executeFujiBrowserTransaction({
      operation: { id: "op-w", kind: "withdrawal", state: "ready_to_submit", note: { secret: "kept" }, transaction: {} },
      poolTransaction: { to: "0xpool" },
      send: async () => "0xpool",
      waitReceipt: async () => receipt,
      preflight: async () => {},
      markSubmittedBeforeBroadcast: async (_id, _transaction, broadcast) => broadcast(),
      reconcile: () => ({ confirmed: false, noteSpendable: true }),
    });
    assert.equal(result.noteSpendable, true);
  }
});

test("wallet disclosure uses only Rust-supported fields and binds their canonical hash", () => {
  const plan = planFujiWithdrawalDisclosure({
    transactionHash: `0x${"12".repeat(32)}`,
    applicationId: `0x${"34".repeat(32)}`,
    pool: "0x00BEB0A5D709d0F093952fD374Dbbf3d0d21d550",
    chainId: 43113,
    expiresAt: 1_800_000_000,
  });
  assert.deepEqual(plan.requestedFields, ["user", "amount", "counterparty", "tx_hash", "policy_version"]);
  assert.equal(plan.typedData.message.requestedFieldsHash, "0x4ffe502c8216dceb08eb87ea2edb4ee202c3afb1aac2ccaf6e4dcffae1a80853");
  assert.equal(plan.typedData.message.transactionHash, `0x${"12".repeat(32)}`);
});
