import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { keccak256 as keccak256Bytes } from "../sdk/typescript/src/keccak.ts";
import { detectPoolNoteTree, planLiveCircuitDeposit } from "../dev/operator-circuit-deposit.mjs";
import {
  fetchLivePoolTreeSnapshot,
  planLiveCircuitTransact,
  LIVE_POSEIDON_POOL,
  PRIVATE_TRANSACTION_TOPIC,
  validateLivePoolTreeSnapshot,
} from "../dev/operator-circuit-live.mjs";
import { planOperatorProve } from "../dev/operator-prove.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const POSEIDON_POOL = join(HAZE_ROOT, "contracts/src/HazePoolPoseidon.sol");
const FUJI = join(HAZE_ROOT, "deployments/fuji-v1.json");
const LIVE = join(HAZE_ROOT, "deployments/fuji-v1.live.json");

const FULL_CHAIN_LEAVES = [
  { leafIndex: 0, commitment: "0x0acd50a5afb0a74605cea66358fae514a6aba02dce5ee081ae888fee11f716c3" },
  { leafIndex: 1, commitment: "0x214107a40cd5289d482150889bf6c6299c7b347b4e4b2583b95446e08a7085df" },
  { leafIndex: 2, commitment: "0x08cbf5f1fcf47c7c848d2fdcff1e2a7bf05b529d954886994037d96a051a0389" },
  { leafIndex: 3, commitment: "0x2a003882516d7362de42261ebe44c4c84bdacb37417d9c4868f58db0634dabaa" },
];

function eventData(outputCommitment0, outputCommitment1 = `0x${"00".repeat(32)}`) {
  const words = Array.from({ length: 16 }, () => "0".repeat(64));
  words[5] = outputCommitment0.slice(2).padStart(64, "0");
  words[6] = outputCommitment1.slice(2).padStart(64, "0");
  return `0x${words.join("")}`;
}

function privateTransactionLog(outputCommitment0, outputCommitment1, blockNumber, transactionIndex, logIndex) {
  return {
    address: LIVE_POSEIDON_POOL,
    topics: [PRIVATE_TRANSACTION_TOPIC, `0x${"00".repeat(32)}`, `0x${"01".repeat(32)}`, `0x${"00".repeat(12)}${"11".repeat(20)}`],
    data: eventData(outputCommitment0, outputCommitment1),
    blockNumber: `0x${blockNumber.toString(16)}`,
    transactionIndex: `0x${transactionIndex.toString(16)}`,
    logIndex: `0x${logIndex.toString(16)}`,
  };
}

function keccakHex(hex) {
  const body = hex.startsWith("0x") ? hex.slice(2) : hex;
  return `0x${Buffer.from(keccak256Bytes(Buffer.from(body, "hex"))).toString("hex")}`;
}

test("live transact plan binds the Poseidon sidecar and refuses keccak HazePool.sol", () => {
  assert.throws(() => planLiveCircuitTransact({ action: "deposit", poolSourcePath: join(HAZE_ROOT, "contracts/src/HazePool.sol") }), (error) => {
    assert.equal(error.code, "NOTE_TREE_MISMATCH");
    return true;
  });
  const plan = planLiveCircuitTransact({ action: "deposit" });
  assert.equal(plan.noteTree, "poseidon2");
  assert.equal(plan.action, 1);
  assert.equal(plan.chainId, 43113);
  assert.equal(plan.pool.toLowerCase(), LIVE_POSEIDON_POOL.toLowerCase());
  assert.equal(plan.circom.action, "1");
  assert.equal(plan.circom.publicAmount, "1000000");
  assert.equal(plan.envelopes.recipientCiphertext1, "0x");
  assert.equal(plan.envelopes.recipientCiphertextHash1, `0x${"00".repeat(32)}`);
  assert.equal(keccakHex(plan.envelopes.recipientCiphertext0), plan.envelopes.recipientCiphertextHash0);
  assert.equal(keccakHex(plan.envelopes.auditCiphertext), plan.envelopes.auditCiphertextHash);
  assert.equal(plan.spendProve, "KEYS_MISSING");
  assert.equal(plan.notForProduction, true);
  const fuji = JSON.parse(readFileSync(FUJI, "utf8"));
  assert.equal(fuji.broadcast, false);
  assert.equal(fuji.spend_prove, "KEYS_MISSING");
  const live = JSON.parse(readFileSync(LIVE, "utf8"));
  assert.equal(live.addresses.HazePool, plan.pool);
  assert.equal(detectPoolNoteTree(readFileSync(POSEIDON_POOL, "utf8")), "poseidon2");
  assert.equal(planLiveCircuitDeposit({
    poolSource: readFileSync(POSEIDON_POOL, "utf8"),
    membershipRoot: live.membershipRoot,
    hazeBlocklistRoot: live.hazeBlocklistRoot,
  }).noteTree, "poseidon2");
});

test("Fuji pool snapshots reconstruct every event output at one pinned block", async () => {
  const note = JSON.parse(readFileSync(join(HAZE_ROOT, "dev/artifacts/ceremony-private/fuji-poseidon-note.json"), "utf8"));
  const expectedRoot = planLiveCircuitTransact({
    action: "withdraw",
    note: note.note,
    treeLeaves: FULL_CHAIN_LEAVES,
  }).noteTreeRoot;
  const logs = [
    privateTransactionLog(FULL_CHAIN_LEAVES[2].commitment, FULL_CHAIN_LEAVES[3].commitment, 12, 0, 0),
    privateTransactionLog(FULL_CHAIN_LEAVES[0].commitment, `0x${"00".repeat(32)}`, 10, 0, 0),
    privateTransactionLog(FULL_CHAIN_LEAVES[1].commitment, `0x${"00".repeat(32)}`, 11, 0, 0),
  ];
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (_url, options) => {
    const request = JSON.parse(options.body);
    calls.push(request);
    if (request.method === "eth_blockNumber") {
      return { json: async () => ({ result: "0x2a" }) };
    }
    if (request.method === "eth_getLogs") {
      return { json: async () => ({ result: logs }) };
    }
    if (request.method === "eth_call" && request.params[0].data === "0xfc7e9c6f") {
      return { json: async () => ({ result: "0x04" }) };
    }
    if (request.method === "eth_call") {
      return { json: async () => ({ result: expectedRoot }) };
    }
    throw new Error(`unexpected ${request.method}`);
  };
  try {
    const snapshot = await fetchLivePoolTreeSnapshot({
      live_rpc: "https://fuji.invalid/rpc",
      addresses: { HazePool: LIVE_POSEIDON_POOL },
    });
    assert.equal(snapshot.blockTag, "0x2a");
    assert.equal(snapshot.nextIndex, 4);
    assert.equal(snapshot.currentRoot, expectedRoot);
    assert.deepEqual(snapshot.leaves, FULL_CHAIN_LEAVES);
    const logsCall = calls.find((call) => call.method === "eth_getLogs");
    assert.equal(logsCall.params[0].fromBlock, "0x0");
    assert.equal(logsCall.params[0].toBlock, "0x2a");
    assert.deepEqual(calls.filter((call) => call.method === "eth_call").map((call) => call.params[1]), ["0x2a", "0x2a"]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("incomplete or root-inconsistent Fuji history fails closed before proving", () => {
  const note = JSON.parse(readFileSync(join(HAZE_ROOT, "dev/artifacts/ceremony-private/fuji-poseidon-note.json"), "utf8"));
  const rejectedRoot = planLiveCircuitTransact({
    action: "withdraw",
    note: note.note,
    treeLeaves: note.treeLeaves,
  }).noteTreeRoot;
  assert.equal(rejectedRoot, "0x0dd7094b62972e2e0748d99d603225216bd5f406c71ee570018535ce7582fcc6");
  assert.throws(
    () => validateLivePoolTreeSnapshot({ blockTag: "0x2a", nextIndex: 4, currentRoot: rejectedRoot, leaves: note.treeLeaves }),
    (error) => error.code === "TREE_SNAPSHOT_INVALID",
  );
  assert.throws(
    () => validateLivePoolTreeSnapshot({ blockTag: "0x2a", nextIndex: 4, currentRoot: rejectedRoot, leaves: FULL_CHAIN_LEAVES }),
    (error) => error.code === "TREE_SNAPSHOT_INVALID",
  );
});

test("withdraw proving rejects a stale planned root before invoking the prover", async () => {
  const { proveLiveCircuit } = await import("../dev/operator-circuit-live.mjs");
  const stored = JSON.parse(readFileSync(join(HAZE_ROOT, "dev/artifacts/ceremony-private/fuji-poseidon-note.json"), "utf8"));
  const currentRoot = planLiveCircuitTransact({
    action: "withdraw",
    note: stored.note,
    treeLeaves: FULL_CHAIN_LEAVES,
  }).noteTreeRoot;
  await assert.rejects(
    () => proveLiveCircuit({
      action: "withdraw",
      note: stored.note,
      noteTreeRoot: "0x174ca9493d65cb2c0c5117edf3d5596b434379c5d4cce2693649adb30b4b5f76",
      snapshot: {
        blockTag: "0x2a",
        nextIndex: 4,
        currentRoot,
        leaves: FULL_CHAIN_LEAVES,
      },
      zkeyPath: join(HAZE_ROOT, "package.json"),
    }),
    (error) => error.code === "ROOT_STALE",
  );
});

test("deposit persistence never records an absent or reverted commitment", async () => {
  const { persistLiveCircuitNote } = await import("../dev/operator-circuit-live.mjs");
  const dir = mkdtempSync(join(tmpdir(), "haze-note-receipt-"));
  const notePath = join(dir, "fuji-poseidon-note.json");
  try {
    const deposit = planLiveCircuitTransact({ action: "deposit" });
    const fullRoot = planLiveCircuitTransact({
      action: "withdraw",
      note: deposit.note,
      treeLeaves: FULL_CHAIN_LEAVES,
    }).noteTreeRoot;
    const snapshot = validateLivePoolTreeSnapshot({
      blockTag: "0x2a",
      nextIndex: 4,
      currentRoot: fullRoot,
      leaves: FULL_CHAIN_LEAVES,
    });
    await assert.rejects(
      () => persistLiveCircuitNote({
        plan: { ...deposit, note: { ...deposit.note, leafIndex: 2 } },
        notePath,
        snapshot,
        receipt: { status: "0x0" },
      }),
      (error) => error.code === "RECEIPT_REVERTED",
    );
    await assert.rejects(
      () => persistLiveCircuitNote({
        plan: { ...deposit, note: { ...deposit.note, commitment: FULL_CHAIN_LEAVES[0].commitment, leafIndex: 2 } },
        notePath,
        snapshot,
        receipt: { status: "0x1" },
      }),
      (error) => error.code === "TREE_SNAPSHOT_INVALID",
    );
    assert.equal(existsSync(notePath), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("live withdraw plan spends the planned deposit note with unused output hashes at zero", () => {
  const deposit = planLiveCircuitTransact({ action: "deposit" });
  const withdraw = planLiveCircuitTransact({ action: "withdraw", note: deposit.note });
  assert.equal(withdraw.action, 3);
  assert.equal(withdraw.circom.publicAmount, "1000000");
  assert.equal(withdraw.circom.outputCommitment0, `0x${"00".repeat(32)}`);
  assert.equal(withdraw.envelopes.recipientCiphertext0, "0x");
  assert.equal(withdraw.envelopes.recipientCiphertextHash0, `0x${"00".repeat(32)}`);
  assert.equal(withdraw.circom.applicationMembershipRoot, deposit.circom.applicationMembershipRoot);
  assert.notEqual(withdraw.circom.noteTreeRoot, `0x${"00".repeat(32)}`);
});

test("live transact plan refuses production flips and rehearsal zkeys", () => {
  assert.throws(() => planLiveCircuitTransact({ action: "deposit", spendProve: "production" }), (error) => {
    assert.equal(error.code, "KEYS_MISSING");
    return true;
  });
  assert.throws(() => planLiveCircuitTransact({ action: "deposit", productionCeremonyApproved: true }), (error) => {
    assert.equal(error.code, "KEYS_MISSING");
    return true;
  });
  assert.throws(() => planLiveCircuitTransact({ action: "deposit", flipFujiBroadcast: true }), (error) => {
    assert.equal(error.code, "SC-09");
    return true;
  });
  assert.throws(() => planOperatorProve({ spendProve: "production" }), (error) => {
    assert.equal(error.code, "KEYS_MISSING");
    return true;
  });
});

test("hatch deposit plans a note the live pool has not already committed", async () => {
  const { planUnusedLiveCircuitDeposit } = await import("../dev/operator-circuit-live.mjs");
  const live = JSON.parse(readFileSync(LIVE, "utf8"));
  const fixture = planLiveCircuitTransact({ action: "deposit" });
  assert.equal(fixture.note.commitment.toLowerCase(), live.transactions.depositCommitment.toLowerCase());
  assert.equal(Number(fixture.note.leafIndex), 0);
  const unused = planUnusedLiveCircuitDeposit();
  assert.notEqual(unused.note.commitment.toLowerCase(), live.transactions.depositCommitment.toLowerCase());
  assert.notEqual(unused.note.commitment.toLowerCase(), live.transactions.deposit1Commitment.toLowerCase());
  assert.equal(Number(unused.note.leafIndex), 2);
  assert.equal(unused.action, 1);
  assert.throws(() => planUnusedLiveCircuitDeposit({ secret: 1, blinding: 2 }), (error) => {
    assert.equal(error.code, "COMMITMENT_DUPLICATE");
    return true;
  });
  assert.throws(() => planUnusedLiveCircuitDeposit({ writeCommittedFuji: true }), (error) => {
    assert.equal(error.code, "SC-09");
    return true;
  });
  const fuji = JSON.parse(readFileSync(FUJI, "utf8"));
  assert.equal(fuji.broadcast, false);
  assert.equal(fuji.spend_prove, "KEYS_MISSING");
});

test("circuit deposit persist writes a Poseidon note the withdraw planner can spend", async () => {
  const { persistLiveCircuitNote } = await import("../dev/operator-circuit-live.mjs");
  const dir = mkdtempSync(join(tmpdir(), "haze-note-"));
  const notePath = join(dir, "fuji-poseidon-note.json");
  try {
    const deposit = planLiveCircuitTransact({ action: "deposit" });
    const fullLeaves = [
      deposit.note,
      { leafIndex: 1, commitment: "0x214107a40cd5289d482150889bf6c6299c7b347b4e4b2583b95446e08a7085df" },
      { leafIndex: 2, commitment: "0x08cbf5f1fcf47c7c848d2fdcff1e2a7bf05b529d954886994037d96a051a0389" },
      { leafIndex: 3, commitment: "0x2a003882516d7362de42261ebe44c4c84bdacb37417d9c4868f58db0634dabaa" },
    ];
    const fullRoot = planLiveCircuitTransact({
      action: "withdraw",
      note: deposit.note,
      treeLeaves: fullLeaves,
    }).noteTreeRoot;
    const snapshot = validateLivePoolTreeSnapshot({
      blockTag: "0x123",
      nextIndex: 4,
      currentRoot: fullRoot,
      leaves: fullLeaves,
    });
    await persistLiveCircuitNote({ plan: deposit, notePath, snapshot });
    const stored = JSON.parse(readFileSync(notePath, "utf8"));
    assert.equal(stored.not_for_production, true);
    assert.equal(stored.note.commitment, deposit.note.commitment);
    assert.equal(Number(stored.note.leafIndex), Number(deposit.note.leafIndex));
    assert.equal(stored.pool.toLowerCase(), LIVE_POSEIDON_POOL.toLowerCase());
    const withdraw = planLiveCircuitTransact({
      action: "withdraw",
      note: stored.note,
      treeLeaves: stored.treeLeaves,
    });
    assert.equal(withdraw.action, 3);
    assert.equal(withdraw.circom.outputCommitment0, `0x${"00".repeat(32)}`);
    assert.equal(withdraw.note.commitment, stored.note.commitment);
    await assert.rejects(() => persistLiveCircuitNote({ plan: deposit, notePath, writeCommittedFuji: true }), (error) => {
      assert.equal(error.code, "SC-09");
      return true;
    });
    const fuji = JSON.parse(readFileSync(FUJI, "utf8"));
    assert.equal(fuji.broadcast, false);
    assert.equal(fuji.spend_prove, "KEYS_MISSING");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
