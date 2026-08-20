import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { keccak256 as keccak256Bytes } from "../sdk/typescript/src/keccak.ts";
import { detectPoolNoteTree, planLiveCircuitDeposit } from "../dev/operator-circuit-deposit.mjs";
import {
  planLiveCircuitTransact,
  LIVE_POSEIDON_POOL,
} from "../dev/operator-circuit-live.mjs";
import { planOperatorProve } from "../dev/operator-prove.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const POSEIDON_POOL = join(HAZE_ROOT, "contracts/src/HazePoolPoseidon.sol");
const FUJI = join(HAZE_ROOT, "deployments/fuji-v1.json");
const LIVE = join(HAZE_ROOT, "deployments/fuji-v1.live.json");

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
    persistLiveCircuitNote({ plan: deposit, notePath });
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
    assert.throws(() => persistLiveCircuitNote({ plan: deposit, notePath, writeCommittedFuji: true }), (error) => {
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
