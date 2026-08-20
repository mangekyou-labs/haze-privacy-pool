import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  assertCommittedFujiUntouched,
  detectPoolNoteTree,
  planLiveCircuitDeposit,
} from "../dev/operator-circuit-deposit.mjs";
import {
  BLOCKLIST_SENTINEL_ROOT,
  FIXTURE_DEPOSIT_COMMITMENT,
  FIXTURE_DEPOSIT_MEMBERSHIP_ROOT,
  buildFixtureDepositWitness,
  buildLiveDepositWitness,
  buildLiveWithdrawWitness,
} from "../dev/operator-circuit-witness.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const POSEIDON_POOL = join(HAZE_ROOT, "contracts/src/HazePoolPoseidon.sol");
const FUJI = join(HAZE_ROOT, "deployments/fuji-v1.json");
const LIVE_OPERATOR = "0xeD37fd0d6f0f69236e7472b36796e133d20ecc32";
const LIVE_POOL = "0x3333333333333333333333333333333333333333";
const LIVE_APP = `0x${(0xa11n).toString(16).padStart(64, "0")}`;
const LIVE_POOL_VERSION = `0x${(0xb001n).toString(16).padStart(64, "0")}`;

const FIXTURE = JSON.parse(
  readFileSync(join(HAZE_ROOT, "circuits/vectors/v1/haze-spend-v1.json"), "utf8"),
);
const FIXTURE_DEPOSIT = FIXTURE.cases.find((entry) => entry.name === "deposit").circom;

test("sentinel blocklist root matches the frozen circuit vector", () => {
  assert.equal(
    BLOCKLIST_SENTINEL_ROOT,
    "0x2f9120bf4979f6f079577e2eaeb96fd996129dbd24a0855fbd0fe7e30669716d",
  );
  assert.equal(FIXTURE_DEPOSIT.hazeBlocklistRoot, BLOCKLIST_SENTINEL_ROOT);
});

test("fixture deposit witness reproduces frozen membership, commitment, audit, and intent", () => {
  const { circom } = buildFixtureDepositWitness();
  assert.equal(circom.applicationMembershipRoot, FIXTURE_DEPOSIT_MEMBERSHIP_ROOT);
  assert.equal(circom.outputCommitment0, FIXTURE_DEPOSIT_COMMITMENT);
  assert.equal(circom.hazeBlocklistRoot, BLOCKLIST_SENTINEL_ROOT);
  assert.equal(circom.auditDataCommitment, FIXTURE_DEPOSIT.auditDataCommitment);
  assert.equal(circom.intentHashHi, FIXTURE_DEPOSIT.intentHashHi);
  assert.equal(circom.intentHashLo, FIXTURE_DEPOSIT.intentHashLo);
  assert.equal(circom.outputCommitment0, FIXTURE_DEPOSIT.outputCommitment0);
  assert.equal(circom.applicationMembershipRoot, FIXTURE_DEPOSIT.applicationMembershipRoot);
  assert.equal(circom.action, "1");
  assert.equal(circom.publicAmount, "1000000");
  assert.equal(circom.noteTreeRoot, FIXTURE_DEPOSIT.noteTreeRoot);
  assert.deepEqual(circom.outAppMemberSiblings[0], FIXTURE_DEPOSIT.outAppMemberSiblings[0]);
  assert.deepEqual(circom.addressLowerSiblings, FIXTURE_DEPOSIT.addressLowerSiblings);
});

test("live deposit rebind changes pool-bound fields and keeps the sentinel blocklist", () => {
  const { circom, note } = buildLiveDepositWitness({
    pool: LIVE_POOL,
    user: LIVE_OPERATOR,
    applicationId: LIVE_APP,
    poolVersion: LIVE_POOL_VERSION,
  });
  assert.equal(circom.action, "1");
  assert.equal(circom.chainId, "43113");
  assert.equal(circom.hazeBlocklistRoot, BLOCKLIST_SENTINEL_ROOT);
  assert.notEqual(circom.outputCommitment0, FIXTURE_DEPOSIT_COMMITMENT);
  assert.notEqual(circom.applicationMembershipRoot, FIXTURE_DEPOSIT_MEMBERSHIP_ROOT);
  assert.notEqual(circom.auditDataCommitment, FIXTURE_DEPOSIT.auditDataCommitment);
  assert.match(circom.authorizedUser, /ed37fd0d6f0f69236e7472b36796e133d20ecc32$/i);
  assert.match(circom.poolAddress, /3333333333333333333333333333333333333333$/i);
  assert.equal(circom.publicAmount, "1000000");
  assert.equal(note.leafIndex, 0);
  assert.equal(note.value, 1_000_000);
  assert.equal(note.secret, `0x${"00".repeat(31)}01`);
});

test("live withdraw with treeLeaves uses the two-leaf Poseidon root", () => {
  const first = buildLiveDepositWitness({
    pool: LIVE_POOL,
    user: LIVE_OPERATOR,
    applicationId: LIVE_APP,
    poolVersion: LIVE_POOL_VERSION,
  });
  const second = buildLiveDepositWitness({
    pool: LIVE_POOL,
    user: LIVE_OPERATOR,
    applicationId: LIVE_APP,
    poolVersion: LIVE_POOL_VERSION,
    secret: 3,
    blinding: 4,
    leafIndex: 1,
  });
  const naive = buildLiveWithdrawWitness({
    pool: LIVE_POOL,
    user: LIVE_OPERATOR,
    applicationId: LIVE_APP,
    poolVersion: LIVE_POOL_VERSION,
    note: second.note,
  });
  const reconstructed = buildLiveWithdrawWitness({
    pool: LIVE_POOL,
    user: LIVE_OPERATOR,
    applicationId: LIVE_APP,
    poolVersion: LIVE_POOL_VERSION,
    note: second.note,
    treeLeaves: [
      { leafIndex: 0, commitment: first.note.commitment },
      { leafIndex: 1, commitment: second.note.commitment },
    ],
  });
  assert.equal(second.note.leafIndex, 1);
  assert.notEqual(first.note.commitment, second.note.commitment);
  assert.notEqual(naive.circom.noteTreeRoot, reconstructed.circom.noteTreeRoot);
  assert.equal(reconstructed.circom.inputNullifier0, second.note.nullifier);
});

test("live withdraw spends the rebound deposit note to the operator", () => {
  const deposit = buildLiveDepositWitness({
    pool: LIVE_POOL,
    user: LIVE_OPERATOR,
    applicationId: LIVE_APP,
    poolVersion: LIVE_POOL_VERSION,
  });
  const { circom } = buildLiveWithdrawWitness({
    pool: LIVE_POOL,
    user: LIVE_OPERATOR,
    applicationId: LIVE_APP,
    poolVersion: LIVE_POOL_VERSION,
    note: deposit.note,
  });
  assert.equal(circom.action, "3");
  assert.equal(circom.publicAmount, "1000000");
  assert.match(circom.publicRecipient, /ed37fd0d6f0f69236e7472b36796e133d20ecc32$/i);
  assert.equal(circom.outputCommitment0, `0x${"00".repeat(32)}`);
  assert.equal(circom.hazeBlocklistRoot, BLOCKLIST_SENTINEL_ROOT);
  assert.equal(circom.applicationMembershipRoot, deposit.circom.applicationMembershipRoot);
  assert.notEqual(circom.noteTreeRoot, `0x${"00".repeat(32)}`);
  assert.notEqual(circom.inputNullifier0, `0x${"00".repeat(32)}`);
});

test("HazePoolPoseidon.sol is Poseidon2 and plans with witness roots", () => {
  const source = readFileSync(POSEIDON_POOL, "utf8");
  assert.equal(detectPoolNoteTree(source), "poseidon2");
  const { circom } = buildLiveDepositWitness({
    pool: LIVE_POOL,
    user: LIVE_OPERATOR,
    applicationId: LIVE_APP,
    poolVersion: LIVE_POOL_VERSION,
  });
  const plan = planLiveCircuitDeposit({
    poolSource: source,
    membershipRoot: circom.applicationMembershipRoot,
    hazeBlocklistRoot: circom.hazeBlocklistRoot,
  });
  assert.equal(plan.noteTree, "poseidon2");
  assert.equal(plan.action, 1);
  assert.equal(plan.spendProve, "KEYS_MISSING");
  assert.equal(plan.broadcast, false);
  assert.equal(plan.notForProduction, true);
  const fuji = assertCommittedFujiUntouched(FUJI);
  assert.equal(fuji.broadcast, false);
  assert.equal(fuji.spend_prove, "KEYS_MISSING");
});
