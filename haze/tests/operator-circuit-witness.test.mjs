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
  SparseMerkleTree,
  buildFixtureDepositWitness,
  buildLiveDepositWitness,
  buildLiveSwapWitness,
  buildLiveTransferWitness,
  buildLiveWithdrawWitness,
} from "../dev/operator-circuit-witness.mjs";
import { unionMembershipLeaves } from "../sdk/typescript/src/fuji-membership-store.ts";
import { applicationMember } from "../sdk/typescript/src/policy.ts";
import { APP_TREE } from "../sdk/typescript/src/merkle.ts";

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

test("fixture deposit witness preserves frozen circuit facts with a real audit envelope", () => {
  const { circom } = buildFixtureDepositWitness();
  assert.equal(circom.applicationMembershipRoot, FIXTURE_DEPOSIT_MEMBERSHIP_ROOT);
  assert.equal(circom.outputCommitment0, FIXTURE_DEPOSIT_COMMITMENT);
  assert.equal(circom.hazeBlocklistRoot, BLOCKLIST_SENTINEL_ROOT);
  assert.equal(circom.auditDataCommitment, FIXTURE_DEPOSIT.auditDataCommitment);
  assert.notEqual(circom.auditCiphertextHashHi, FIXTURE_DEPOSIT.auditCiphertextHashHi);
  assert.notEqual(circom.auditCiphertextHashLo, FIXTURE_DEPOSIT.auditCiphertextHashLo);
  assert.notEqual(circom.intentHashHi, FIXTURE_DEPOSIT.intentHashHi);
  assert.notEqual(circom.intentHashLo, FIXTURE_DEPOSIT.intentHashLo);
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

test("browser-planned witnesses bind the post-update application policy version", () => {
  const { circom } = buildLiveDepositWitness({
    pool: LIVE_POOL,
    user: LIVE_OPERATOR,
    applicationId: LIVE_APP,
    poolVersion: LIVE_POOL_VERSION,
    applicationPolicyVersion: 2,
    hazePolicyVersion: 1,
    secret: 7,
    blinding: 8,
  });
  assert.equal(circom.applicationPolicyVersion, "2");
  assert.equal(circom.hazePolicyVersion, "1");
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

test("live transfer witness full send produces action 2 with single output and matching nullifier", () => {
  const deposit = buildLiveDepositWitness({
    pool: LIVE_POOL,
    user: LIVE_OPERATOR,
    applicationId: LIVE_APP,
    poolVersion: LIVE_POOL_VERSION,
    value: 1_000_000,
  });
  const recipientX25519 = `0x${"22".repeat(32)}`;
  const transfer = buildLiveTransferWitness({
    pool: LIVE_POOL,
    user: LIVE_OPERATOR,
    applicationId: LIVE_APP,
    poolVersion: LIVE_POOL_VERSION,
    note: deposit.note,
    sendAmount: 1_000_000,
    recipientX25519,
    recipientSecret: `0x${"14".repeat(32)}`,
    recipientBlinding: `0x${"15".repeat(32)}`,
  });
  assert.equal(transfer.circom.publicRecipient, `0x${"00".repeat(32)}`);
  assert.equal(transfer.circom.inputNullifier0, deposit.note.nullifier);
  assert.equal(transfer.circom.inputNullifier1, `0x${"00".repeat(32)}`);
  assert.notEqual(transfer.circom.outputCommitment0, `0x${"00".repeat(32)}`);
  assert.equal(transfer.circom.outputCommitment1, `0x${"00".repeat(32)}`);
  assert.equal(transfer.recipientNote.value, 1_000_000);
  assert.equal(transfer.recipientNote.x25519, recipientX25519);
  assert.equal(transfer.note, null);
});

test("live transfer witness partial send produces output0 recipient and output1 change", () => {
  const deposit = buildLiveDepositWitness({
    pool: LIVE_POOL,
    user: LIVE_OPERATOR,
    applicationId: LIVE_APP,
    poolVersion: LIVE_POOL_VERSION,
    value: 1_000_000,
  });
  const recipientX25519 = `0x${"22".repeat(32)}`;
  const transfer = buildLiveTransferWitness({
    pool: LIVE_POOL,
    user: LIVE_OPERATOR,
    applicationId: LIVE_APP,
    poolVersion: LIVE_POOL_VERSION,
    note: deposit.note,
    sendAmount: 400_000,
    recipientX25519,
    recipientSecret: `0x${"14".repeat(32)}`,
    recipientBlinding: `0x${"15".repeat(32)}`,
    changeSecret: `0x${"16".repeat(32)}`,
    changeBlinding: `0x${"17".repeat(32)}`,
    changeX25519: deposit.note.x25519,
  });
  assert.equal(transfer.circom.action, "2");
  assert.equal(transfer.circom.publicAmount, "0");
  assert.notEqual(transfer.circom.outputCommitment0, `0x${"00".repeat(32)}`);
  assert.notEqual(transfer.circom.outputCommitment1, `0x${"00".repeat(32)}`);
  assert.equal(transfer.recipientNote.value, 400_000);
  assert.equal(transfer.note.value, 600_000);
  assert.equal(transfer.note.x25519, deposit.note.x25519);
});

test("live transfer with membershipLeaves prepends prior leaves into application tree", () => {
  const deposit = buildLiveDepositWitness({
    pool: LIVE_POOL,
    user: LIVE_OPERATOR,
    applicationId: LIVE_APP,
    poolVersion: LIVE_POOL_VERSION,
    value: 1_000_000,
  });
  const priorMember = {
    npk: `0x${"18".repeat(32)}`,
    enc: `0x${"19".repeat(32)}`,
  };
  const transferWithout = buildLiveTransferWitness({
    pool: LIVE_POOL,
    user: LIVE_OPERATOR,
    applicationId: LIVE_APP,
    poolVersion: LIVE_POOL_VERSION,
    note: deposit.note,
    sendAmount: 1_000_000,
    recipientX25519: `0x${"22".repeat(32)}`,
    recipientSecret: `0x${"14".repeat(32)}`,
    recipientBlinding: `0x${"15".repeat(32)}`,
  });
  const transferWith = buildLiveTransferWitness({
    pool: LIVE_POOL,
    user: LIVE_OPERATOR,
    applicationId: LIVE_APP,
    poolVersion: LIVE_POOL_VERSION,
    note: deposit.note,
    sendAmount: 1_000_000,
    recipientX25519: `0x${"22".repeat(32)}`,
    recipientSecret: `0x${"14".repeat(32)}`,
    recipientBlinding: `0x${"15".repeat(32)}`,
    membershipLeaves: [priorMember],
  });
  assert.notEqual(
    transferWithout.circom.applicationMembershipRoot,
    transferWith.circom.applicationMembershipRoot,
  );
});

test("Shield witness membership root includes stored members then the new output", () => {
  const priorMember = {
    npk: `0x${"18".repeat(32)}`,
    enc: `0x${"19".repeat(32)}`,
  };
  const deposit = buildLiveDepositWitness({
    pool: LIVE_POOL,
    user: LIVE_OPERATOR,
    applicationId: LIVE_APP,
    poolVersion: LIVE_POOL_VERSION,
    value: 1_000_000,
    membershipLeaves: [priorMember],
  });
  const union = unionMembershipLeaves([priorMember], [], [deposit.note]);
  const tree = new SparseMerkleTree(APP_TREE);
  union.forEach((leaf, index) => {
    tree.insert(index, applicationMember(LIVE_APP, leaf.npk, leaf.enc));
  });
  assert.equal(deposit.circom.applicationMembershipRoot, tree.root());
});

test("Withdraw witness membership root includes stored members then the spent input", () => {
  const priorMember = {
    npk: `0x${"18".repeat(32)}`,
    enc: `0x${"19".repeat(32)}`,
  };
  const deposit = buildLiveDepositWitness({
    pool: LIVE_POOL,
    user: LIVE_OPERATOR,
    applicationId: LIVE_APP,
    poolVersion: LIVE_POOL_VERSION,
    value: 1_000_000,
  });
  const withdraw = buildLiveWithdrawWitness({
    pool: LIVE_POOL,
    user: LIVE_OPERATOR,
    applicationId: LIVE_APP,
    poolVersion: LIVE_POOL_VERSION,
    note: deposit.note,
    publicAmount: 1_000_000,
    publicRecipient: LIVE_OPERATOR,
    membershipLeaves: [priorMember, { npk: deposit.note.npk, enc: deposit.note.enc }],
  });
  const union = unionMembershipLeaves(
    [priorMember, { npk: deposit.note.npk, enc: deposit.note.enc }],
    [{ npk: deposit.note.npk, enc: deposit.note.enc }],
    [],
  );
  const tree = new SparseMerkleTree(APP_TREE);
  union.forEach((leaf, index) => {
    tree.insert(index, applicationMember(LIVE_APP, leaf.npk, leaf.enc));
  });
  assert.equal(withdraw.circom.applicationMembershipRoot, tree.root());
});

test("Send witness membership root matches union of stored then in then out leaves", () => {
  const priorMember = {
    npk: `0x${"18".repeat(32)}`,
    enc: `0x${"19".repeat(32)}`,
  };
  const deposit = buildLiveDepositWitness({
    pool: LIVE_POOL,
    user: LIVE_OPERATOR,
    applicationId: LIVE_APP,
    poolVersion: LIVE_POOL_VERSION,
    value: 1_000_000,
  });
  const transfer = buildLiveTransferWitness({
    pool: LIVE_POOL,
    user: LIVE_OPERATOR,
    applicationId: LIVE_APP,
    poolVersion: LIVE_POOL_VERSION,
    note: deposit.note,
    sendAmount: 400_000,
    recipientX25519: `0x${"22".repeat(32)}`,
    recipientSecret: `0x${"14".repeat(32)}`,
    recipientBlinding: `0x${"15".repeat(32)}`,
    changeSecret: `0x${"16".repeat(32)}`,
    changeBlinding: `0x${"17".repeat(32)}`,
    changeX25519: deposit.note.x25519,
    membershipLeaves: [priorMember],
  });
  const union = unionMembershipLeaves(
    [priorMember],
    [{ npk: deposit.note.npk, enc: deposit.note.enc }],
    [transfer.recipientNote, transfer.note],
  );
  const tree = new SparseMerkleTree(APP_TREE);
  union.forEach((leaf, index) => {
    tree.insert(index, applicationMember(LIVE_APP, leaf.npk, leaf.enc));
  });
  assert.equal(transfer.circom.applicationMembershipRoot, tree.root());
});

test("Send witness from a recovered note without owner x25519 diverges from stored envelope membership union", () => {
  const ownerX25519 = `0x${"33".repeat(32)}`;
  const deposit = buildLiveDepositWitness({
    pool: LIVE_POOL,
    user: LIVE_OPERATOR,
    applicationId: LIVE_APP,
    poolVersion: LIVE_POOL_VERSION,
    value: 1_000_000,
    x25519: ownerX25519,
  });
  const recoveredNote = { ...deposit.note };
  delete recoveredNote.x25519;
  const stored = [{ npk: deposit.note.npk, enc: deposit.note.enc }];
  const transfer = buildLiveTransferWitness({
    pool: LIVE_POOL,
    user: LIVE_OPERATOR,
    applicationId: LIVE_APP,
    poolVersion: LIVE_POOL_VERSION,
    note: recoveredNote,
    sendAmount: 400_000,
    recipientX25519: `0x${"22".repeat(32)}`,
    recipientSecret: `0x${"14".repeat(32)}`,
    recipientBlinding: `0x${"15".repeat(32)}`,
    changeSecret: `0x${"16".repeat(32)}`,
    changeBlinding: `0x${"17".repeat(32)}`,
    membershipLeaves: stored,
  });
  const union = unionMembershipLeaves(
    stored,
    [{ npk: recoveredNote.npk, enc: recoveredNote.enc }],
    [transfer.recipientNote, transfer.note],
  );
  const tree = new SparseMerkleTree(APP_TREE);
  union.forEach((leaf, index) => {
    tree.insert(index, applicationMember(LIVE_APP, leaf.npk, leaf.enc));
  });
  assert.notEqual(transfer.circom.applicationMembershipRoot, tree.root());
});

test("Send witness from a recovered note with owner x25519 matches stored envelope membership union", () => {
  const ownerX25519 = `0x${"33".repeat(32)}`;
  const deposit = buildLiveDepositWitness({
    pool: LIVE_POOL,
    user: LIVE_OPERATOR,
    applicationId: LIVE_APP,
    poolVersion: LIVE_POOL_VERSION,
    value: 1_000_000,
    x25519: ownerX25519,
  });
  const recoveredNote = { ...deposit.note, x25519: ownerX25519 };
  const stored = [{ npk: deposit.note.npk, enc: deposit.note.enc }];
  const transfer = buildLiveTransferWitness({
    pool: LIVE_POOL,
    user: LIVE_OPERATOR,
    applicationId: LIVE_APP,
    poolVersion: LIVE_POOL_VERSION,
    note: recoveredNote,
    sendAmount: 400_000,
    recipientX25519: `0x${"22".repeat(32)}`,
    recipientSecret: `0x${"14".repeat(32)}`,
    recipientBlinding: `0x${"15".repeat(32)}`,
    changeSecret: `0x${"16".repeat(32)}`,
    changeBlinding: `0x${"17".repeat(32)}`,
    membershipLeaves: stored,
  });
  const union = unionMembershipLeaves(
    stored,
    [{ npk: recoveredNote.npk, enc: recoveredNote.enc }],
    [transfer.recipientNote, transfer.note],
  );
  const tree = new SparseMerkleTree(APP_TREE);
  union.forEach((leaf, index) => {
    tree.insert(index, applicationMember(LIVE_APP, leaf.npk, leaf.enc));
  });
  assert.equal(transfer.circom.applicationMembershipRoot, tree.root());
});


test("live swap independently binds source input, exact USDC output, and slippage floor", () => {
  const tokenIn = "0x1111111111111111111111111111111111111111";
  const amountIn = "2000000";
  const usdcOut = "1500000";
  const minUsdcOut = 1_490_000;
  const routeHash = `0x${"ab".repeat(32)}`;
  const deadline = 1700000000;
  const swap = buildLiveSwapWitness({
    pool: LIVE_POOL,
    user: LIVE_OPERATOR,
    applicationId: LIVE_APP,
    poolVersion: LIVE_POOL_VERSION,
    value: usdcOut,
    tokenIn,
    amountIn,
    minUsdcOut,
    routeHash,
    deadline,
  });
  assert.equal(swap.circom.action, "4");
  assert.equal(swap.circom.publicAmount, "1500000");
  assert.equal(swap.note.value, 1_500_000);
  assert.equal(swap.circom.inputNullifier0, `0x${"00".repeat(32)}`);
  assert.equal(swap.circom.inputNullifier1, `0x${"00".repeat(32)}`);
  assert.equal(swap.circom.noteTreeRoot, `0x${"00".repeat(32)}`);
  assert.notEqual(swap.circom.outputCommitment0, `0x${"00".repeat(32)}`);
  assert.equal(swap.circom.outputCommitment1, `0x${"00".repeat(32)}`);

  const changedInput = buildLiveSwapWitness({
    pool: LIVE_POOL, user: LIVE_OPERATOR, applicationId: LIVE_APP, poolVersion: LIVE_POOL_VERSION,
    value: usdcOut, tokenIn, amountIn: "2000001", minUsdcOut, routeHash, deadline,
  });
  const changedFloor = buildLiveSwapWitness({
    pool: LIVE_POOL, user: LIVE_OPERATOR, applicationId: LIVE_APP, poolVersion: LIVE_POOL_VERSION,
    value: usdcOut, tokenIn, amountIn, minUsdcOut: minUsdcOut + 1, routeHash, deadline,
  });
  assert.notDeepEqual(
    [changedInput.circom.intentHashHi, changedInput.circom.intentHashLo],
    [swap.circom.intentHashHi, swap.circom.intentHashLo],
  );
  assert.notDeepEqual(
    [changedFloor.circom.intentHashHi, changedFloor.circom.intentHashLo],
    [swap.circom.intentHashHi, swap.circom.intentHashLo],
  );
  assert.equal(changedInput.circom.publicAmount, "1500000");
  assert.equal(changedFloor.circom.publicAmount, "1500000");
});

test("live swap canonicalizes uint256 amountIn representations before intent hashing", () => {
  const canonical = `0x${(2_000_000n).toString(16).padStart(64, "0")}`;
  const hashes = ["2000000", 2_000_000, 2_000_000n, canonical].map((amountIn) => {
    const swap = buildLiveSwapWitness({
      pool: LIVE_POOL, user: LIVE_OPERATOR, applicationId: LIVE_APP, poolVersion: LIVE_POOL_VERSION,
      value: 1_500_000, tokenIn: LIVE_OPERATOR, amountIn, minUsdcOut: 1_490_000,
      routeHash: `0x${"ab".repeat(32)}`, deadline: 1700000000,
    });
    return [swap.circom.intentHashHi, swap.circom.intentHashLo];
  });
  hashes.slice(1).forEach((hash) => assert.deepEqual(hash, hashes[0]));
});

test("live swap rejects invalid exact output values with ENCODING_INVALID", () => {
  for (const value of ["wat", "1.5", 0, -1, Number.MAX_SAFE_INTEGER + 1, 1n << 63n]) {
    assert.throws(() => buildLiveSwapWitness({
      pool: LIVE_POOL, user: LIVE_OPERATOR, applicationId: LIVE_APP, poolVersion: LIVE_POOL_VERSION,
      value, tokenIn: LIVE_OPERATOR, amountIn: "2000000", minUsdcOut: 1_490_000,
      routeHash: `0x${"ab".repeat(32)}`, deadline: 1700000000,
    }), /ENCODING_INVALID/);
  }
});
