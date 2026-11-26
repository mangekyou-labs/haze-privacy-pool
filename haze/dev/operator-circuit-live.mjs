#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertCommittedFujiUntouched,
  detectPoolNoteTree,
  isPlaceholderPolicyRoot,
  planLiveCircuitDeposit,
} from "./operator-circuit-deposit.mjs";
import {
  buildLiveDepositWitness,
  buildLiveWithdrawWitness,
} from "./operator-circuit-witness.mjs";
import {
  FUJI_RPC,
  LIVE_OVERLAY_PATH,
  LIVE_POSEIDON_BLOCKLIST_ROOT,
  LIVE_POSEIDON_MEMBERSHIP_ROOT,
  loadPrivateKey,
} from "./fuji-live-deploy.mjs";
import { DEFAULT_OUTPUT, DEFAULT_ZKEY, runOperatorProve } from "./operator-prove.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const POSEIDON_POOL_SOL = join(HAZE_ROOT, "contracts/src/HazePoolPoseidon.sol");
const FUJI_PACKAGE = join(HAZE_ROOT, "deployments/fuji-v1.json");
const PRIVATE_DIR = join(HAZE_ROOT, "dev/artifacts/ceremony-private");
export const LIVE_POSEIDON_POOL = "0x00BEB0A5D709d0F093952fD374Dbbf3d0d21d550";
export const LIVE_OPERATOR = "0xeD37FD0d6F0f69236E7472B36796e133D20EcC32";
export const LIVE_APP_ID = `0x${(0xa11n).toString(16).padStart(64, "0")}`;
export const LIVE_POOL_VERSION = `0x${(0xb001n).toString(16).padStart(64, "0")}`;
export const DEPOSIT_ARTIFACT = join(PRIVATE_DIR, "fuji-poseidon-deposit.json");
export const WITHDRAW_ARTIFACT = join(PRIVATE_DIR, "fuji-poseidon-withdraw.json");
export const NOTE_SECRET_PATH = join(PRIVATE_DIR, "fuji-poseidon-note.json");
export const DEPOSIT_TRANSACT = join(PRIVATE_DIR, "fuji-poseidon-deposit-tx.json");
export const WITHDRAW_TRANSACT = join(PRIVATE_DIR, "fuji-poseidon-withdraw-tx.json");

function coded(code, message) {
  return Object.assign(new Error(message), { code });
}

function loadOverlay(path = LIVE_OVERLAY_PATH) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function refuseFlips(input) {
  if (input.flipFujiBroadcast === true || input.writeCommittedFuji === true) {
    throw coded("SC-09", "refusing to write committed fuji-v1.json");
  }
  if (input.mainnetAuthorized === true) {
    throw coded("SC-09", "mainnet 43114 is not authorized");
  }
}

export function occupiedLiveLeaves(overlay) {
  const tx = overlay?.transactions ?? {};
  const leaves = [];
  for (const [key, value] of Object.entries(tx)) {
    if (typeof value !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(value)) {
      continue;
    }
    if (key === "depositCommitment") {
      leaves.push({ leafIndex: 0, commitment: value });
      continue;
    }
    const indexed = /^deposit(\d+)Commitment$/.exec(key);
    if (indexed) {
      leaves.push({ leafIndex: Number(indexed[1]), commitment: value });
    }
  }
  leaves.sort((a, b) => Number(a.leafIndex) - Number(b.leafIndex));
  return leaves;
}

export function planUnusedLiveCircuitDeposit(input = {}) {
  refuseFlips(input);
  const overlay = loadOverlay(input.overlayPath ?? LIVE_OVERLAY_PATH);
  const occupiedLeaves = input.occupiedLeaves ?? occupiedLiveLeaves(overlay);
  const occupied = new Set(occupiedLeaves.map((leaf) => leaf.commitment.toLowerCase()));
  const sidecarNextIndex = Number(overlay.transactions?.nextIndex);
  const nextIndex = Number.isSafeInteger(sidecarNextIndex) && sidecarNextIndex >= 0
    ? sidecarNextIndex
    : occupiedLeaves.length;
  const leafIndex = Number(input.leafIndex ?? nextIndex);
  if (input.secret !== undefined || input.blinding !== undefined) {
    const plan = planLiveCircuitTransact({ ...input, action: "deposit", leafIndex });
    if (occupied.has(plan.note.commitment.toLowerCase())) {
      throw coded("COMMITMENT_DUPLICATE", "note commitment already on the live pool");
    }
    return plan;
  }
  const secret =
    input.secret ?? (process.env.HAZE_NOTE_SECRET !== undefined ? Number(process.env.HAZE_NOTE_SECRET) : 1);
  const startBlinding = Number(input.startBlinding ?? 2);
  for (let blinding = startBlinding; blinding < 10_000; blinding += 1) {
    const plan = planLiveCircuitTransact({
      ...input,
      action: "deposit",
      secret,
      blinding,
      leafIndex,
    });
    if (!occupied.has(plan.note.commitment.toLowerCase())) {
      return plan;
    }
  }
  throw coded("COMMITMENT_DUPLICATE", "could not find an unused live note");
}

export function planLiveCircuitTransact(input = {}) {
  refuseFlips(input);
  const overlay = loadOverlay(input.overlayPath ?? LIVE_OVERLAY_PATH);
  const poolSourcePath = input.poolSourcePath ?? POSEIDON_POOL_SOL;
  const poolSource = input.poolSource ?? readFileSync(poolSourcePath, "utf8");
  const membershipRoot = input.membershipRoot ?? overlay.membershipRoot ?? LIVE_POSEIDON_MEMBERSHIP_ROOT;
  const hazeBlocklistRoot = input.hazeBlocklistRoot ?? overlay.hazeBlocklistRoot ?? LIVE_POSEIDON_BLOCKLIST_ROOT;
  const depositPlan = planLiveCircuitDeposit({
    ...input,
    poolSource,
    membershipRoot,
    hazeBlocklistRoot,
  });
  const pool = overlay.addresses?.HazePoolPoseidon ?? overlay.addresses?.HazePool;
  if (!pool) {
    throw coded("ENCODING_INVALID", "live sidecar is missing HazePoolPoseidon");
  }
  if (detectPoolNoteTree(poolSource) !== "poseidon2") {
    throw coded("NOTE_TREE_MISMATCH", "live transact requires HazePoolPoseidon");
  }
  if (isPlaceholderPolicyRoot(membershipRoot) || isPlaceholderPolicyRoot(hazeBlocklistRoot)) {
    throw coded("POLICY_INVALID", "live membership/blocklist roots are placeholders");
  }
  const bindings = {
    pool,
    user: input.user ?? LIVE_OPERATOR,
    applicationId: overlay.applicationId ?? LIVE_APP_ID,
    poolVersion: overlay.poolVersion ?? LIVE_POOL_VERSION,
  };
  const action = input.action ?? "deposit";
  const leafIndex = Number(input.leafIndex ?? process.env.HAZE_LEAF_INDEX ?? 0);
  const secret =
    input.secret ?? (process.env.HAZE_NOTE_SECRET !== undefined ? Number(process.env.HAZE_NOTE_SECRET) : 1);
  const blinding =
    input.blinding ??
    (process.env.HAZE_NOTE_BLINDING !== undefined ? Number(process.env.HAZE_NOTE_BLINDING) : 2);
  const witness =
    action === "withdraw"
      ? buildLiveWithdrawWitness({
          ...bindings,
          note: input.note,
          publicAmount: input.publicAmount,
          publicRecipient: input.publicRecipient ?? bindings.user,
          treeLeaves: input.treeLeaves,
        })
      : buildLiveDepositWitness({
          ...bindings,
          publicAmount: input.publicAmount ?? 1_000_000,
          secret,
          blinding,
          leafIndex,
        });
  if (witness.membershipRoot.toLowerCase() !== membershipRoot.toLowerCase()) {
    throw coded("POLICY_INVALID", "witness membership root does not match sidecar");
  }
  if (witness.hazeBlocklistRoot.toLowerCase() !== hazeBlocklistRoot.toLowerCase()) {
    throw coded("POLICY_INVALID", "witness blocklist root does not match sidecar");
  }
  return {
    ...depositPlan,
    action: action === "withdraw" ? 3 : 1,
    caseName: action === "withdraw" ? "withdraw" : "deposit",
    pool,
    user: bindings.user,
    applicationId: bindings.applicationId,
    poolVersion: bindings.poolVersion,
    membershipRoot,
    hazeBlocklistRoot,
    circom: witness.circom,
    note: witness.note,
    envelopes: witness.envelopes,
    noteTreeRoot: witness.noteTreeRoot,
    committedFujiPath: FUJI_PACKAGE,
  };
}

export function writeTransactArtifact(plan, proofArtifact, outputPath) {
  const envelopes = plan.envelopes;
  const artifact = {
    not_for_production: true,
    spend_prove: "KEYS_MISSING",
    production_ceremony_approved: false,
    action: plan.action,
    chainId: 43113,
    pool: plan.pool,
    user: plan.user,
    applicationId: plan.applicationId,
    poolVersion: plan.poolVersion,
    publicAmount: Number(plan.circom.publicAmount),
    publicRecipient:
      plan.action === 3 ? plan.user : "0x0000000000000000000000000000000000000000",
    noteTreeRoot: plan.circom.noteTreeRoot,
    applicationPolicyVersion: Number(plan.circom.applicationPolicyVersion),
    hazePolicyVersion: Number(plan.circom.hazePolicyVersion),
    applicationMembershipRoot: plan.circom.applicationMembershipRoot,
    hazeBlocklistRoot: plan.circom.hazeBlocklistRoot,
    inputNullifier0: plan.circom.inputNullifier0,
    inputNullifier1: plan.circom.inputNullifier1,
    outputCommitment0: plan.circom.outputCommitment0,
    outputCommitment1: plan.circom.outputCommitment1,
    auditDataCommitment: plan.circom.auditDataCommitment,
    recipientCiphertext0: envelopes.recipientCiphertext0,
    recipientCiphertext1: envelopes.recipientCiphertext1,
    auditCiphertext: envelopes.auditCiphertext,
    recipientCiphertextHash0: envelopes.recipientCiphertextHash0,
    recipientCiphertextHash1: envelopes.recipientCiphertextHash1,
    auditCiphertextHash: envelopes.auditCiphertextHash,
    proofBytes: proofArtifact.proofBytes,
    publicSignals: proofArtifact.publicSignals,
    artifactHash: proofArtifact.artifactHash,
  };
  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, `${JSON.stringify(artifact, null, 2)}\n`);
  return artifact;
}

function upsertLeaf(leaves, leaf) {
  if (leaf?.commitment == null || leaf.leafIndex == null) {
    return;
  }
  const next = { leafIndex: leaf.leafIndex, commitment: leaf.commitment };
  const index = leaves.findIndex((item) => Number(item.leafIndex) === Number(leaf.leafIndex));
  if (index >= 0) {
    leaves[index] = next;
  } else {
    leaves.push(next);
  }
}

function mergeTreeLeaves(previous, note, baseLeaves) {
  const leaves = Array.isArray(baseLeaves)
    ? [...baseLeaves]
    : Array.isArray(previous?.treeLeaves)
      ? [...previous.treeLeaves]
      : [];
  if (!baseLeaves) {
    upsertLeaf(leaves, previous?.note);
  }
  upsertLeaf(leaves, note);
  return leaves.sort((a, b) => Number(a.leafIndex) - Number(b.leafIndex));
}

export function persistLiveCircuitNote(input = {}) {
  refuseFlips(input);
  if (input.productionCeremonyApproved === true) {
    throw coded("KEYS_MISSING", "production ceremony stays KEYS_MISSING");
  }
  const plan = input.plan;
  if (!plan?.note) {
    throw coded("WITNESS_INVALID", "circuit note is missing");
  }
  const outputPath = input.notePath ?? NOTE_SECRET_PATH;
  mkdirSync(dirname(outputPath), { recursive: true });
  const previous = existsSync(outputPath) ? JSON.parse(readFileSync(outputPath, "utf8")) : {};
  const overlay = loadOverlay(input.overlayPath ?? LIVE_OVERLAY_PATH);
  const treeLeaves = mergeTreeLeaves(
    previous,
    plan.note,
    input.baseLeaves ?? occupiedLiveLeaves(overlay),
  );
  const stored = {
    not_for_production: true,
    note: plan.note,
    pool: plan.pool,
    treeLeaves,
  };
  writeFileSync(outputPath, `${JSON.stringify(stored, null, 2)}\n`);
  return stored;
}

export function persistLiveCircuitWithdraw(input = {}) {
  refuseFlips(input);
  if (input.productionCeremonyApproved === true) {
    throw coded("KEYS_MISSING", "production ceremony stays KEYS_MISSING");
  }
  if (input.receipt?.status !== "0x1") {
    throw coded("RECEIPT_REVERTED", "withdraw receipt is not mined successfully");
  }
  const outputPath = input.notePath ?? NOTE_SECRET_PATH;
  if (!existsSync(outputPath)) {
    throw coded("KEYS_MISSING", "circuit note is missing");
  }
  const stored = JSON.parse(readFileSync(outputPath, "utf8"));
  if (!stored?.note) {
    throw coded("WITNESS_INVALID", "circuit note is missing");
  }
  if (stored.spent === true) {
    throw coded("NOTE_SPENT", "circuit note has already been withdrawn");
  }
  const plan = input.plan;
  const amount = Number(plan?.intent?.publicAmount ?? plan?.circom?.publicAmount ?? input.amount);
  if (!Number.isSafeInteger(amount) || amount <= 0 || BigInt(amount) !== BigInt(stored.note.value)) {
    throw coded("WITNESS_INVALID", "withdraw amount does not consume the persisted note");
  }
  const withdrawal = {
    amount,
    publicRecipient: plan?.intent?.publicRecipient ?? input.publicRecipient ?? "",
    user: plan?.intent?.user ?? input.user ?? "",
    receiptStatus: input.receipt.status,
  };
  const next = {
    ...stored,
    spent: true,
    withdrawal,
  };
  writeFileSync(outputPath, `${JSON.stringify(next, null, 2)}\n`);
  return next;
}

export async function proveLiveCircuit(input = {}) {
  const plan =
    input.plan ??
    (input.action === "withdraw" ? planLiveCircuitTransact(input) : planUnusedLiveCircuitDeposit(input));
  const leafIndex = Number(plan.note?.leafIndex ?? 0);
  const outputPath =
    input.outputPath ??
    (plan.action === 3
      ? WITHDRAW_ARTIFACT
      : leafIndex > 0
        ? join(PRIVATE_DIR, `fuji-poseidon-deposit-${leafIndex}.json`)
        : DEPOSIT_ARTIFACT);
  const { artifact } = await runOperatorProve({
    ...input,
    circom: plan.circom,
    caseName: plan.caseName,
    outputPath,
    zkeyPath: input.zkeyPath ?? DEFAULT_ZKEY,
  });
  if (plan.action === 1 && input.skipPersist !== true) {
    persistLiveCircuitNote({
      ...input,
      plan,
      notePath: input.notePath ?? NOTE_SECRET_PATH,
    });
  }
  const transactPath =
    input.transactPath ??
    (plan.action === 3
      ? WITHDRAW_TRANSACT
      : leafIndex > 0
        ? join(PRIVATE_DIR, `fuji-poseidon-deposit-${leafIndex}-tx.json`)
        : DEPOSIT_TRANSACT);
  writeTransactArtifact(plan, artifact, transactPath);
  return { plan, artifact, transactPath, outputPath };
}

function runForge(args, env) {
  const result = spawnSync("forge", args, {
    cwd: join(HAZE_ROOT, "contracts"),
    encoding: "utf8",
    env: { ...process.env, ...env, FOUNDRY_DISABLE_NIGHTLY_WARNING: "1" },
  });
  if (result.status !== 0) {
    throw new Error(`forge failed (${result.status}): ${result.stderr || result.stdout}`);
  }
  return { stdout: result.stdout, stderr: result.stderr };
}

export function broadcastLiveCircuitTransact(input = {}) {
  refuseFlips(input);
  assertCommittedFujiUntouched();
  const overlay = loadOverlay(input.overlayPath ?? LIVE_OVERLAY_PATH);
  const transactPath = resolve(input.transactPath ?? DEPOSIT_TRANSACT);
  if (!existsSync(transactPath)) {
    throw coded("WITNESS_INVALID", "transact artifact is missing");
  }
  const privateKey = loadPrivateKey();
  const { stdout } = runForge(
    [
      "script",
      "script/TransactFujiPoseidonLive.s.sol:TransactFujiPoseidonLive",
      "--rpc-url",
      overlay.live_rpc ?? FUJI_RPC,
      "--broadcast",
      "--slow",
    ],
    {
      PRIVATE_KEY: privateKey,
      HAZE_POOL: overlay.addresses.HazePool,
      HAZE_TRANSACT_JSON: transactPath,
    },
  );
  return { stdout, transactPath, pool: overlay.addresses.HazePool };
}

async function main() {
  const command = process.argv[2] ?? "plan";
  if (command === "plan" || command === "plan-deposit") {
    process.stdout.write(`${JSON.stringify(planLiveCircuitTransact({ action: "deposit" }), null, 2)}\n`);
    return;
  }
  if (command === "plan-withdraw") {
    const stored = JSON.parse(readFileSync(NOTE_SECRET_PATH, "utf8"));
    process.stdout.write(
      `${JSON.stringify(planLiveCircuitTransact({ action: "withdraw", note: stored.note, treeLeaves: stored.treeLeaves }), null, 2)}\n`,
    );
    return;
  }
  if (command === "prove-deposit") {
    const result = await proveLiveCircuit({ action: "deposit" });
    process.stdout.write(`${JSON.stringify({ outputPath: result.outputPath, transactPath: result.transactPath }, null, 2)}\n`);
    // snarkjs workers keep the event loop alive after fullProve.
    process.exit(0);
  }
  if (command === "prove-withdraw") {
    const stored = JSON.parse(readFileSync(NOTE_SECRET_PATH, "utf8"));
    const result = await proveLiveCircuit({
      action: "withdraw",
      note: stored.note,
      treeLeaves: stored.treeLeaves,
    });
    process.stdout.write(`${JSON.stringify({ outputPath: result.outputPath, transactPath: result.transactPath }, null, 2)}\n`);
    process.exit(0);
  }
  if (command === "broadcast-deposit") {
    const leafIndex = Number(process.env.HAZE_LEAF_INDEX ?? 0);
    const transactPath =
      leafIndex > 0 ? join(PRIVATE_DIR, `fuji-poseidon-deposit-${leafIndex}-tx.json`) : DEPOSIT_TRANSACT;
    const result = broadcastLiveCircuitTransact({ transactPath });
    process.stdout.write(`${JSON.stringify({ pool: result.pool, transactPath }, null, 2)}\n`);
    return;
  }
  if (command === "broadcast-withdraw") {
    const result = broadcastLiveCircuitTransact({ transactPath: WITHDRAW_TRANSACT });
    process.stdout.write(`${JSON.stringify({ pool: result.pool }, null, 2)}\n`);
    return;
  }
  throw new Error(`unknown command ${command}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
