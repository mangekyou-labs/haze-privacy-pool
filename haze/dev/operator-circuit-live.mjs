#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { functionSelector, keccakHex } from "../sdk/typescript/src/abi.ts";
import {
  assertCommittedFujiUntouched,
  detectPoolNoteTree,
  isPlaceholderPolicyRoot,
  planLiveCircuitDeposit,
} from "./operator-circuit-deposit.mjs";
import {
  buildLiveDepositWitness,
  buildLiveWithdrawWitness,
  SparseMerkleTree,
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
const NOTE_TREE_DOMAIN = "haze/avalanche/v1/note-tree-node";
const ZERO_BYTES32 = `0x${"00".repeat(32)}`;
const PRIVATE_TRANSACTION_SIGNATURE =
  "PrivateTransaction(bytes32,uint8,address,uint64,uint64,uint256,uint256,uint256,uint256,uint256,uint64,address,bytes32,bytes32,uint256,bytes32,bytes,bytes,bytes)";
export const PRIVATE_TRANSACTION_TOPIC = keccakHex(Buffer.from(PRIVATE_TRANSACTION_SIGNATURE));
const NEXT_INDEX_SELECTOR = functionSelector("nextIndex()");
const CURRENT_ROOT_SELECTOR = functionSelector("currentRoot()");
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

function normalizedBytes32(value) {
  try {
    const parsed = BigInt(value);
    if (parsed < 0n || parsed >= (1n << 256n)) {
      throw new Error("out of range");
    }
    return `0x${parsed.toString(16).padStart(64, "0")}`;
  } catch {
    throw coded("TREE_SNAPSHOT_INVALID", "tree snapshot contains an invalid field");
  }
}

function normalizedQuantity(value, label) {
  try {
    const parsed = BigInt(value);
    if (parsed < 0n) {
      throw new Error("negative");
    }
    return parsed;
  } catch {
    throw coded("TREE_SNAPSHOT_INVALID", `tree snapshot ${label} is invalid`);
  }
}

function normalizeBlockTag(value) {
  const parsed = normalizedQuantity(value, "blockTag");
  return `0x${parsed.toString(16)}`;
}

function wordsFromData(data) {
  if (typeof data !== "string" || !/^0x[0-9a-fA-F]*$/.test(data)) {
    throw coded("TREE_SNAPSHOT_INVALID", "PrivateTransaction data is invalid");
  }
  const body = data.slice(2);
  if (body.length % 64 !== 0 || body.length < 16 * 64) {
    throw coded("TREE_SNAPSHOT_INVALID", "PrivateTransaction data is truncated");
  }
  return body.match(/.{64}/g) ?? [];
}

function decodePrivateTransaction(log, pool) {
  if (!log || log.removed === true || !Array.isArray(log.topics) || log.topics.length < 4) {
    throw coded("TREE_SNAPSHOT_INVALID", "PrivateTransaction log is incomplete");
  }
  if (String(log.address).toLowerCase() !== String(pool).toLowerCase()) {
    throw coded("TREE_SNAPSHOT_INVALID", "PrivateTransaction log has an unexpected pool address");
  }
  if (String(log.topics[0]).toLowerCase() !== PRIVATE_TRANSACTION_TOPIC.toLowerCase()) {
    throw coded("TREE_SNAPSHOT_INVALID", "unexpected event in PrivateTransaction history");
  }
  const words = wordsFromData(log.data);
  const outputCommitments = [words[5], words[6]].map((word) => normalizedBytes32(`0x${word}`));
  const position = {
    blockNumber: normalizedQuantity(log.blockNumber, "blockNumber"),
    transactionIndex: normalizedQuantity(log.transactionIndex, "transactionIndex"),
    logIndex: normalizedQuantity(log.logIndex, "logIndex"),
  };
  return { outputCommitments, position };
}

function locallyComputedTreeRoot(leaves) {
  const tree = new SparseMerkleTree(NOTE_TREE_DOMAIN);
  for (const leaf of leaves) {
    tree.insert(leaf.leafIndex, leaf.commitment);
  }
  return normalizedBytes32(tree.root());
}

export function validateLivePoolTreeSnapshot(snapshot) {
  if (!snapshot || snapshot.blockTag == null || snapshot.nextIndex == null || snapshot.currentRoot == null) {
    throw coded("TREE_SNAPSHOT_INVALID", "tree snapshot is missing chain state");
  }
  const nextIndex = normalizedQuantity(snapshot.nextIndex, "nextIndex");
  if (nextIndex > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw coded("TREE_SNAPSHOT_INVALID", "tree snapshot nextIndex is too large");
  }
  const commitments = new Set();
  const leaves = Array.isArray(snapshot.leaves) ? snapshot.leaves.map((leaf, index) => {
    if (!leaf || Number(leaf.leafIndex) !== index) {
      throw coded("TREE_SNAPSHOT_INVALID", "tree snapshot leaves are missing or misordered");
    }
    const commitment = normalizedBytes32(leaf.commitment);
    if (commitment === ZERO_BYTES32) {
      throw coded("TREE_SNAPSHOT_INVALID", "tree snapshot contains a zero commitment");
    }
    if (commitments.has(commitment)) {
      throw coded("TREE_SNAPSHOT_INVALID", "tree snapshot repeats a commitment");
    }
    commitments.add(commitment);
    return { leafIndex: index, commitment };
  }) : null;
  if (!leaves || BigInt(leaves.length) !== nextIndex) {
    throw coded("TREE_SNAPSHOT_INVALID", "tree snapshot leaf count disagrees with nextIndex");
  }
  const currentRoot = normalizedBytes32(snapshot.currentRoot);
  let recomputed;
  try {
    recomputed = locallyComputedTreeRoot(leaves);
  } catch (error) {
    if (error?.code === "TREE_SNAPSHOT_INVALID") {
      throw error;
    }
    throw coded("TREE_SNAPSHOT_INVALID", "tree snapshot Poseidon root could not be recomputed");
  }
  if (recomputed !== currentRoot) {
    throw coded("TREE_SNAPSHOT_INVALID", "tree snapshot root disagrees with currentRoot()");
  }
  return {
    blockTag: normalizeBlockTag(snapshot.blockTag),
    nextIndex: Number(nextIndex),
    currentRoot,
    leaves,
  };
}

async function rpcRequest(rpc, method, params) {
  let response;
  try {
    response = await fetch(rpc, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    const json = await response.json();
    if (json?.error || json?.result == null) {
      throw new Error(json?.error?.message ?? `${method} failed`);
    }
    return json.result;
  } catch (error) {
    if (error?.code === "TREE_SNAPSHOT_INVALID") {
      throw error;
    }
    throw coded("TREE_SNAPSHOT_INVALID", `Fuji ${method} snapshot request failed`);
  }
}

export async function fetchLivePoolTreeSnapshot(sidecar) {
  const rpc = sidecar?.live_rpc;
  const pool = sidecar?.addresses?.HazePoolPoseidon ?? sidecar?.addresses?.HazePool;
  if (!rpc || !pool) {
    throw coded("TREE_SNAPSHOT_INVALID", "live sidecar is missing Fuji RPC or pool address");
  }
  const pinnedBlockTag = normalizeBlockTag(await rpcRequest(rpc, "eth_blockNumber", []));
  const [logs, nextIndexReturn, currentRootReturn] = await Promise.all([
    rpcRequest(rpc, "eth_getLogs", [{
      address: pool,
      fromBlock: "0x0",
      toBlock: pinnedBlockTag,
      topics: [PRIVATE_TRANSACTION_TOPIC],
    }]),
    rpcRequest(rpc, "eth_call", [{ to: pool, data: NEXT_INDEX_SELECTOR }, pinnedBlockTag]),
    rpcRequest(rpc, "eth_call", [{ to: pool, data: CURRENT_ROOT_SELECTOR }, pinnedBlockTag]),
  ]);
  if (!Array.isArray(logs)) {
    throw coded("TREE_SNAPSHOT_INVALID", "Fuji eth_getLogs did not return an array");
  }
  const decoded = logs.map((log) => decodePrivateTransaction(log, pool));
  const pinnedBlockNumber = normalizedQuantity(pinnedBlockTag, "blockTag");
  if (decoded.some((event) => event.position.blockNumber > pinnedBlockNumber)) {
    throw coded("TREE_SNAPSHOT_INVALID", "PrivateTransaction log is newer than the pinned block");
  }
  decoded.sort((left, right) => {
    for (const key of ["blockNumber", "transactionIndex", "logIndex"]) {
      if (left.position[key] !== right.position[key]) {
        return left.position[key] < right.position[key] ? -1 : 1;
      }
    }
    return 0;
  });
  for (let index = 1; index < decoded.length; index += 1) {
    const previous = decoded[index - 1].position;
    const current = decoded[index].position;
    if (
      previous.blockNumber === current.blockNumber &&
      previous.transactionIndex === current.transactionIndex &&
      previous.logIndex === current.logIndex
    ) {
      throw coded("TREE_SNAPSHOT_INVALID", "Fuji event history contains duplicate log positions");
    }
  }
  const leaves = [];
  for (const event of decoded) {
    for (const commitment of event.outputCommitments) {
      if (commitment !== ZERO_BYTES32) {
        leaves.push({ leafIndex: leaves.length, commitment });
      }
    }
  }
  return validateLivePoolTreeSnapshot({
    blockTag: pinnedBlockTag,
    nextIndex: normalizedQuantity(nextIndexReturn, "nextIndex").toString(),
    currentRoot: normalizedBytes32(currentRootReturn),
    leaves,
  });
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
  const leafIndex = Number(input.leafIndex ?? occupiedLeaves.length);
  if (input.secret !== undefined || input.blinding !== undefined) {
    const plan = planLiveCircuitTransact({ ...input, action: "deposit", leafIndex });
    if (occupied.has(plan.note.commitment.toLowerCase())) {
      throw coded("COMMITMENT_DUPLICATE", "note commitment already on the live pool");
    }
    return plan;
  }
  const secret =
    input.secret ?? (process.env.HAZE_NOTE_SECRET !== undefined ? Number(process.env.HAZE_NOTE_SECRET) : 1);
  for (let blinding = 2; blinding < 10_000; blinding += 1) {
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
    usdc: input.usdc ?? overlay.usdc,
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
          usdc: bindings.usdc,
          actionReference: input.actionReference,
          caseTag: input.caseTag,
          treeLeaves: input.treeLeaves,
        })
      : buildLiveDepositWitness({
          ...bindings,
          publicAmount: input.publicAmount ?? 1_000_000,
          usdc: bindings.usdc,
          actionReference: input.actionReference,
          caseTag: input.caseTag,
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
    publicAmount: Number(witness.circom.publicAmount),
    publicRecipient: witness.publicRecipient,
    usdc: bindings.usdc,
    auditRecord: witness.auditRecord,
    auditRecordBytes: witness.auditRecordBytes,
    auditKeyVersion: witness.auditKeyVersion,
    auditDevelopmentFixture: witness.auditDevelopmentFixture,
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
    publicRecipient: plan.publicRecipient ?? "0x0000000000000000000000000000000000000000",
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
    auditRecord: plan.auditRecord,
    auditRecordBytes: plan.auditRecordBytes,
    auditKeyVersion: plan.auditKeyVersion,
    auditDevelopmentFixture: plan.auditDevelopmentFixture,
    actionReference: plan.auditRecord?.facts?.actionReference,
    proofBytes: proofArtifact.proofBytes,
    publicSignals: proofArtifact.publicSignals,
    artifactHash: proofArtifact.artifactHash,
  };
  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, `${JSON.stringify(artifact, null, 2)}\n`);
  return artifact;
}

export async function persistLiveCircuitNote(input = {}) {
  refuseFlips(input);
  if (input.productionCeremonyApproved === true) {
    throw coded("KEYS_MISSING", "production ceremony stays KEYS_MISSING");
  }
  const plan = input.plan;
  if (!plan?.note) {
    throw coded("WITNESS_INVALID", "circuit note is missing");
  }
  if (input.receipt && input.receipt.status !== "0x1") {
    throw coded("RECEIPT_REVERTED", "deposit receipt is not successful");
  }
  const snapshot = input.snapshot
    ? validateLivePoolTreeSnapshot(input.snapshot)
    : await fetchLivePoolTreeSnapshot(loadOverlay(input.overlayPath ?? LIVE_OVERLAY_PATH));
  const leafIndex = Number(plan.note.leafIndex);
  const chainLeaf = snapshot.leaves[leafIndex];
  if (!chainLeaf || chainLeaf.commitment.toLowerCase() !== String(plan.note.commitment).toLowerCase()) {
    throw coded("TREE_SNAPSHOT_INVALID", "mined deposit commitment is absent at its planned leaf");
  }
  const outputPath = input.notePath ?? NOTE_SECRET_PATH;
  mkdirSync(dirname(outputPath), { recursive: true });
  const stored = {
    not_for_production: true,
    note: plan.note,
    pool: plan.pool,
    treeLeaves: snapshot.leaves,
  };
  writeFileSync(outputPath, `${JSON.stringify(stored, null, 2)}\n`);
  return stored;
}

export async function proveLiveCircuit(input = {}) {
  let plan = input.plan;
  let snapshot = input.snapshot;
  if (input.action === "withdraw" || plan?.action === 3) {
    const overlay = loadOverlay(input.overlayPath ?? LIVE_OVERLAY_PATH);
    snapshot = validateLivePoolTreeSnapshot(snapshot ?? await fetchLivePoolTreeSnapshot(overlay));
    const note = input.note ?? plan?.note;
    if (!note) {
      throw coded("WITNESS_INVALID", "withdraw note is missing");
    }
    const authoritativePlan = planLiveCircuitTransact({
      ...input,
      action: "withdraw",
      note,
      treeLeaves: snapshot.leaves,
    });
    if (
      input.noteTreeRoot !== undefined &&
      String(input.noteTreeRoot).toLowerCase() !== snapshot.currentRoot.toLowerCase()
    ) {
      throw coded("ROOT_STALE", "planned note tree root is stale");
    }
    if (authoritativePlan.circom.noteTreeRoot.toLowerCase() !== snapshot.currentRoot.toLowerCase()) {
      throw coded("ROOT_STALE", "authoritative note tree root changed");
    }
    if (plan?.circom?.noteTreeRoot && plan.circom.noteTreeRoot.toLowerCase() !== snapshot.currentRoot.toLowerCase()) {
      throw coded("ROOT_STALE", "withdraw plan was built against a stale root");
    }
    plan = authoritativePlan;
  } else {
    plan = plan ?? planUnusedLiveCircuitDeposit(input);
  }
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
  if (plan.action === 1 && input.persist === true) {
    if (!snapshot) {
      throw coded("TREE_SNAPSHOT_INVALID", "deposit persistence requires an authoritative chain snapshot");
    }
    await persistLiveCircuitNote({
      ...input,
      plan,
      snapshot,
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
    const snapshot = await fetchLivePoolTreeSnapshot(loadOverlay());
    process.stdout.write(
      `${JSON.stringify(
        planLiveCircuitTransact({ action: "withdraw", note: stored.note, treeLeaves: snapshot.leaves }),
        null,
        2,
      )}\n`,
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
