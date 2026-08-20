#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { DEFAULT_WASM, planOperatorProve } from "./operator-prove.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const POOL_SOL = join(HAZE_ROOT, "contracts/src/HazePool.sol");
const FUJI_PACKAGE = join(HAZE_ROOT, "deployments/fuji-v1.json");
const PLACEHOLDER_MEMBERSHIP = 0x11n;
const PLACEHOLDER_BLOCKLIST = 0x44n;

function coded(code, message) {
  return Object.assign(new Error(message), { code });
}

function asField(value) {
  if (typeof value === "bigint") {
    return value;
  }
  if (typeof value === "number") {
    return BigInt(value);
  }
  if (typeof value === "string" && value !== "") {
    return BigInt(value);
  }
  return 0n;
}

export function detectPoolNoteTree(source) {
  if (/keccak256\(\s*abi\.encodePacked\(\s*left\s*,\s*right\s*\)\s*\)/.test(source)) {
    return "keccak";
  }
  if (/haze\/avalanche\/v1\/note-tree-node/.test(source) && /poseidon2/i.test(source)) {
    return "poseidon2";
  }
  return "unknown";
}

export function isPlaceholderPolicyRoot(value) {
  const field = asField(value);
  return field === PLACEHOLDER_MEMBERSHIP || field === PLACEHOLDER_BLOCKLIST;
}

export function planLiveCircuitDeposit(input = {}) {
  const provePlan = planOperatorProve({
    inventProductionKeys: input.inventProductionKeys,
    spendProve: input.spendProve,
    productionCeremonyApproved: input.productionCeremonyApproved,
    circuitId: input.circuitId,
    zkeyPath: input.zkeyPath,
    wasmPath: input.wasmPath,
  });
  if (/rehearsal|equality/i.test(provePlan.zkeyPath)) {
    throw coded("ARTIFACT_INVALID", "rehearsal and equality zkeys are not spend keys");
  }
  if (input.flipFujiBroadcast === true || input.writeCommittedFuji === true) {
    throw coded("SC-09", "refusing to write committed fuji-v1.json");
  }
  if (input.mainnetAuthorized === true) {
    throw coded("SC-09", "mainnet 43114 is not authorized");
  }

  const poolSource = input.poolSource ?? readFileSync(POOL_SOL, "utf8");
  const noteTree = detectPoolNoteTree(poolSource);
  if (noteTree !== "poseidon2") {
    throw coded(
      "NOTE_TREE_MISMATCH",
      "live HazePool hashes keccak parents; haze-spend-v1 requires Poseidon2 note-tree-node",
    );
  }

  const membershipRoot = input.membershipRoot ?? `0x${PLACEHOLDER_MEMBERSHIP.toString(16).padStart(64, "0")}`;
  const hazeBlocklistRoot = input.hazeBlocklistRoot ?? `0x${PLACEHOLDER_BLOCKLIST.toString(16).padStart(64, "0")}`;
  if (isPlaceholderPolicyRoot(membershipRoot) || isPlaceholderPolicyRoot(hazeBlocklistRoot)) {
    throw coded(
      "POLICY_INVALID",
      "live membership/blocklist roots are placeholders, not Poseidon trees",
    );
  }

  return {
    ...provePlan,
    action: 1,
    caseName: "deposit",
    chainId: 43113,
    noteTree,
    membershipRoot,
    hazeBlocklistRoot,
    spendProve: "KEYS_MISSING",
    prove: "operator-owned-groth16",
    notForProduction: true,
    broadcast: false,
    committedFujiPath: FUJI_PACKAGE,
    zkeyExists: existsSync(provePlan.zkeyPath),
    wasmExists: existsSync(provePlan.wasmPath ?? DEFAULT_WASM),
  };
}

export function assertCommittedFujiUntouched(path = FUJI_PACKAGE) {
  const fuji = JSON.parse(readFileSync(path, "utf8"));
  if (fuji.broadcast !== false || fuji.spend_prove !== "KEYS_MISSING") {
    throw coded("SC-09", "committed fuji-v1.json must stay broadcast:false / KEYS_MISSING");
  }
  return fuji;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const plan = planLiveCircuitDeposit();
    process.stdout.write(`${JSON.stringify(plan, null, 2)}\n`);
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ code: error.code, message: error.message }, null, 2)}\n`);
    process.exitCode = 1;
  }
}
