#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { keccak256 as keccak256Bytes } from "../sdk/typescript/src/keccak.ts";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const FUJI_PACKAGE = join(HAZE_ROOT, "deployments/fuji-v1.json");
const MAINNET_PACKAGE = join(HAZE_ROOT, "deployments/mainnet-v1.json");
export const FUJI_USDC = "0x5425890298aed601595a70AB815c96711a31Bc65";
export const FUJI_RPC = "https://api.avax-test.network/ext/bc/C/rpc";
export const LIVE_OVERLAY_PATH = join(HAZE_ROOT, "deployments/fuji-v1.live.json");
export const CREATE_ORDER = [
  "HazeAccess",
  "ApplicationRegistry",
  "PolicyRegistry",
  "VersionRegistry",
  "DevelopmentEqualityVerifier",
  "HazeSpendVerifier",
  "HazePool",
  "SwapAndShieldRouter",
  "EmergencyExit",
];
export const PAIRING_CREATE_ORDER = [
  "HazeAccess",
  "ApplicationRegistry",
  "PolicyRegistry",
  "VersionRegistry",
  "DevelopmentEqualityVerifier",
  "Groth16Verifier",
  "HazeOperatorGroth16Adapter",
  "HazeSpendVerifierPairing",
  "HazePool",
  "SwapAndShieldRouter",
  "EmergencyExit",
];
export const POSEIDON_CREATE_ORDER = [
  "HazeAccess",
  "ApplicationRegistry",
  "PolicyRegistry",
  "VersionRegistry",
  "DevelopmentEqualityVerifier",
  "Groth16Verifier",
  "HazeOperatorGroth16Adapter",
  "HazeSpendVerifierPairing",
  "HazePoolPoseidon",
  "SwapAndShieldRouter",
  "EmergencyExit",
];
export const LIVE_POSEIDON_MEMBERSHIP_ROOT =
  "0x15d312c3937a289d3fd541c50355ac3a2122c88498db924c011ac0a619f352c4";
export const LIVE_POSEIDON_BLOCKLIST_ROOT =
  "0x2f9120bf4979f6f079577e2eaeb96fd996129dbd24a0855fbd0fe7e30669716d";

function hexToBytes(hex) {
  const body = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (body.length % 2 !== 0) {
    throw new Error("odd hex length");
  }
  return Buffer.from(body, "hex");
}

function keccak256(data) {
  return Buffer.from(keccak256Bytes(data));
}

function rlpBytes(bytes) {
  if (bytes.length === 1 && bytes[0] < 0x80) {
    return Buffer.from(bytes);
  }
  if (bytes.length <= 55) {
    return Buffer.concat([Buffer.from([0x80 + bytes.length]), bytes]);
  }
  const length = Buffer.from(bytes.length.toString(16).padStart(2, "0"), "hex");
  return Buffer.concat([Buffer.from([0xb7 + length.length]), length, bytes]);
}

function rlpNonce(nonce) {
  if (!Number.isInteger(nonce) || nonce < 0) {
    throw new Error("nonce must be a non-negative integer");
  }
  if (nonce === 0) {
    return Buffer.from([0x80]);
  }
  let hex = nonce.toString(16);
  if (hex.length % 2 !== 0) {
    hex = `0${hex}`;
  }
  return rlpBytes(Buffer.from(hex, "hex"));
}

function rlpList(items) {
  const payload = Buffer.concat(items);
  if (payload.length <= 55) {
    return Buffer.concat([Buffer.from([0xc0 + payload.length]), payload]);
  }
  const length = Buffer.from(payload.length.toString(16).padStart(2, "0"), "hex");
  return Buffer.concat([Buffer.from([0xf7 + length.length]), length, payload]);
}

export function computeCreateAddress(deployer, nonce) {
  const address = hexToBytes(deployer);
  if (address.length !== 20) {
    throw new Error("deployer must be a 20-byte address");
  }
  const encoded = rlpList([rlpBytes(address), rlpNonce(nonce)]);
  return `0x${keccak256(encoded).subarray(12).toString("hex")}`;
}

function loadJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

export function assertCommittedProvenanceUntouched() {
  const fuji = loadJson(FUJI_PACKAGE);
  const mainnet = loadJson(MAINNET_PACKAGE);
  if (fuji.broadcast !== false || fuji.spend_prove !== "KEYS_MISSING") {
    throw Object.assign(new Error("committed Fuji package drifted"), { code: "SC-09" });
  }
  if (mainnet.broadcast === true || mainnet.authorized === true) {
    throw Object.assign(new Error("committed mainnet package drifted"), { code: "SC-09" });
  }
}

export function planLiveFujiDeploy(input = {}) {
  refuseProductionOrProvenanceFlips(input);
  assertCommittedProvenanceUntouched();
  const deployer = (input.deployer ?? "0x0000000000000000000000000000000000000000").toLowerCase();
  const nonce = input.nonce ?? 0;
  const creates = CREATE_ORDER.map((name, index) => ({
    name,
    nonce: nonce + index,
    address: computeCreateAddress(deployer, nonce + index),
  }));
  return {
    chainId: 43113,
    usdc: FUJI_USDC,
    notForProduction: true,
    spendProve: "KEYS_MISSING",
    prove: "development-equality",
    minDelaySeconds: 1,
    rootHistorySize: 4,
    poolVersion: `0x${"00".repeat(30)}b001`,
    publicRpc: FUJI_RPC,
    deployer,
    nonce,
    creates,
    predicted: {
      access: creates[0].address,
      applications: creates[1].address,
      policies: creates[2].address,
      versions: creates[3].address,
      backend: creates[4].address,
      verifier: creates[5].address,
      pool: creates[6].address,
      router: creates[7].address,
      exit: creates[8].address,
    },
  };
}

export function planLiveFujiPairingDeploy(input = {}) {
  refuseProductionOrProvenanceFlips(input);
  assertCommittedProvenanceUntouched();
  const deployer = (input.deployer ?? "0x0000000000000000000000000000000000000000").toLowerCase();
  const nonce = input.nonce ?? 0;
  const creates = PAIRING_CREATE_ORDER.map((name, index) => ({
    name,
    nonce: nonce + index,
    address: computeCreateAddress(deployer, nonce + index),
  }));
  return {
    chainId: 43113,
    usdc: FUJI_USDC,
    notForProduction: true,
    productionCeremonyApproved: false,
    spendProve: "KEYS_MISSING",
    prove: "operator-owned-groth16",
    minDelaySeconds: 1,
    rootHistorySize: 4,
    poolVersion: `0x${"00".repeat(30)}b001`,
    publicRpc: FUJI_RPC,
    deployer,
    nonce,
    creates,
    predicted: {
      access: creates[0].address,
      applications: creates[1].address,
      policies: creates[2].address,
      versions: creates[3].address,
      backend: creates[4].address,
      groth16: creates[5].address,
      adapter: creates[6].address,
      verifier: creates[7].address,
      pool: creates[8].address,
      router: creates[9].address,
      exit: creates[10].address,
    },
  };
}

export function planLiveFujiPoseidonDeploy(input = {}) {
  refuseProductionOrProvenanceFlips(input);
  assertCommittedProvenanceUntouched();
  const deployer = (input.deployer ?? "0x0000000000000000000000000000000000000000").toLowerCase();
  const nonce = input.nonce ?? 0;
  const creates = POSEIDON_CREATE_ORDER.map((name, index) => ({
    name,
    nonce: nonce + index,
    address: computeCreateAddress(deployer, nonce + index),
  }));
  return {
    chainId: 43113,
    usdc: FUJI_USDC,
    notForProduction: true,
    productionCeremonyApproved: false,
    spendProve: "KEYS_MISSING",
    prove: "operator-owned-groth16",
    noteTree: "poseidon2",
    membershipRoot: LIVE_POSEIDON_MEMBERSHIP_ROOT,
    hazeBlocklistRoot: LIVE_POSEIDON_BLOCKLIST_ROOT,
    minDelaySeconds: 1,
    rootHistorySize: 4,
    poolVersion: LIVE_POOL_VERSION,
    applicationId: LIVE_APP_ID,
    publicRpc: FUJI_RPC,
    deployer,
    nonce,
    creates,
    predicted: {
      access: creates[0].address,
      applications: creates[1].address,
      policies: creates[2].address,
      versions: creates[3].address,
      backend: creates[4].address,
      groth16: creates[5].address,
      adapter: creates[6].address,
      verifier: creates[7].address,
      pool: creates[8].address,
      router: creates[9].address,
      exit: creates[10].address,
    },
  };
}

function requireAddress(value, label) {
  if (typeof value !== "string" || !/^0x[a-fA-F0-9]{40}$/.test(value)) {
    throw new Error(`${label} must be a 20-byte address`);
  }
  return value;
}

export const LIVE_APP_ID = `0x${"00".repeat(30)}0a11`;
export const LIVE_POOL_VERSION = `0x${"00".repeat(30)}b001`;
export const LIVE_DEPOSIT_AMOUNT = 1_000_000;

function refuseProductionOrProvenanceFlips(input) {
  if (input.inventProductionKeys === true || input.spendProve === "production") {
    throw Object.assign(new Error("production Groth16 keys remain KEYS_MISSING"), {
      code: "KEYS_MISSING",
    });
  }
  if (input.flipFujiBroadcast === true || input.mainnetAuthorized === true) {
    throw Object.assign(new Error("refusing to flip T7.5 provenance or SC-09"), { code: "SC-09" });
  }
}

export function planLiveFujiDeposit(input = {}) {
  refuseProductionOrProvenanceFlips(input);
  assertCommittedProvenanceUntouched();
  return {
    chainId: 43113,
    usdc: FUJI_USDC,
    pool: requireAddress(input.pool ?? "0x0000000000000000000000000000000000000000", "pool"),
    amount: input.amount ?? LIVE_DEPOSIT_AMOUNT,
    action: 1,
    prove: "development-equality",
    spendProve: "KEYS_MISSING",
    notForProduction: true,
    applicationId: LIVE_APP_ID,
    poolVersion: LIVE_POOL_VERSION,
    membershipVersion: 1,
    hazePolicyVersion: 1,
    publicRpc: FUJI_RPC,
  };
}

export function recordLiveDeposit(input) {
  assertCommittedProvenanceUntouched();
  const overlayPath = input.overlayPath ?? LIVE_OVERLAY_PATH;
  const overlay = loadJson(overlayPath);
  overlay.transactions = {
    ...(overlay.transactions ?? {}),
    deposit: input.depositTx,
    approve: input.approveTx,
    depositAmount: input.amount ?? LIVE_DEPOSIT_AMOUNT,
  };
  writeFileSync(overlayPath, `${JSON.stringify(overlay, null, 2)}\n`);
  assertCommittedProvenanceUntouched();
  return overlay;
}

export function writeLiveOverlay(input) {
  assertCommittedProvenanceUntouched();
  const addresses = input.addresses ?? {};
  for (const name of CREATE_ORDER) {
    if (name === "DevelopmentEqualityVerifier") {
      continue;
    }
    requireAddress(addresses[name], name);
  }
  const overlay = {
    product_id: "haze-avalanche-compliant-pool",
    network: "fuji",
    chainId: 43113,
    usdc: FUJI_USDC,
    not_for_production: true,
    broadcast: true,
    live_rpc: FUJI_RPC,
    prove: input.prove ?? "development-equality",
    spend_prove: "KEYS_MISSING",
    production_ceremony_approved: false,
    applicationId: input.applicationId ?? LIVE_APP_ID,
    poolVersion: input.poolVersion ?? LIVE_POOL_VERSION,
    addresses,
    transactions: input.transactions ?? {},
  };
  const overlayPath = input.overlayPath ?? LIVE_OVERLAY_PATH;
  writeFileSync(overlayPath, `${JSON.stringify(overlay, null, 2)}\n`);
  assertCommittedProvenanceUntouched();
  return overlay;
}

function parseDotEnv(text) {
  const env = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) {
      continue;
    }
    const index = line.indexOf("=");
    if (index <= 0) {
      continue;
    }
    const key = line.slice(0, index).trim();
    let value = line.slice(index + 1).trim();
    if (
      (value.startsWith("\"") && value.endsWith("\"")) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    env[key] = value;
  }
  return env;
}

export function loadDotEnvFiles(paths) {
  const merged = {};
  for (const path of paths) {
    if (!existsSync(path)) {
      continue;
    }
    Object.assign(merged, parseDotEnv(readFileSync(path, "utf8")));
  }
  return merged;
}

export function loadPrivateKey() {
  const files = loadDotEnvFiles([
    join(HAZE_ROOT, "..", ".env"),
    join(HAZE_ROOT, ".env"),
  ]);
  const raw = process.env.PRIVATE_KEY || files.PRIVATE_KEY;
  if (typeof raw !== "string" || raw.replace(/^0x/i, "").length !== 64) {
    throw Object.assign(new Error("PRIVATE_KEY is missing or not 32 bytes"), {
      code: "PRIVATE_KEY_MISSING",
    });
  }
  return raw.startsWith("0x") ? raw : `0x${raw}`;
}

function redact(text, secret) {
  const raw = secret.replace(/^0x/i, "");
  return text.replace(new RegExp(`0x?${raw}`, "gi"), "[redacted]");
}

function runForge(args, env) {
  const result = spawnSync("forge", args, {
    cwd: join(HAZE_ROOT, "contracts"),
    encoding: "utf8",
    env: { ...process.env, ...env, FOUNDRY_DISABLE_NIGHTLY_WARNING: "1" },
  });
  const secret = env.PRIVATE_KEY ?? "";
  const stdout = redact(result.stdout ?? "", secret);
  const stderr = redact(result.stderr ?? "", secret);
  if (result.status !== 0) {
    throw new Error(`forge failed (${result.status}): ${stderr || stdout}`);
  }
  return { stdout, stderr };
}

function parseLoggedAddresses(stdout) {
  const addresses = {};
  const names = [...new Set([...CREATE_ORDER, ...PAIRING_CREATE_ORDER, ...POSEIDON_CREATE_ORDER, "HazePool", "deployer"])];
  for (const name of names) {
    const match = stdout.match(new RegExp(`${name}\\s+(0x[a-fA-F0-9]{40})`));
    if (match) {
      addresses[name] = match[1];
    }
  }
  return addresses;
}

export function simulateLiveFujiDeploy() {
  const privateKey = loadPrivateKey();
  const { stdout } = runForge(
    [
      "script",
      "script/DeployFujiLive.s.sol:DeployFujiLive",
      "--rpc-url",
      FUJI_RPC,
      "--tc",
      "DeployFujiLive",
    ],
    { PRIVATE_KEY: privateKey },
  );
  return { stdout, addresses: parseLoggedAddresses(stdout) };
}

export function broadcastLiveFujiDeploy() {
  const privateKey = loadPrivateKey();
  const { stdout } = runForge(
    [
      "script",
      "script/DeployFujiLive.s.sol:DeployFujiLive",
      "--rpc-url",
      FUJI_RPC,
      "--broadcast",
      "--slow",
    ],
    { PRIVATE_KEY: privateKey },
  );
  const addresses = parseLoggedAddresses(stdout);
  const overlay = writeLiveOverlay({
    addresses: {
      HazeAccess: addresses.HazeAccess,
      ApplicationRegistry: addresses.ApplicationRegistry,
      PolicyRegistry: addresses.PolicyRegistry,
      VersionRegistry: addresses.VersionRegistry,
      HazeSpendVerifier: addresses.HazeSpendVerifier,
      HazePool: addresses.HazePool,
      SwapAndShieldRouter: addresses.SwapAndShieldRouter,
      EmergencyExit: addresses.EmergencyExit,
    },
    transactions: { deployLog: "forge-broadcast" },
  });
  return { overlay, addresses, stdout };
}

export function broadcastLiveFujiPairingDeploy() {
  refuseProductionOrProvenanceFlips({});
  assertCommittedProvenanceUntouched();
  const privateKey = loadPrivateKey();
  const { stdout } = runForge(
    [
      "script",
      "script/DeployFujiPairingLive.s.sol:DeployFujiPairingLive",
      "--rpc-url",
      FUJI_RPC,
      "--broadcast",
      "--slow",
    ],
    { PRIVATE_KEY: privateKey },
  );
  const addresses = parseLoggedAddresses(stdout);
  const previous = existsSync(LIVE_OVERLAY_PATH) ? JSON.parse(readFileSync(LIVE_OVERLAY_PATH, "utf8")) : {};
  const overlay = writeLiveOverlay({
    prove: "operator-owned-groth16",
    addresses: {
      HazeAccess: addresses.HazeAccess,
      ApplicationRegistry: addresses.ApplicationRegistry,
      PolicyRegistry: addresses.PolicyRegistry,
      VersionRegistry: addresses.VersionRegistry,
      DevelopmentEqualityVerifier: addresses.DevelopmentEqualityVerifier,
      Groth16Verifier: addresses.Groth16Verifier,
      HazeOperatorGroth16Adapter: addresses.HazeOperatorGroth16Adapter,
      HazeSpendVerifierPairing: addresses.HazeSpendVerifierPairing,
      HazeSpendVerifier: addresses.HazeSpendVerifierPairing,
      HazePool: addresses.HazePool,
      SwapAndShieldRouter: addresses.SwapAndShieldRouter,
      EmergencyExit: addresses.EmergencyExit,
    },
    transactions: {
      deployLog: "forge-broadcast-pairing",
      previous: previous.addresses ?? {},
      previousTransactions: previous.transactions ?? {},
    },
  });
  return { overlay, addresses, stdout };
}

export function broadcastLiveFujiPoseidonDeploy() {
  refuseProductionOrProvenanceFlips({});
  assertCommittedProvenanceUntouched();
  const privateKey = loadPrivateKey();
  const { stdout } = runForge(
    [
      "script",
      "script/DeployFujiPoseidonLive.s.sol:DeployFujiPoseidonLive",
      "--rpc-url",
      FUJI_RPC,
      "--broadcast",
      "--slow",
    ],
    { PRIVATE_KEY: privateKey },
  );
  const addresses = parseLoggedAddresses(stdout);
  const previous = existsSync(LIVE_OVERLAY_PATH) ? JSON.parse(readFileSync(LIVE_OVERLAY_PATH, "utf8")) : {};
  const overlay = writeLiveOverlay({
    prove: "operator-owned-groth16",
    noteTree: "poseidon2",
    membershipRoot: LIVE_POSEIDON_MEMBERSHIP_ROOT,
    hazeBlocklistRoot: LIVE_POSEIDON_BLOCKLIST_ROOT,
    addresses: {
      HazeAccess: addresses.HazeAccess,
      ApplicationRegistry: addresses.ApplicationRegistry,
      PolicyRegistry: addresses.PolicyRegistry,
      VersionRegistry: addresses.VersionRegistry,
      DevelopmentEqualityVerifier: addresses.DevelopmentEqualityVerifier,
      Groth16Verifier: addresses.Groth16Verifier,
      HazeOperatorGroth16Adapter: addresses.HazeOperatorGroth16Adapter,
      HazeSpendVerifierPairing: addresses.HazeSpendVerifierPairing,
      HazeSpendVerifier: addresses.HazeSpendVerifierPairing,
      HazePoolPoseidon: addresses.HazePoolPoseidon ?? addresses.HazePool,
      HazePool: addresses.HazePool ?? addresses.HazePoolPoseidon,
      SwapAndShieldRouter: addresses.SwapAndShieldRouter,
      EmergencyExit: addresses.EmergencyExit,
    },
    transactions: {
      deployLog: "forge-broadcast-poseidon",
      previous: previous.addresses ?? {},
      previousTransactions: previous.transactions ?? {},
    },
  });
  overlay.noteTree = "poseidon2";
  overlay.membershipRoot = LIVE_POSEIDON_MEMBERSHIP_ROOT;
  overlay.hazeBlocklistRoot = LIVE_POSEIDON_BLOCKLIST_ROOT;
  writeFileSync(LIVE_OVERLAY_PATH, `${JSON.stringify(overlay, null, 2)}\n`);
  assertCommittedProvenanceUntouched();
  return { overlay, addresses, stdout };
}

export function activateLiveFuji() {
  const privateKey = loadPrivateKey();
  const overlay = JSON.parse(readFileSync(LIVE_OVERLAY_PATH, "utf8"));
  const { stdout } = runForge(
    ["script", "script/ActivateFujiLive.s.sol:ActivateFujiLive", "--rpc-url", FUJI_RPC, "--broadcast", "--slow"],
    {
      PRIVATE_KEY: privateKey,
      HAZE_APPLICATION_REGISTRY: overlay.addresses.ApplicationRegistry,
      HAZE_POLICY_REGISTRY: overlay.addresses.PolicyRegistry,
    },
  );
  return { stdout };
}

export function parseBroadcastDeposit(broadcast) {
  const txs = Array.isArray(broadcast?.transactions) ? broadcast.transactions : [];
  const approve = txs.find((tx) => tx.function === "approve(address,uint256)");
  const deposit = txs.find((tx) => typeof tx.function === "string" && tx.function.startsWith("deposit("));
  return {
    approveTx: approve?.hash ?? "",
    depositTx: deposit?.hash ?? "",
  };
}

function readLatestDepositBroadcast() {
  const path = join(
    HAZE_ROOT,
    "contracts/broadcast/DepositFujiLive.s.sol/43113/run-latest.json",
  );
  if (!existsSync(path)) {
    return { approveTx: "", depositTx: "" };
  }
  return parseBroadcastDeposit(JSON.parse(readFileSync(path, "utf8")));
}

export function broadcastLiveFujiDeposit(input = {}) {
  refuseProductionOrProvenanceFlips(input);
  assertCommittedProvenanceUntouched();
  const privateKey = loadPrivateKey();
  const overlay = JSON.parse(readFileSync(LIVE_OVERLAY_PATH, "utf8"));
  const pool = overlay.addresses.HazePool;
  const amount = input.amount ?? LIVE_DEPOSIT_AMOUNT;
  const { stdout } = runForge(
    ["script", "script/DepositFujiLive.s.sol:DepositFujiLive", "--rpc-url", FUJI_RPC, "--broadcast", "--slow"],
    {
      PRIVATE_KEY: privateKey,
      HAZE_POOL: pool,
      HAZE_DEPOSIT_AMOUNT: String(amount),
    },
  );
  const parsed = readLatestDepositBroadcast();
  const recorded = recordLiveDeposit({
    overlayPath: LIVE_OVERLAY_PATH,
    depositTx: parsed.depositTx,
    approveTx: parsed.approveTx,
    amount,
  });
  return { stdout, ...parsed, overlay: recorded };
}

function main(argv) {
  const command = argv[0] ?? "plan";
  if (command === "plan") {
    const plan = planLiveFujiDeploy({
      deployer: process.env.HAZE_DEPLOYER,
      nonce: process.env.HAZE_NONCE ? Number(process.env.HAZE_NONCE) : 0,
    });
    process.stdout.write(`${JSON.stringify(plan, null, 2)}\n`);
    return;
  }
  if (command === "simulate") {
    const result = simulateLiveFujiDeploy();
    process.stdout.write(`${JSON.stringify(result.addresses, null, 2)}\n`);
    return;
  }
  if (command === "broadcast") {
    const result = broadcastLiveFujiDeploy();
    process.stdout.write(`${JSON.stringify(result.addresses, null, 2)}\n`);
    return;
  }
  if (command === "plan-pairing") {
    const plan = planLiveFujiPairingDeploy({
      deployer: process.env.HAZE_DEPLOYER,
      nonce: process.env.HAZE_NONCE ? Number(process.env.HAZE_NONCE) : 0,
    });
    process.stdout.write(`${JSON.stringify(plan, null, 2)}\n`);
    return;
  }
  if (command === "broadcast-pairing") {
    const result = broadcastLiveFujiPairingDeploy();
    process.stdout.write(`${JSON.stringify(result.addresses, null, 2)}\n`);
    return;
  }
  if (command === "plan-poseidon") {
    const plan = planLiveFujiPoseidonDeploy({
      deployer: process.env.HAZE_DEPLOYER,
      nonce: process.env.HAZE_NONCE ? Number(process.env.HAZE_NONCE) : 0,
    });
    process.stdout.write(`${JSON.stringify(plan, null, 2)}\n`);
    return;
  }
  if (command === "broadcast-poseidon") {
    const result = broadcastLiveFujiPoseidonDeploy();
    process.stdout.write(`${JSON.stringify(result.addresses, null, 2)}\n`);
    return;
  }
  if (command === "activate") {
    activateLiveFuji();
    process.stdout.write("activated\n");
    return;
  }
  if (command === "deposit-plan") {
    const overlay = existsSync(LIVE_OVERLAY_PATH) ? loadJson(LIVE_OVERLAY_PATH) : {};
    const plan = planLiveFujiDeposit({
      pool: process.env.HAZE_POOL ?? overlay.addresses?.HazePool,
      amount: process.env.HAZE_DEPOSIT_AMOUNT
        ? Number(process.env.HAZE_DEPOSIT_AMOUNT)
        : LIVE_DEPOSIT_AMOUNT,
    });
    process.stdout.write(`${JSON.stringify(plan, null, 2)}\n`);
    return;
  }
  if (command === "deposit") {
    const result = broadcastLiveFujiDeposit({
      amount: process.env.HAZE_DEPOSIT_AMOUNT
        ? Number(process.env.HAZE_DEPOSIT_AMOUNT)
        : LIVE_DEPOSIT_AMOUNT,
    });
    process.stdout.write(`${JSON.stringify({ depositTx: result.depositTx }, null, 2)}\n`);
    return;
  }
  throw new Error(`unknown fuji-live-deploy command: ${command}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2));
}
