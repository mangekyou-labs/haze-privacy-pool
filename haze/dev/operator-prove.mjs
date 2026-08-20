#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createProverSession, encodeOperatorGroth16Proof } from "../sdk/typescript/src/prover.ts";
import {
  FUJI_RPC,
  LIVE_OVERLAY_PATH,
  loadPrivateKey,
} from "./fuji-live-deploy.mjs";
import { PINNED_SPEND } from "./ceremony/production.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const SPEND_ARTIFACT_HASH =
  "0xac2082ecb2129c571d2ddeb170f261a0da074491773102fa4f1544e97eb19281";
export const DEFAULT_ZKEY = join(HAZE_ROOT, "dev/artifacts/ceremony-private/haze-spend-final.zkey");
export const DEFAULT_WASM = join(HAZE_ROOT, "circuits/build/spend/spend_js/spend.wasm");
export const DEFAULT_FIXTURE = join(HAZE_ROOT, "circuits/vectors/v1/haze-spend-v1.json");
export const DEFAULT_OUTPUT = join(
  HAZE_ROOT,
  "dev/artifacts/ceremony-private/operator-prove-deposit.json",
);

function coded(code, message) {
  return Object.assign(new Error(message), { code });
}

export function planOperatorProve(input = {}) {
  if (input.inventProductionKeys === true || input.spendProve === "production") {
    throw coded("KEYS_MISSING", "production Groth16 keys remain KEYS_MISSING");
  }
  if (input.productionCeremonyApproved === true) {
    throw coded("KEYS_MISSING", "one-laptop prove is not production_ceremony.approved");
  }
  const circuitId = input.circuitId ?? "haze-spend-v1";
  if (circuitId !== "haze-spend-v1") {
    throw coded("ARTIFACT_INVALID", "operator prove is pinned to haze-spend-v1");
  }
  return {
    circuitId,
    caseName: input.caseName ?? "deposit",
    nConstraints: PINNED_SPEND.n_constraints,
    zkeyPath: input.zkeyPath ?? DEFAULT_ZKEY,
    wasmPath: input.wasmPath ?? DEFAULT_WASM,
    fixturePath: input.fixturePath ?? DEFAULT_FIXTURE,
    outputPath: input.outputPath ?? DEFAULT_OUTPUT,
    spendProve: "KEYS_MISSING",
    prove: "operator-owned-groth16",
    productionCeremonyApproved: false,
    notForProduction: true,
    productionCall: true,
    artifactHash: SPEND_ARTIFACT_HASH,
  };
}

export function loadSpendCase(plan) {
  const fixture = JSON.parse(readFileSync(plan.fixturePath, "utf8"));
  const found = fixture.cases.find((entry) => entry.name === plan.caseName);
  if (!found?.circom) {
    throw coded("WITNESS_INVALID", `missing spend case ${plan.caseName}`);
  }
  return found.circom;
}

export async function runOperatorProve(input = {}) {
  const plan = planOperatorProve(input);
  if (!existsSync(plan.zkeyPath)) {
    throw coded("KEYS_MISSING", "operator zkey is missing");
  }
  if (!existsSync(plan.wasmPath)) {
    throw coded("WITNESS_INVALID", "spend wasm is missing");
  }
  const circom = input.circom ?? loadSpendCase(plan);
  const session = createProverSession();
  const proved = await session.proveSpend({
    ...circom,
    zkeyPath: plan.zkeyPath,
    wasmPath: plan.wasmPath,
    circuit_id: plan.circuitId,
  });
  const proofBytes = encodeOperatorGroth16Proof(proved);
  const artifact = {
    not_for_production: true,
    production_ceremony_approved: false,
    spend_prove: "KEYS_MISSING",
    prove: "operator-owned-groth16",
    circuit_id: plan.circuitId,
    caseName: plan.caseName,
    n_constraints: plan.nConstraints,
    artifactHash: plan.artifactHash,
    publicSignals: proved.publicSignals,
    proof: proved.proof,
    proofBytes,
    profile: proved.profile,
  };
  writeFileSync(plan.outputPath, `${JSON.stringify(artifact, null, 2)}\n`);
  return { plan, artifact };
}

export function callLivePairingVerify(input = {}) {
  const overlay = JSON.parse(readFileSync(input.overlayPath ?? LIVE_OVERLAY_PATH, "utf8"));
  const artifact = JSON.parse(readFileSync(input.artifactPath ?? DEFAULT_OUTPUT, "utf8"));
  const pairing = overlay.addresses?.HazeSpendVerifierPairing;
  if (!pairing) {
    throw coded("ENCODING_INVALID", "live sidecar is missing HazeSpendVerifierPairing");
  }
  if (artifact.proofBytes?.length !== 2 + 256 * 2) {
    throw coded("ENCODING_INVALID", "operator proof must be 256 bytes");
  }
  const signals = (artifact.publicSignals ?? []).map((value) => BigInt(value).toString());
  if (signals.length !== 29) {
    throw coded("WITNESS_INVALID", "operator proof must expose 29 public signals");
  }
  const production = input.production !== false;
  const result = spawnSync(
    "cast",
    [
      "call",
      pairing,
      "verify(uint256[29],bytes,bytes32,bool)(bool)",
      `[${signals.join(",")}]`,
      artifact.proofBytes,
      artifact.artifactHash,
      production ? "true" : "false",
      "--rpc-url",
      overlay.live_rpc ?? FUJI_RPC,
    ],
    { encoding: "utf8" },
  );
  if (result.status !== 0) {
    throw coded("PROOF_INVALID", result.stderr || result.stdout || "cast call failed");
  }
  const verified = result.stdout.trim().toLowerCase() === "true";
  return {
    pairing,
    production,
    verified,
    stdout: result.stdout.trim(),
    spendProve: "KEYS_MISSING",
    productionCeremonyApproved: false,
  };
}

export function broadcastLivePairingVerify(input = {}) {
  const overlay = JSON.parse(readFileSync(input.overlayPath ?? LIVE_OVERLAY_PATH, "utf8"));
  const artifactPath = input.artifactPath ?? DEFAULT_OUTPUT;
  const pairing = overlay.addresses?.HazeSpendVerifierPairing;
  const privateKey = loadPrivateKey();
  const result = spawnSync(
    "forge",
    [
      "script",
      "script/VerifyFujiPairingLive.s.sol:VerifyFujiPairingLive",
      "--rpc-url",
      overlay.live_rpc ?? FUJI_RPC,
      "--broadcast",
      "--slow",
    ],
    {
      encoding: "utf8",
      cwd: join(HAZE_ROOT, "contracts"),
      env: {
        ...process.env,
        PRIVATE_KEY: privateKey,
        HAZE_PAIRING: pairing,
        HAZE_OPERATOR_PROVE_JSON: artifactPath,
      },
    },
  );
  if (result.status !== 0) {
    throw coded("PROOF_INVALID", result.stderr || result.stdout || "forge pairing verify failed");
  }
  const match = result.stdout.match(/HazeOperatorPairingReceipt\s+(0x[0-9a-fA-F]{40})/);
  return {
    pairing,
    receipt: match?.[1] ?? null,
    stdout: result.stdout,
    spendProve: "KEYS_MISSING",
    productionCeremonyApproved: false,
  };
}

export function recordOperatorProve(input) {
  const overlayPath = input.overlayPath ?? LIVE_OVERLAY_PATH;
  const overlay = JSON.parse(readFileSync(overlayPath, "utf8"));
  overlay.prove = "operator-owned-groth16";
  overlay.spend_prove = "KEYS_MISSING";
  overlay.production_ceremony_approved = false;
  overlay.not_for_production = true;
  overlay.transactions = {
    ...(overlay.transactions ?? {}),
    operatorProve: input.operatorProve,
    pairingEthCall: input.pairingEthCall,
    pairingReceipt: input.pairingReceipt,
  };
  writeFileSync(overlayPath, `${JSON.stringify(overlay, null, 2)}\n`);
  return overlay;
}

async function main() {
  const command = process.argv[2] ?? "plan";
  if (command === "plan") {
    process.stdout.write(`${JSON.stringify(planOperatorProve(), null, 2)}\n`);
    return;
  }
  if (command === "prove") {
    const { plan, artifact } = await runOperatorProve();
    process.stdout.write(
      `${JSON.stringify(
        {
          outputPath: plan.outputPath,
          proofBytes: artifact.proofBytes.length,
          publicSignals: artifact.publicSignals.length,
          spend_prove: artifact.spend_prove,
          production_ceremony_approved: artifact.production_ceremony_approved,
        },
        null,
        2,
      )}\n`,
    );
    return;
  }
  if (command === "verify") {
    const call = callLivePairingVerify();
    process.stdout.write(`${JSON.stringify(call, null, 2)}\n`);
    if (!call.verified) {
      process.exitCode = 1;
    }
    return;
  }
  if (command === "broadcast") {
    const broadcast = broadcastLivePairingVerify();
    process.stdout.write(
      `${JSON.stringify(
        {
          pairing: broadcast.pairing,
          receipt: broadcast.receipt,
          spend_prove: broadcast.spendProve,
          production_ceremony_approved: broadcast.productionCeremonyApproved,
        },
        null,
        2,
      )}\n`,
    );
    return;
  }
  throw new Error(`unknown operator-prove command ${command}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
