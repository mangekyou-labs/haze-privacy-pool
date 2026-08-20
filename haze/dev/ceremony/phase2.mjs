#!/usr/bin/env node
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { HAZE_ROOT, SPEND_CIRCUIT_ID, SPEND_N_CONSTRAINTS } from "./lib.mjs";
import { PTAU_FILE, versionError } from "./ptau.mjs";

export function refuseRehearsalAsSpendZkey(input) {
  const circuitId = input?.circuit_id ?? input?.circuitId ?? "";
  const r1cs = String(input?.r1cs ?? input?.zkeyPath ?? input?.zkey ?? "");
  if (circuitId !== SPEND_CIRCUIT_ID) {
    throw versionError("VERSION_UNSUPPORTED");
  }
  if (/equality|rehearsal/i.test(r1cs)) {
    throw versionError("VERSION_UNSUPPORTED");
  }
  if (input?.n_constraints && input.n_constraints !== SPEND_N_CONSTRAINTS) {
    throw versionError("VERSION_UNSUPPORTED");
  }
  return true;
}

export function redactEntropy(text) {
  return String(text)
    .replace(/(entropy[_=:\s-]+)([0-9a-fA-Fx]+)/g, "$1[REDACTED]")
    .replace(/\b[0-9a-fA-F]{16,}\b/g, "[REDACTED]");
}

export function planPhase2({
  r1cs,
  ptau = PTAU_FILE,
  workDir = join(HAZE_ROOT, "dev/artifacts/ceremony-private"),
  contributors = ["operator-1", "operator-2"],
} = {}) {
  refuseRehearsalAsSpendZkey({
    circuit_id: SPEND_CIRCUIT_ID,
    r1cs,
    n_constraints: SPEND_N_CONSTRAINTS,
  });
  if (!Array.isArray(contributors) || contributors.length < 2) {
    throw versionError("VERSION_UNSUPPORTED");
  }
  const setup = join(workDir, "haze-spend-0000.zkey");
  const afterFirst = join(workDir, "haze-spend-0001.zkey");
  const afterSecond = join(workDir, "haze-spend-0002.zkey");
  const finalZkey = join(workDir, "haze-spend-final.zkey");
  const vk = join(workDir, "haze-spend-verification-key.json");
  const solidity = join(workDir, "HazeGroth16Verifier.generated.sol");
  const commands = [
    ["snarkjs", "groth16", "setup", r1cs, ptau, setup],
    ["snarkjs", "zkey", "contribute", setup, afterFirst, `--name=${contributors[0]}`],
    ["snarkjs", "zkey", "contribute", afterFirst, afterSecond, `--name=${contributors[1]}`],
    ["snarkjs", "zkey", "beacon", afterSecond, finalZkey, "0", "10"],
    ["snarkjs", "zkey", "verify", r1cs, ptau, finalZkey],
    ["snarkjs", "zkey", "export", "verificationkey", finalZkey, vk],
    ["snarkjs", "zkey", "export", "solidityverifier", finalZkey, solidity],
  ];
  return {
    commands,
    privateDir: workDir,
    setup,
    finalZkey,
    vk,
    solidity,
    contributors: contributors.slice(0, 2),
    not_for_production: true,
    production_ceremony_approved: false,
  };
}

function entropyArg() {
  return randomBytes(32).toString("hex");
}

export function runPhase2(options = {}) {
  const plan = planPhase2(options);
  mkdirSync(plan.privateDir, { recursive: true });
  if (!existsSync(options.r1cs)) {
    throw Object.assign(new Error("ARTIFACT_INVALID"), { code: "ARTIFACT_INVALID" });
  }
  if (!existsSync(options.ptau ?? join(plan.privateDir, PTAU_FILE))) {
    throw Object.assign(new Error("ARTIFACT_INVALID"), { code: "ARTIFACT_INVALID" });
  }
  const logs = [];
  for (const command of plan.commands) {
    const extra = command.includes("contribute") ? [entropyArg()] : [];
    const result = spawnSync(command[0], [...command.slice(1), ...extra], {
      encoding: "utf8",
      env: { ...process.env, NODE_OPTIONS: process.env.NODE_OPTIONS ?? "--max-old-space-size=12288" },
    });
    logs.push(redactEntropy(result.stdout ?? ""));
    logs.push(redactEntropy(result.stderr ?? ""));
    if (result.status !== 0) {
      const failure = redactEntropy(result.stderr || result.stdout || "phase2 failed");
      throw new Error(failure);
    }
  }
  writeFileSync(join(plan.privateDir, "phase2.log"), `${logs.join("\n")}\n`);
  return plan;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const plan = planPhase2({
    r1cs: join(HAZE_ROOT, "circuits/build/spend/spend.r1cs"),
    ptau: join(HAZE_ROOT, "dev/artifacts/ceremony-private", PTAU_FILE),
  });
  process.stdout.write(`${JSON.stringify({ ...plan, note: "not_for_production" }, null, 2)}\n`);
}
