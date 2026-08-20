#!/usr/bin/env node
import { createHash } from "node:crypto";
import { createWriteStream, existsSync, mkdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { pipeline } from "node:stream/promises";
import { HAZE_ROOT, SPEND_N_CONSTRAINTS } from "./lib.mjs";

export const PTAU_POWER = 20;
export const PTAU_FILE = "powersOfTau28_hez_final_20.ptau";
export const PTAU_URL =
  "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_20.ptau";
export const PTAU_ALTERNATE_URL =
  "https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_20.ptau";
/** SHA-256 of the Hermez ptau 20 file downloaded from PTAU_URL on 2026-08-18. */
export const PTAU_SHA256 = "159d3f938d941e06767d99f30b9fe59a245400a4aae138cf8e411732d7a2f6cd";

export function versionError(message = "VERSION_UNSUPPORTED") {
  return Object.assign(new Error(message), { code: "VERSION_UNSUPPORTED" });
}

export function requiredPtauPower(nConstraints) {
  if (!Number.isInteger(nConstraints) || nConstraints < 1) {
    throw versionError("VERSION_UNSUPPORTED");
  }
  if (nConstraints >= 2 ** PTAU_POWER) {
    throw versionError("VERSION_UNSUPPORTED");
  }
  let power = 1;
  while (2 ** power <= nConstraints) {
    power += 1;
  }
  if (power > PTAU_POWER) {
    throw versionError("VERSION_UNSUPPORTED");
  }
  return PTAU_POWER;
}

export function ptauSpec() {
  return {
    power: PTAU_POWER,
    file: PTAU_FILE,
    url: PTAU_URL,
    alternateUrl: PTAU_ALTERNATE_URL,
    source: "hermez",
    sha256: PTAU_SHA256,
    minConstraints: SPEND_N_CONSTRAINTS,
    notProductionCeremonyApproval: true,
  };
}

export function ptauPath(workDir = join(HAZE_ROOT, "dev/artifacts/ceremony-private")) {
  return join(workDir, PTAU_FILE);
}

export function assertPtauFileName(file) {
  if (!String(file).endsWith(PTAU_FILE) && !String(file).includes(`final_${PTAU_POWER}.ptau`)) {
    throw versionError("VERSION_UNSUPPORTED");
  }
  return ptauSpec();
}

export function sha256File(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

export function assertPtauChecksum(path) {
  const digest = sha256File(path);
  if (digest !== PTAU_SHA256) {
    throw versionError("VERSION_UNSUPPORTED");
  }
  return digest;
}

export async function downloadPtau({ dest = ptauPath(), fetchImpl = globalThis.fetch } = {}) {
  mkdirSync(dirname(dest), { recursive: true });
  if (existsSync(dest) && statSync(dest).size > 0) {
    return { path: dest, skipped: true, sha256: assertPtauChecksum(dest) };
  }
  const response = await fetchImpl(PTAU_URL);
  if (!response.ok) {
    throw new Error(`ptau download failed: ${response.status}`);
  }
  await pipeline(response.body, createWriteStream(dest));
  return { path: dest, skipped: false, sha256: assertPtauChecksum(dest) };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  requiredPtauPower(SPEND_N_CONSTRAINTS);
  process.stdout.write(`${JSON.stringify(ptauSpec(), null, 2)}\n`);
}
