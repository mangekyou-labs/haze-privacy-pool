import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak256 as keccakBuffer } from "./keccak256.mjs";
import { resolveCircom, r1csConstraintCount } from "../circuits/witness.mjs";
import {
  activationBlocked,
  computeBuildHash,
  fileKeccak,
  verifyTranscript,
} from "../dev/ceremony/lib.mjs";
import { createProverSession } from "../sdk/typescript/src/prover.ts";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ARTIFACTS = join(HAZE_ROOT, "dev/artifacts");
const EQUALITY = join(HAZE_ROOT, "circuits/test/development_equality.circom");
const FIXTURE_WALLET = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf";

function hex(bytes) {
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

test("ceremony tooling files and runbook exist", () => {
  const missing = [
    "dev/ceremony/setup.mjs",
    "dev/ceremony/rehearse.mjs",
    "dev/ceremony/verify-transcript.mjs",
    "dev/ceremony/sign-manifest.mjs",
    "dev/ceremony/lib.mjs",
    "dev/runbooks/production-ceremony.md",
    "dev/artifacts/circuit-build-manifest.json",
    "dev/artifacts/rehearsal-ceremony.json",
    "dev/artifacts/rehearsal-signed-manifest.json",
    "dev/artifacts/provenance.json",
    "dev/artifacts/DevelopmentEqualityVerifier.sol",
    "circuits/test/development_equality.circom",
  ]
    .filter((path) => !existsSync(join(HAZE_ROOT, path)))
    .map((path) => `missing ${path}`);
  assert.deepEqual(missing, []);
});

test("two clean equality-circuit builds match r1cs hashes", () => {
  const circom = resolveCircom(HAZE_ROOT);
  const hashes = [0, 1].map((index) => {
    const dir = mkdtempSync(join(tmpdir(), `haze-eq-${index}-`));
    try {
      execFileSync(circom, [EQUALITY, "--r1cs", "--O0", "-o", dir], { encoding: "utf8" });
      const r1cs = join(dir, "development_equality.r1cs");
      assert.equal(existsSync(r1cs), true);
      return hex(fileKeccak(r1cs));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
  assert.equal(hashes[0], hashes[1]);
});

test("spend r1cs still pins 588459 constraints and build manifest matches files", () => {
  const r1cs = join(HAZE_ROOT, "circuits/build/spend/spend.r1cs");
  assert.equal(r1csConstraintCount(r1cs), 588459);
  const manifest = JSON.parse(readFileSync(join(ARTIFACTS, "circuit-build-manifest.json"), "utf8"));
  const sourceHash = hex(fileKeccak(join(HAZE_ROOT, "circuits/src/spend.circom")));
  const fixtureHash = hex(fileKeccak(join(HAZE_ROOT, "circuits/vectors/v1/haze-spend-v1.json")));
  assert.equal(manifest.n_constraints, 588459);
  assert.equal(manifest.circom_version, "2.2.3");
  assert.equal(manifest.not_for_production, true);
  assert.equal(manifest.source_hash, sourceHash);
  assert.equal(manifest.fixture_hash, fixtureHash);
  assert.equal(
    manifest.build_hash,
    computeBuildHash(
      manifest.source_hash,
      manifest.r1cs_hash,
      manifest.fixture_hash,
      manifest.n_constraints,
    ),
  );
});

test("rehearsal transcript verifies every contribution", () => {
  const transcript = JSON.parse(readFileSync(join(ARTIFACTS, "rehearsal-ceremony.json"), "utf8"));
  assert.equal(transcript.not_for_production, true);
  assert.ok(transcript.contributions.length >= 2);
  verifyTranscript(transcript);
});

test("generated development verifier is labeled not for production", () => {
  const source = readFileSync(join(ARTIFACTS, "DevelopmentEqualityVerifier.sol"), "utf8");
  assert.match(source, /NOT_FOR_PRODUCTION/);
  assert.match(source, /not.for.production/i);
  assert.doesNotMatch(source, /HazePool/);
  assert.doesNotMatch(source, /pairing/);
});

test("production ceremony runbook forbids T7.4 until audit freeze", () => {
  const runbook = readFileSync(join(HAZE_ROOT, "dev/runbooks/production-ceremony.md"), "utf8");
  assert.match(runbook, /T7\.4/);
  assert.match(runbook, /must not/i);
  assert.match(runbook, /audit/);
  assert.match(runbook, /Do not import or wrap the parent Stellar/);
});

test("provenance display keeps every SC-09 gate closed", () => {
  const provenance = JSON.parse(readFileSync(join(ARTIFACTS, "provenance.json"), "utf8"));
  assert.equal(activationBlocked(provenance), true);
  assert.equal(provenance.sc09.fuji_pilot.approved, false);
  assert.equal(provenance.sc09.independent_audit.approved, false);
  assert.equal(provenance.sc09.production_ceremony.approved, false);
  assert.equal(provenance.sc09.incident_review.approved, false);
  assert.equal(provenance.spend_prove, "KEYS_MISSING");
});

test("signed rehearsal manifest recovers the fixture wallet", () => {
  const signed = JSON.parse(readFileSync(join(ARTIFACTS, "rehearsal-signed-manifest.json"), "utf8"));
  const digest = Buffer.from(signed.digest.slice(2), "hex");
  const signature = signed.signature.slice(2);
  const recovered = secp256k1.Signature.fromCompact(Buffer.from(signature.slice(0, 128), "hex"))
    .addRecoveryBit(Number.parseInt(signature.slice(128, 130), 16))
    .recoverPublicKey(digest)
    .toRawBytes(false);
  const address = hex(keccakBuffer(recovered.subarray(1)).subarray(12));
  assert.equal(address, FIXTURE_WALLET);
  assert.equal(signed.not_for_production, true);
});

test("spend proving still returns KEYS_MISSING", async () => {
  const session = createProverSession();
  await assert.rejects(() => session.proveSpend({}), { code: "KEYS_MISSING" });
});
