import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { createProverSession, encodeOperatorGroth16Proof } from "../sdk/typescript/src/prover.ts";
import { planOperatorProve } from "../dev/operator-prove.mjs";
import { activationBlocked } from "../dev/ceremony/lib.mjs";
import {
  assertCommittedFujiUnchanged,
  assertSpendCircuitPin,
  productionActivationAllowed,
} from "../dev/ceremony/production.mjs";
import { ptauSpec, requiredPtauPower } from "../dev/ceremony/ptau.mjs";
import {
  planPhase2,
  redactEntropy,
  refuseRehearsalAsSpendZkey,
} from "../dev/ceremony/phase2.mjs";
import { publicTranscript } from "../dev/ceremony/export.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ARTIFACTS = join(HAZE_ROOT, "dev/artifacts");
const SOURCE_EXTENSIONS = new Set([".mjs", ".js", ".ts", ".tsx", ".sol", ".rs", ".md"]);

function collectFiles(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    if (entry.name === "node_modules" || entry.name === "out" || entry.name === "cache") {
      return [];
    }
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      return collectFiles(path);
    }
    return SOURCE_EXTENSIONS.has(extname(entry.name)) ? [path] : [];
  });
}

test("production ceremony driver files exist", () => {
  const missing = [
    "dev/ceremony/ptau.mjs",
    "dev/ceremony/phase2.mjs",
    "dev/ceremony/export.mjs",
    "dev/ceremony/production.mjs",
    "contracts/src/HazeSpendVerifierPairing.sol",
    "contracts/src/HazeGroth16Verifier.sol",
    "docs/ai/design/2026-08-18-haze-production-ceremony-design.md",
  ]
    .map((path) => (path.startsWith("docs/") ? join(HAZE_ROOT, "../", path) : join(HAZE_ROOT, path)))
    .filter((path) => !existsSync(path));
  assert.deepEqual(missing, []);
});

test("refuses equality-circuit rehearsal transcript as a spend zkey", () => {
  const rehearsal = JSON.parse(readFileSync(join(ARTIFACTS, "rehearsal-ceremony.json"), "utf8"));
  assert.equal(rehearsal.circuit_id, "haze-development-equality-v1");
  assert.throws(() => refuseRehearsalAsSpendZkey(rehearsal), { code: "VERSION_UNSUPPORTED" });
  assert.throws(
    () => refuseRehearsalAsSpendZkey({ circuit_id: "haze-spend-v1", r1cs: "development_equality.r1cs" }),
    { code: "VERSION_UNSUPPORTED" },
  );
  assert.doesNotThrow(() =>
    refuseRehearsalAsSpendZkey({
      circuit_id: "haze-spend-v1",
      r1cs: "spend.r1cs",
      n_constraints: 588459,
    }),
  );
});

test("pins Circom 2.2.3, 588459 constraints, and committed spend hashes", () => {
  const manifest = JSON.parse(readFileSync(join(ARTIFACTS, "circuit-build-manifest.json"), "utf8"));
  const pin = assertSpendCircuitPin(manifest);
  assert.equal(pin.circuit_id, "haze-spend-v1");
  assert.equal(pin.circom_version, "2.2.3");
  assert.equal(pin.n_constraints, 588459);
  assert.equal(pin.source_hash, "0xddab1e2d4aca797058f3e3aca49c99a1bd5a396f3c3bf8dd1bc3c47a8e1fd9b1");
  assert.equal(pin.r1cs_hash, "0x98cc762ccc18a9a3b0aba3b6be3dba217c928629cf8f330a09779ffa5e23f02d");
  assert.equal(pin.fixture_hash, "0x7b55ab0190cbe83541e9763c1bf314776cf378af3b3018a060c836c53c7979df");
  assert.equal(pin.build_hash, "0x533f1d9d172c8395b4849bd7b90901b5314b7fc4735b878385e22b5a19d3cd41");
  assert.throws(
    () => assertSpendCircuitPin({ ...manifest, n_constraints: 37616, circuit_id: "policy_tx_2_2_AB" }),
    { code: "VERSION_UNSUPPORTED" },
  );
});

test("required ptau power is 20 for the spend circuit", () => {
  const spec = ptauSpec();
  assert.equal(spec.power, 20);
  assert.equal(spec.file, "powersOfTau28_hez_final_20.ptau");
  assert.match(spec.url, /powersOfTau28_hez_final_20\.ptau/);
  assert.equal(spec.source, "hermez");
  assert.equal(spec.sha256, "159d3f938d941e06767d99f30b9fe59a245400a4aae138cf8e411732d7a2f6cd");
  assert.equal(requiredPtauPower(588459), 20);
  assert.ok(2 ** spec.power > 588459);
  assert.throws(() => requiredPtauPower(1 << 20), { code: "VERSION_UNSUPPORTED" });
});

test("phase2 plan is groth16 setup, two contributions, beacon, verify, export", () => {
  const plan = planPhase2({
    r1cs: join(HAZE_ROOT, "circuits/build/spend/spend.r1cs"),
    ptau: "powersOfTau28_hez_final_20.ptau",
    workDir: join(HAZE_ROOT, "dev/artifacts/ceremony-private"),
    contributors: ["operator-1", "operator-2"],
  });
  const flat = plan.commands.map((command) => command.join(" ")).join("\n");
  assert.match(flat, /snarkjs groth16 setup/);
  assert.match(flat, /snarkjs zkey contribute/);
  assert.match(flat, /snarkjs zkey beacon/);
  assert.match(flat, /snarkjs zkey verify/);
  assert.match(flat, /snarkjs zkey export verificationkey/);
  assert.match(flat, /snarkjs zkey export solidityverifier/);
  assert.ok(plan.commands.filter((command) => command.includes("contribute")).length >= 2);
  assert.match(plan.privateDir, /ceremony-private/);
  assert.equal(plan.not_for_production, true);
});

test("redacts entropy from logs and omits it from the public transcript", () => {
  const redacted = redactEntropy("contribute operator-1 entropy=deadbeefcafebabe extra");
  assert.doesNotMatch(redacted, /deadbeefcafebabe/);
  assert.match(redacted, /\[REDACTED\]/);
  const transcript = publicTranscript({
    circuit_id: "haze-spend-v1",
    contributions: [
      { contributor: "operator-1", zkey_hash: "0xaaa", entropy: "0x1111" },
      { contributor: "operator-2", zkey_hash: "0xbbb", entropy_commitment: "0x2222" },
    ],
  });
  assert.equal(transcript.circuit_id, "haze-spend-v1");
  assert.equal(transcript.contributions[0].contributor, "operator-1");
  assert.equal(transcript.contributions[0].zkey_hash, "0xaaa");
  assert.equal(transcript.contributions[0].entropy, undefined);
  assert.equal(transcript.contributions[1].entropy_commitment, undefined);
  const serialized = JSON.stringify(transcript);
  assert.doesNotMatch(serialized, /0x1111|0x2222|entropy/);
});

test("spend_prove stays KEYS_MISSING until attestation and SC-09 production_ceremony", () => {
  const provenance = JSON.parse(readFileSync(join(ARTIFACTS, "provenance.json"), "utf8"));
  assert.equal(activationBlocked(provenance), true);
  assert.equal(provenance.sc09.production_ceremony.approved, false);
  assert.equal(provenance.sc09.fuji_pilot.approved, false);
  assert.equal(provenance.sc09.independent_audit.approved, false);
  assert.equal(provenance.sc09.incident_review.approved, false);
  assert.equal(productionActivationAllowed({ attestation: true, provenance }), false);
  assert.equal(provenance.spend_prove, "KEYS_MISSING");
});

test("committed fuji-v1 stays broadcast false and KEYS_MISSING", () => {
  const fuji = JSON.parse(readFileSync(join(HAZE_ROOT, "deployments/fuji-v1.json"), "utf8"));
  assertCommittedFujiUnchanged(fuji);
  assert.equal(fuji.broadcast, false);
  assert.equal(fuji.spend_prove, "KEYS_MISSING");
  assert.equal(fuji.immutable, true);
  assert.throws(() => assertCommittedFujiUnchanged({ ...fuji, broadcast: true }), {
    code: "VERSION_UNSUPPORTED",
  });
});

test("haze sources do not import parent tools/ceremony-cli", () => {
  const hits = collectFiles(HAZE_ROOT).flatMap((path) => {
    const text = readFileSync(path, "utf8");
    if (!/tools\/ceremony-cli|from ["'].*ceremony-cli/.test(text)) {
      return [];
    }
    if (path.endsWith("production-ceremony.test.mjs") || path.endsWith("production-ceremony.md")) {
      return [];
    }
    return [path];
  });
  assert.deepEqual(hits, []);
});

test("proveSpend without operator zkey stays KEYS_MISSING and refuses rehearsal path", async () => {
  const session = createProverSession();
  await assert.rejects(() => session.proveSpend({}), { code: "KEYS_MISSING" });
  await assert.rejects(
    () =>
      session.proveSpend({
        zkeyPath: join(ARTIFACTS, "rehearsal-ceremony.json"),
        circuit_id: "haze-development-equality-v1",
      }),
    { code: "ARTIFACT_INVALID" },
  );
});

test("operator prove plan uses the deposit fixture and refuses a production flip", () => {
  const plan = planOperatorProve();
  assert.equal(plan.circuitId, "haze-spend-v1");
  assert.equal(plan.caseName, "deposit");
  assert.equal(plan.nConstraints, 588459);
  assert.equal(plan.spendProve, "KEYS_MISSING");
  assert.equal(plan.prove, "operator-owned-groth16");
  assert.equal(plan.productionCeremonyApproved, false);
  assert.equal(plan.notForProduction, true);
  assert.equal(plan.productionCall, true);
  assert.equal(plan.artifactHash, "0xac2082ecb2129c571d2ddeb170f261a0da074491773102fa4f1544e97eb19281");
  assert.match(plan.zkeyPath, /haze-spend-final\.zkey$/);
  assert.match(plan.wasmPath, /spend\.wasm$/);
  assert.throws(() => planOperatorProve({ spendProve: "production" }), (error) => {
    assert.equal(error.code, "KEYS_MISSING");
    return true;
  });
  assert.throws(() => planOperatorProve({ productionCeremonyApproved: true }), (error) => {
    assert.equal(error.code, "KEYS_MISSING");
    return true;
  });
  const fuji = JSON.parse(readFileSync(join(HAZE_ROOT, "deployments/fuji-v1.json"), "utf8"));
  assert.equal(fuji.broadcast, false);
  assert.equal(fuji.spend_prove, "KEYS_MISSING");
});

test("operator Groth16 proof encodes to a 256-byte pairing wrap with G2 limbs swapped", () => {
  const encoded = encodeOperatorGroth16Proof({
    profile: "operator-owned",
    notForProduction: true,
    protocol: "groth16",
    proof: {
      pi_a: ["1", "2", "1"],
      pi_b: [
        ["3", "4"],
        ["5", "6"],
        ["1", "0"],
      ],
      pi_c: ["7", "8", "1"],
      protocol: "groth16",
      curve: "bn128",
    },
    publicSignals: ["9"],
  });
  assert.equal(encoded.length, 2 + 256 * 2);
  assert.equal(
    encoded,
    `0x${["1", "2", "4", "3", "6", "5", "7", "8"].map((word) => BigInt(word).toString(16).padStart(64, "0")).join("")}`,
  );
  assert.throws(
    () =>
      encodeOperatorGroth16Proof({
        profile: "operator-owned",
        notForProduction: true,
        protocol: "groth16",
        proof: {
          pi_a: ["1"],
          pi_b: [["3", "4"]],
          pi_c: ["7", "8"],
          protocol: "groth16",
          curve: "bn128",
        },
        publicSignals: [],
      }),
    { code: "PROOF_INVALID" },
  );
});

test("proveSpend with a spend zkey path and missing wasm is WITNESS_INVALID", async () => {
  const session = createProverSession();
  await assert.rejects(
    () =>
      session.proveSpend({
        zkeyPath: join(ARTIFACTS, "operator-owned-ceremony-transcript.json"),
        circuit_id: "haze-spend-v1",
        wasmPath: join(ARTIFACTS, "missing-spend.wasm"),
      }),
    { code: "WITNESS_INVALID" },
  );
});

test("committed spend verifier stays KEYS_MISSING; pairing sibling forwards operator proofs", () => {
  const committed = readFileSync(join(HAZE_ROOT, "contracts/src/HazeSpendVerifier.sol"), "utf8");
  const pairing = readFileSync(join(HAZE_ROOT, "contracts/src/HazeSpendVerifierPairing.sol"), "utf8");
  const groth = readFileSync(join(HAZE_ROOT, "contracts/src/HazeGroth16Verifier.sol"), "utf8");
  assert.match(committed, /if \(production\) \{\s*revert\("KEYS_MISSING"\);/s);
  assert.match(pairing, /verifyProof/);
  assert.match(pairing, /pairing/i);
  assert.match(groth, /KEYS_MISSING/);
  assert.doesNotMatch(groth, /0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001.{0,40}vk/i);
});

test("operator-owned transcript is public hashes and is not a production approval", () => {
  const transcript = JSON.parse(
    readFileSync(join(ARTIFACTS, "operator-owned-ceremony-transcript.json"), "utf8"),
  );
  assert.equal(transcript.circuit_id, "haze-spend-v1");
  assert.equal(transcript.not_for_production, true);
  assert.equal(transcript.production_ceremony_approved, false);
  assert.equal(transcript.zkey_verify, "ZKey Ok");
  assert.doesNotMatch(JSON.stringify(transcript), /entropy/);
  assert.ok(transcript.contributions.length >= 2);
});

test("design spec records Builder Hub is not a Haze ceremony service", () => {
  const spec = readFileSync(
    join(HAZE_ROOT, "../docs/ai/design/2026-08-18-haze-production-ceremony-design.md"),
    "utf8",
  );
  assert.match(spec, /build\.avax\.network\/llms\.txt/);
  assert.match(spec, /not a Powers-of-Tau/);
  assert.match(spec, /Encrypted ERC/);
  assert.match(spec, /production_ceremony\.approved/);
  assert.match(spec, /588459/);
});
