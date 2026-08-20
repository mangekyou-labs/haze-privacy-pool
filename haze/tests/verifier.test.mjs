import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  SPEND_PUBLIC_CAMEL,
  checkSpendPublicInputs,
  developmentProofDigest,
  spendPublicInputs,
  verifyDevelopmentSpend,
} from "../sdk/typescript/src/prover.ts";
import { keccak256 } from "../sdk/typescript/src/keccak.ts";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SPEND_FIXTURE = join(HAZE_ROOT, "circuits/vectors/v1/haze-spend-v1.json");
const VECTOR = join(HAZE_ROOT, "circuits/vectors/v1/haze-verifier-v1.json");
const WRAPPER = join(HAZE_ROOT, "contracts/src/HazeSpendVerifier.sol");
const GAS = join(HAZE_ROOT, "dev/artifacts/verifier-gas-snapshot.json");
const ARTIFACT =
  "0xac2082ecb2129c571d2ddeb170f261a0da074491773102fa4f1544e97eb19281";

function loadCase(index) {
  const fixture = JSON.parse(readFileSync(SPEND_FIXTURE, "utf8"));
  return spendPublicInputs(fixture.cases[index].circom);
}

test("immutable spend verifier wrapper exists and forbids proxy mutation", () => {
  assert.equal(existsSync(WRAPPER), true);
  const source = readFileSync(WRAPPER, "utf8");
  assert.match(source, /NOT_FOR_PRODUCTION = true/);
  assert.match(source, /PUBLIC_INPUT_COUNT = 29/);
  assert.match(source, /immutable/);
  assert.doesNotMatch(source, /\b(owner|admin|upgradeTo|initialize)\s*\(/);
  assert.doesNotMatch(source, /delegatecall/i);
  assert.match(source, /KEYS_MISSING/);
});

test("rust and browser deposit public inputs verify against the committed artifact hash", () => {
  const inputs = loadCase(0);
  assert.equal(inputs.length, SPEND_PUBLIC_CAMEL.length);
  assert.equal(inputs.length, 29);
  checkSpendPublicInputs(inputs);
  const proof = developmentProofDigest(inputs);
  assert.equal(verifyDevelopmentSpend(inputs, proof, ARTIFACT), true);
  const packed = Buffer.concat(
    inputs.map((value) => {
      const hex = value.startsWith("0x")
        ? value.slice(2).padStart(64, "0")
        : BigInt(value).toString(16).padStart(64, "0");
      return Buffer.from(hex, "hex");
    }),
  );
  assert.equal(proof, `0x${Buffer.from(keccak256(packed)).toString("hex")}`);
});

test("malformed proofs and artifact mismatch fail", () => {
  const inputs = loadCase(0);
  const proof = developmentProofDigest(inputs);
  assert.throws(() => verifyDevelopmentSpend(inputs, proof, `0x${"11".repeat(32)}`), {
    code: "ARTIFACT_INVALID",
  });
  assert.throws(() => verifyDevelopmentSpend(inputs, `0x${"22".repeat(32)}`, ARTIFACT), {
    code: "PROOF_INVALID",
  });
  const badDeposit = [...inputs];
  badDeposit[7] = "1";
  assert.throws(() => checkSpendPublicInputs(badDeposit), /ENCODING_INVALID/);
});

test("rejects a proof whose pool version, public recipient, public value, intent hash, or audit ciphertext hash differs from the submitted action", () => {
  const inputs = loadCase(0);
  const proof = developmentProofDigest(inputs);
  const mutations = [
    ["poolVersionHi", 3],
    ["publicAmount", 17],
    ["publicRecipient", 18],
    ["intentHashHi", 20],
    ["auditCiphertextHashHi", 27],
  ];
  for (const [label, index] of mutations) {
    const mutated = [...inputs];
    mutated[index] = (BigInt(mutated[index]) + 1n).toString();
    assert.throws(
      () => verifyDevelopmentSpend(mutated, proof, ARTIFACT),
      { code: "PROOF_INVALID" },
      label,
    );
  }
});

test("committed verifier vector pins hashes and gas snapshot", () => {
  const vector = JSON.parse(readFileSync(VECTOR, "utf8"));
  assert.equal(vector.publicInputCount, 29);
  assert.equal(vector.artifactHash, ARTIFACT);
  assert.equal(vector.notForProduction, true);
  assert.equal(vector.spendProve, "KEYS_MISSING");
  assert.equal(existsSync(GAS), true);
  const snapshot = JSON.parse(readFileSync(GAS, "utf8"));
  assert.equal(snapshot.verify_deposit_gas, 15214);
});
