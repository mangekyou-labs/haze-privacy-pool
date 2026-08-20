import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  compileAndWitnessFull,
  fieldToBigInt,
  parseMainPublicSignals,
} from "../circuits/witness.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PROTOCOL_VECTORS = join(HAZE_ROOT, "circuits/vectors/v1/haze-protocol-v1.json");
const SPEND_FIXTURES = join(HAZE_ROOT, "circuits/vectors/v1/haze-spend-v1.json");
const SPEND_MAIN = join(HAZE_ROOT, "circuits/test/spend.circom");

const PUBLIC_SIGNALS = [
  ["protocolVersionTag", "protocol_version_tag"],
  ["chainId", "chain_id"],
  ["poolAddress", "pool_address"],
  ["poolVersionHi", "pool_version_hi"],
  ["poolVersionLo", "pool_version_lo"],
  ["applicationIdHi", "application_id_hi"],
  ["applicationIdLo", "application_id_lo"],
  ["noteTreeRoot", "note_tree_root"],
  ["applicationPolicyVersion", "application_policy_version"],
  ["hazePolicyVersion", "haze_policy_version"],
  ["applicationMembershipRoot", "application_membership_root"],
  ["hazeBlocklistRoot", "haze_blocklist_root"],
  ["inputNullifier0", "input_nullifier_0"],
  ["inputNullifier1", "input_nullifier_1"],
  ["outputCommitment0", "output_commitment_0"],
  ["outputCommitment1", "output_commitment_1"],
  ["action", "action"],
  ["publicAmount", "public_amount"],
  ["publicRecipient", "public_recipient"],
  ["authorizedUser", "authorized_user"],
  ["intentHashHi", "intent_hash_hi"],
  ["intentHashLo", "intent_hash_lo"],
  ["recipientCiphertextHash0Hi", "recipient_ciphertext_hash_0_hi"],
  ["recipientCiphertextHash0Lo", "recipient_ciphertext_hash_0_lo"],
  ["recipientCiphertextHash1Hi", "recipient_ciphertext_hash_1_hi"],
  ["recipientCiphertextHash1Lo", "recipient_ciphertext_hash_1_lo"],
  ["auditDataCommitment", "audit_data_commitment"],
  ["auditCiphertextHashHi", "audit_ciphertext_hash_hi"],
  ["auditCiphertextHashLo", "audit_ciphertext_hash_lo"],
];

function protocolFile() {
  return JSON.parse(readFileSync(PROTOCOL_VECTORS, "utf8"));
}

function spendFile() {
  assert.equal(existsSync(SPEND_FIXTURES), true, "missing haze/circuits/vectors/v1/haze-spend-v1.json");
  return JSON.parse(readFileSync(SPEND_FIXTURES, "utf8"));
}

function caseInput(name) {
  const file = spendFile();
  const found = file.cases.find((entry) => entry.name === name);
  assert.ok(found, `missing spend case ${name}`);
  return found.circom;
}

async function witnessCase(name) {
  return compileAndWitnessFull(SPEND_MAIN, caseInput(name), HAZE_ROOT, { sanityCheck: true });
}

test("normal spend circuit pins the frozen public-input order", () => {
  assert.equal(existsSync(SPEND_MAIN), true, "missing haze/circuits/test/spend.circom");
  const names = parseMainPublicSignals(readFileSync(SPEND_MAIN, "utf8"));
  assert.deepEqual(
    names,
    PUBLIC_SIGNALS.map(([circom]) => circom),
  );
  const frozen = protocolFile().positive.find((vector) => vector.name === "normal_public_input_order");
  assert.ok(frozen, "missing normal_public_input_order vector");
  assert.deepEqual(
    PUBLIC_SIGNALS.map(([, proto]) => proto),
    frozen.fields,
  );
});

test("proves a valid direct USDC deposit for a registered application", { timeout: 600_000 }, async () => {
  const result = await witnessCase("deposit");
  assert.equal(result.publicSignals.length, 29);
  assert.equal(result.publicSignals[16], 1n);
  assert.equal(result.publicSignals[17], 1_000_000n);
  assert.equal(result.publicSignals[18], 0n);
});

test("proves a valid 2-input/2-output same-application transfer with change", { timeout: 600_000 }, async () => {
  const result = await witnessCase("transfer");
  assert.equal(result.publicSignals[16], 2n);
  assert.equal(result.publicSignals[17], 0n);
  assert.equal(result.publicSignals[18], 0n);
  assert.notEqual(result.publicSignals[14], 0n);
  assert.notEqual(result.publicSignals[15], 0n);
});

test("proves a valid variable-value withdrawal with the public recipient and amount", { timeout: 600_000 }, async () => {
  const result = await witnessCase("withdraw");
  assert.equal(result.publicSignals[16], 3n);
  assert.equal(result.publicSignals[17], 600_000n);
  assert.notEqual(result.publicSignals[18], 0n);
});

test("rejects an input note whose commitment is absent from the submitted Merkle root", { timeout: 600_000 }, async () => {
  const input = structuredClone(caseInput("transfer"));
  input.noteTreeRoot = (fieldToBigInt(input.noteTreeRoot) + 1n).toString();
  await assert.rejects(() => compileAndWitnessFull(SPEND_MAIN, input, HAZE_ROOT, { sanityCheck: true }));
});

test("rejects an incorrect owner secret", { timeout: 600_000 }, async () => {
  const input = structuredClone(caseInput("transfer"));
  input.inSpendingSecret[0] = "99";
  await assert.rejects(() => compileAndWitnessFull(SPEND_MAIN, input, HAZE_ROOT, { sanityCheck: true }));
});

test("rejects input/output value inflation", { timeout: 600_000 }, async () => {
  const input = structuredClone(caseInput("transfer"));
  input.outValue[0] = "900000";
  await assert.rejects(() => compileAndWitnessFull(SPEND_MAIN, input, HAZE_ROOT, { sanityCheck: true }));
});

test("rejects mixed application IDs on an enabled output", { timeout: 600_000 }, async () => {
  const input = structuredClone(caseInput("deposit"));
  input.applicationIdHi = (fieldToBigInt(input.applicationIdHi) + 1n).toString();
  await assert.rejects(() => compileAndWitnessFull(SPEND_MAIN, input, HAZE_ROOT, { sanityCheck: true }));
});

test("rejects a dummy slot whose enable bit and value disagree", { timeout: 600_000 }, async () => {
  const input = structuredClone(caseInput("deposit"));
  input.inValue[0] = "1";
  await assert.rejects(() => compileAndWitnessFull(SPEND_MAIN, input, HAZE_ROOT, { sanityCheck: true }));
});

test("rejects an audit commitment that does not match the proven private fields", { timeout: 600_000 }, async () => {
  const input = structuredClone(caseInput("deposit"));
  input.auditSalt = "99";
  await assert.rejects(() => compileAndWitnessFull(SPEND_MAIN, input, HAZE_ROOT, { sanityCheck: true }));
});

test("pins the compiled spend constraint count", { timeout: 600_000 }, async () => {
  const file = spendFile();
  const result = await witnessCase("deposit");
  assert.equal(result.nConstraints, file.n_constraints);
  assert.ok(file.n_constraints > 0, "spend fixture must pin a positive constraint count");
});
