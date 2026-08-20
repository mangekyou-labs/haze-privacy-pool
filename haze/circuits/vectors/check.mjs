import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { keccak256 } from "../../tests/keccak256.mjs";
import { compileAndWitness, fieldToBigInt, hazeRootFrom } from "../witness.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const VECTOR_PATH = resolve(HERE, "v1/haze-protocol-v1.json");
const WORKTREE_ROOT = resolve(HERE, "../../..");
const file = JSON.parse(readFileSync(VECTOR_PATH, "utf8"));

function hex(bytes) {
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

assert.equal(file.schema_version, 1);
assert.equal(file.primitives.poseidon2.width, 3);
assert.equal(file.primitives.poseidon2.rate, 2);
assert.equal(file.primitives.poseidon2.capacity, 1);
assert.equal(file.primitives.poseidon2.sbox, 5);
assert.equal(file.primitives.poseidon2.full_rounds, 8);
assert.equal(file.primitives.poseidon2.partial_rounds, 56);
assert.equal(file.primitives.hash_boundary, "poseidon2+keccak256");
assert.ok(file.domains.length >= 13);
assert.ok(file.positive.some((vector) => vector.name === "note_commitment"));
assert.ok(file.negative.some((vector) => vector.reason === "FIELD_OUT_OF_RANGE"));

const domainFields = new Set();
for (const domain of file.domains) {
  assert.match(domain.field, /^0x[0-9a-f]{64}$/);
  assert.notEqual(
    domain.field,
    "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
  );
  assert.equal(domainFields.has(domain.field), false);
  domainFields.add(domain.field);
}
assert.equal(file.domains.length, 13);
assert.ok(file.negative.some((vector) => vector.name === "low_order_x25519"));
assert.ok(file.negative.some((vector) => vector.name === "nonzero_deposit_tree_or_nullifiers"));

assert.ok(Array.isArray(file.parameter_files));
assert.equal(file.parameter_files.length, 2);
for (const entry of file.parameter_files) {
  const bytes = readFileSync(resolve(WORKTREE_ROOT, entry.path));
  assert.equal(hex(keccak256(bytes)), entry.keccak);
}

const normal = file.positive.find((vector) => vector.name === "normal_public_input_order");
const emergency = file.positive.find((vector) => vector.name === "emergency_public_input_order");
assert.equal(normal.fields.length, 29);
assert.equal(emergency.fields.length, 20);
assert.equal(normal.fields[20], "intent_hash_hi");
assert.equal(emergency.fields[15], "request_id_hi");

assert.ok(file.positive.some((vector) => vector.name === "poseidon_pad_odd"));
assert.ok(file.positive.some((vector) => vector.name === "poseidon_pad_even"));

const noteKey = file.positive.find((vector) => vector.name === "note_public_key");
const noteDomain = file.domains.find((domain) => domain.label === "haze/avalanche/v1/note-key");
const hazeRoot = hazeRootFrom(resolve(HERE, ".."));
const sponge = await compileAndWitness(
  resolve(HERE, "../test/sponge_1.circom"),
  {
    domain: fieldToBigInt(noteDomain.field).toString(),
    in: ["1"],
  },
  hazeRoot,
);
assert.equal(sponge.out, fieldToBigInt(noteKey.field));

console.log("circom vector harness ok");
