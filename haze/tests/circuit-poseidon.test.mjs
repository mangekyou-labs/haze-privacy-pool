import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { compileAndWitness, fieldToBigInt, resolveCircom } from "../circuits/witness.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const VECTOR_PATH = join(HAZE_ROOT, "circuits/vectors/v1/haze-protocol-v1.json");
const TEST_DIR = join(HAZE_ROOT, "circuits/test");

function vector(name) {
  const file = JSON.parse(readFileSync(VECTOR_PATH, "utf8"));
  const found = file.positive.find((entry) => entry.name === name);
  assert.ok(found, `missing vector ${name}`);
  return found;
}

function domainField(label) {
  const file = JSON.parse(readFileSync(VECTOR_PATH, "utf8"));
  const found = file.domains.find((entry) => entry.label === label);
  assert.ok(found, `missing domain ${label}`);
  return found.field;
}

function hexToDec(hex) {
  return fieldToBigInt(hex).toString();
}

test("resolves Circom 2.2.3 from haze/.tools, not PATH circom 0.5", () => {
  const circom = resolveCircom(HAZE_ROOT);
  assert.match(circom, /\.tools\/bin\/circom$/);
  assert.equal(existsSync(circom), true, "missing haze/.tools/bin/circom");
});

test("Circom sponge matches note_public_key vector", async () => {
  const witness = await compileAndWitness(join(TEST_DIR, "sponge_1.circom"), {
    domain: hexToDec(domainField("haze/avalanche/v1/note-key")),
    in: [hexToDec("0x0000000000000000000000000000000000000000000000000000000000000001")],
  });
  assert.equal(witness.out, fieldToBigInt(vector("note_public_key").field));
});

test("Circom sponge matches encryption_key_hash vector", async () => {
  const pad = vector("poseidon_pad_even");
  const witness = await compileAndWitness(join(TEST_DIR, "sponge_2.circom"), {
    domain: hexToDec(domainField(pad.domain)),
    in: pad.inputs.map(hexToDec),
  });
  assert.equal(witness.out, fieldToBigInt(vector("encryption_key_hash").field));
});

test("Circom Merkle parent and depth-32 path match committed vectors", async () => {
  const path = vector("merkle_note_path");
  const parent = await compileAndWitness(join(TEST_DIR, "merkle_parent.circom"), {
    domain: hexToDec(domainField(path.domain)),
    level: "0",
    left: hexToDec(path.leaf),
    right: hexToDec(path.siblings[0]),
  });
  assert.notEqual(parent.out, 0n);

  const index = BigInt(path.index);
  const indexBits = Array.from({ length: 32 }, (_, level) => ((index >> BigInt(level)) & 1n).toString());
  const root = await compileAndWitness(join(TEST_DIR, "merkle_path.circom"), {
    domain: hexToDec(domainField(path.domain)),
    leaf: hexToDec(path.leaf),
    indexBits,
    siblings: path.siblings.map(hexToDec),
  });
  assert.equal(root.out, fieldToBigInt(path.root));

  const empty = await compileAndWitness(join(TEST_DIR, "merkle_path.circom"), {
    domain: hexToDec(domainField(path.domain)),
    leaf: hexToDec("0x0000000000000000000000000000000000000000000000000000000000000000"),
    indexBits: Array.from({ length: 32 }, () => "0"),
    siblings: path.siblings.map(hexToDec),
  });
  assert.equal(empty.out, fieldToBigInt(vector("empty_note_root").field));
});

test("Circom note commitment, nullifier, and application member match vectors", async () => {
  const limbs = vector("bytes32_limbs_roundtrip");
  const commitment = await compileAndWitness(join(TEST_DIR, "note_commitment.circom"), {
    domain: hexToDec(domainField("haze/avalanche/v1/note")),
    poolDomain: hexToDec(vector("pool_domain_fuji").field),
    applicationIdHi: hexToDec(limbs.hi),
    applicationIdLo: hexToDec(limbs.lo),
    value: "1000000",
    ownerNotePublicKey: hexToDec(vector("note_public_key").field),
    ownerEncryptionKeyHash: hexToDec(vector("encryption_key_hash").field),
    blinding: hexToDec("0x0000000000000000000000000000000000000000000000000000000000000002"),
  });
  assert.equal(commitment.out, fieldToBigInt(vector("note_commitment").field));

  const nf = await compileAndWitness(join(TEST_DIR, "nullifier.circom"), {
    domain: hexToDec(domainField("haze/avalanche/v1/nullifier")),
    poolDomain: hexToDec(vector("pool_domain_fuji").field),
    applicationIdHi: hexToDec(vector("bytes32_limbs_roundtrip").hi),
    applicationIdLo: hexToDec(vector("bytes32_limbs_roundtrip").lo),
    commitment: hexToDec(vector("note_commitment").field),
    leafIndex: String(vector("merkle_note_path").index),
    spendingSecret: hexToDec("0x0000000000000000000000000000000000000000000000000000000000000001"),
  });
  assert.equal(nf.out, fieldToBigInt(vector("nullifier").field));

  const member = await compileAndWitness(join(TEST_DIR, "application_member.circom"), {
    domain: hexToDec(domainField("haze/avalanche/v1/app-member")),
    applicationIdHi: hexToDec(vector("bytes32_limbs_roundtrip").hi),
    applicationIdLo: hexToDec(vector("bytes32_limbs_roundtrip").lo),
    notePublicKey: hexToDec(vector("note_public_key").field),
    encryptionKeyHash: hexToDec(vector("encryption_key_hash").field),
  });
  assert.equal(member.out, fieldToBigInt(vector("application_member").field));

  const blockedNote = await compileAndWitness(join(TEST_DIR, "global_blocked_note.circom"), {
    domain: hexToDec(domainField("haze/avalanche/v1/block-note")),
    chainId: "43113",
    applicationIdHi: hexToDec(vector("bytes32_limbs_roundtrip").hi),
    applicationIdLo: hexToDec(vector("bytes32_limbs_roundtrip").lo),
    notePublicKey: hexToDec(vector("note_public_key").field),
    encryptionKeyHash: hexToDec(vector("encryption_key_hash").field),
  });
  assert.equal(blockedNote.out, fieldToBigInt(vector("global_blocked_note").field));

  const blockedAddress = await compileAndWitness(join(TEST_DIR, "global_blocked_address.circom"), {
    domain: hexToDec(domainField("haze/avalanche/v1/block-evm-address")),
    chainId: "43113",
    address: hexToDec("0x0000000000000000000000002222222222222222222222222222222222222222"),
  });
  assert.equal(blockedAddress.out, fieldToBigInt(vector("global_blocked_address").field));
});
