import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { SdkError } from "../sdk/typescript/src/errors.ts";
import {
  applicationMember,
  globalBlockedAddress,
  globalBlockedNote,
  requireLivePolicy,
} from "../sdk/typescript/src/policy.ts";
import { keccak256 } from "./keccak256.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const VECTOR_PATH = resolve(HAZE_ROOT, "circuits/vectors/v1/haze-protocol-v1.json");

const INTENT_TYPE =
  "HazeIntent(bytes32 applicationId,address user,address pool,bytes32 poolVersion,uint8 action,uint256 noteTreeRoot,uint64 applicationPolicyVersion,uint64 hazePolicyVersion,uint256 applicationMembershipRoot,uint256 hazeBlocklistRoot,uint256 inputNullifier0,uint256 inputNullifier1,uint256 outputCommitment0,uint256 outputCommitment1,uint64 publicAmount,address publicRecipient,bytes32 recipientCiphertextHash0,bytes32 recipientCiphertextHash1,uint256 auditDataCommitment,bytes32 auditCiphertextHash,address tokenIn,uint256 amountIn,uint64 minUsdcOut,bytes32 routeHash,uint48 deadline)";
const AUTH_TYPE =
  "ApplicationAuthorization(bytes32 applicationId,address user,address pool,bytes32 poolVersion,uint8 action,bytes32 intentHash,uint64 applicationPolicyVersion,uint64 hazePolicyVersion,uint256 auditDataCommitment,bytes32 auditCiphertextHash,bytes32 nonce,uint48 validAfter,uint48 validUntil)";
const KEY_TYPE = "HazeKeyDerivation(address wallet,bytes32 applicationId,bytes32 poolVersion)";
const DOMAIN_TYPE =
  "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const BN254_R = Buffer.from(
  "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
  "hex",
);

function hex(bytes) {
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

function parseHex(value) {
  return Buffer.from(value.replace(/^0x/, ""), "hex");
}

function fieldFromKeccak(digest) {
  const modulus = BigInt(`0x${BN254_R.toString("hex")}`);
  const reduced = BigInt(hex(digest)) % modulus;
  return `0x${reduced.toString(16).padStart(64, "0")}`;
}

function loadVectors() {
  return JSON.parse(readFileSync(VECTOR_PATH, "utf8"));
}

function named(vectors, name) {
  return vectors.positive.find((vector) => vector.name === name);
}

test("TypeScript harness loads the committed Haze protocol vectors", () => {
  const file = loadVectors();
  assert.equal(file.schema_version, 1);
  assert.equal(file.product_id, "haze-avalanche-compliant-pool");
  assert.ok(file.domains.length >= 13);
  assert.ok(file.positive.length >= 8);
  assert.ok(file.negative.length >= 8);
});

test("TypeScript harness recomputes keccak domain tags and EIP-712 type hashes", () => {
  const file = loadVectors();
  for (const domain of file.domains) {
    const digest = keccak256(Buffer.from(domain.label, "utf8"));
    assert.equal(hex(digest), domain.keccak);
    assert.equal(fieldFromKeccak(digest), domain.field);
    assert.ok(parseHex(domain.field).compare(BN254_R) < 0);
  }

  const types = named(file, "eip712_type_hashes");
  assert.equal(hex(keccak256(Buffer.from(DOMAIN_TYPE, "utf8"))), types.domain);
  assert.equal(hex(keccak256(Buffer.from(INTENT_TYPE, "utf8"))), types.intent);
  assert.equal(hex(keccak256(Buffer.from(AUTH_TYPE, "utf8"))), types.authorization);
  assert.equal(hex(keccak256(Buffer.from(KEY_TYPE, "utf8"))), types.key_derivation);
});

test("TypeScript harness recomputes bytes32 limbs and envelope hashes", () => {
  const file = loadVectors();
  const limbs = named(file, "bytes32_limbs_roundtrip");
  const input = parseHex(limbs.input);
  const hi = Buffer.concat([Buffer.alloc(16), input.subarray(0, 16)]);
  const lo = Buffer.concat([Buffer.alloc(16), input.subarray(16)]);
  assert.equal(hex(hi), limbs.hi);
  assert.equal(hex(lo), limbs.lo);
  assert.equal(hex(Buffer.concat([hi.subarray(16), lo.subarray(16)])), limbs.recombined);

  const recipient = named(file, "recipient_envelope_hash");
  const audit = named(file, "audit_envelope_hash");
  const recipientBytes = Buffer.concat([
    Buffer.from("HZHP"),
    Buffer.from([1, 1]),
    Buffer.from([0x00, 0x20, 0x00, 0x01, 0x00, 0x03]),
    Buffer.alloc(8),
    Buffer.from([0x00, 32]),
    Buffer.alloc(32, 0x11),
    Buffer.from([0x00, 0x00, 0x00, 48]),
    Buffer.alloc(48, 0x22),
  ]);
  const auditBytes = Buffer.concat([
    Buffer.from("HZHP"),
    Buffer.from([1, 2]),
    Buffer.from([0x00, 0x20, 0x00, 0x01, 0x00, 0x03]),
    Buffer.from([0, 0, 0, 0, 0, 0, 0, 1]),
    Buffer.from([0x00, 32]),
    Buffer.alloc(32, 0x33),
    Buffer.from([0x00, 0x00, 0x00, 64]),
    Buffer.alloc(64, 0x44),
  ]);
  assert.equal(hex(keccak256(recipientBytes)), recipient.hash);
  assert.equal(hex(keccak256(auditBytes)), audit.hash);
});

test("TypeScript harness rejects modulus and padded Haze addresses", () => {
  const file = loadVectors();
  const modulus = file.negative.find((vector) => vector.name === "field_equal_to_modulus");
  assert.ok(parseHex(modulus.input).compare(BN254_R) === 0);
  const padded = file.negative.find((vector) => vector.name === "padded_haze_address");
  assert.ok(padded.input.endsWith("="));
  const lowOrder = file.negative.find((vector) => vector.name === "low_order_x25519");
  assert.equal(lowOrder.reason, "FIELD_OUT_OF_RANGE");
  assert.ok(parseHex(lowOrder.input).equals(Buffer.alloc(32)));
  const unknownDomain = file.negative.find((vector) => vector.name === "unknown_poseidon_domain");
  assert.equal(unknownDomain.reason, "DOMAIN_MISMATCH");
  const uint48 = file.negative.find((vector) => vector.name === "uint48_deadline_out_of_range");
  assert.equal(uint48.reason, "FIELD_OUT_OF_RANGE");
  assert.equal(uint48.input, 2 ** 48);
});

test("TypeScript harness requires unique Poseidon domain fields", () => {
  const file = loadVectors();
  const fields = file.domains.map((domain) => domain.field);
  assert.equal(new Set(fields).size, fields.length);
  assert.equal(file.domains.length, 13);
});

test("TypeScript harness binds parameter-file hashes and public-input order", () => {
  const file = loadVectors();
  assert.ok(Array.isArray(file.parameter_files));
  assert.equal(file.parameter_files.length, 2);
  for (const entry of file.parameter_files) {
    const bytes = readFileSync(resolve(HAZE_ROOT, "..", entry.path));
    assert.equal(hex(keccak256(bytes)), entry.keccak);
  }

  const normal = named(file, "normal_public_input_order");
  const emergency = named(file, "emergency_public_input_order");
  assert.equal(normal.fields.length, 29);
  assert.equal(emergency.fields.length, 20);
  assert.equal(normal.fields[0], "protocol_version_tag");
  assert.equal(emergency.fields[10], "input_nullifier");
});

test("TypeScript SDK recomputes committed membership and blocklist subject hashes", () => {
  const file = loadVectors();
  const applicationId = `0x${"aa".repeat(32)}`;
  const npk = named(file, "note_public_key").field;
  const enc = named(file, "encryption_key_hash").field;
  assert.equal(applicationMember(applicationId, npk, enc), named(file, "application_member").field);
  assert.equal(
    globalBlockedNote({
      chainId: 43113,
      applicationId,
      notePublicKey: npk,
      encryptionKeyHash: enc,
    }),
    named(file, "global_blocked_note").field,
  );
  assert.equal(
    globalBlockedAddress(43113, `0x${"22".repeat(20)}`),
    named(file, "global_blocked_address").field,
  );
});

test("TypeScript requireLivePolicy rejects stale future and mismatched roots with no grace", () => {
  const root = `0x${"44".repeat(32)}`;
  const next = `0x${"ab".repeat(32)}`;
  requireLivePolicy(1, root, 1, root);
  assert.throws(() => requireLivePolicy(0, root, 1, root), (error) => {
    assert.ok(error instanceof SdkError);
    assert.equal(error.code, "VERSION_UNSUPPORTED");
    return true;
  });
  assert.throws(() => requireLivePolicy(1, root, 2, root), (error) => error.code === "VERSION_UNSUPPORTED");
  assert.throws(() => requireLivePolicy(1, root, 1, next), (error) => error.code === "VERSION_UNSUPPORTED");
  assert.throws(() => requireLivePolicy(2, next, 1, root), (error) => error.code === "VERSION_UNSUPPORTED");
});

test("TypeScript harness records deposit zero-rule and HPKE negatives", () => {
  const file = loadVectors();
  const deposit = file.negative.find((vector) => vector.name === "nonzero_deposit_tree_or_nullifiers");
  assert.equal(deposit.reason, "ENCODING_INVALID");
  const hpke = file.negative.find((vector) => vector.name === "hpke_open_wrong_aad");
  assert.equal(hpke.reason, "CIPHERTEXT_INVALID");
  assert.ok(named(file, "recipient_hpke_seal_open").encapsulated_key);
  assert.ok(named(file, "audit_cbor_record").bytes.startsWith("0x"));
});
