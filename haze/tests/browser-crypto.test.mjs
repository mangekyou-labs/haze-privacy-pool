import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  browserAuditAad,
  decodeBrowserEnvelope,
  deriveBrowserX25519PublicKey,
  encodeBrowserEnvelope,
  openBrowserHpke,
  sealBrowserHpke,
  sealBrowserHpkeToPublicKey,
} from "../sdk/typescript/src/browser-crypto.ts";
import { encodeBrowserAuditRecord } from "../sdk/typescript/src/browser-audit.ts";
import { buildFixtureDepositWitness } from "../dev/operator-circuit-witness.mjs";

const vectors = JSON.parse(readFileSync(new URL("../circuits/vectors/v1/haze-protocol-v1.json", import.meta.url)));
const named = (name) => vectors.positive.find((entry) => entry.name === name);
const bytes = (hex) => Uint8Array.from(hex.slice(2).match(/../g).map((value) => Number.parseInt(value, 16)));
const hex = (value) => `0x${Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;

test("browser HPKE opens the Rust recipient and audit vectors", () => {
  for (const name of ["recipient_hpke_seal_open", "audit_hpke_seal_open"]) {
    const vector = named(name);
    const opened = openBrowserHpke({
      recipientIkm: bytes(vector.recipient_ikm),
      encapsulatedKey: bytes(vector.encapsulated_key),
      ciphertext: bytes(vector.ciphertext),
      info: new TextEncoder().encode(vector.info),
      aad: bytes(vector.aad),
    });
    assert.equal(hex(opened), vector.plaintext);
  }
});

test("browser HPKE seals envelopes that the Rust-compatible receiver recovers", () => {
  for (const name of ["recipient_hpke_seal_open", "audit_hpke_seal_open"]) {
    const vector = named(name);
    const sealed = sealBrowserHpke({
      recipientIkm: bytes(vector.recipient_ikm),
      ephemeralSeed: bytes(vector.sender_seed),
      plaintext: bytes(vector.plaintext),
      info: new TextEncoder().encode(vector.info),
      aad: bytes(vector.aad),
    });
    assert.equal(hex(openBrowserHpke({ recipientIkm: bytes(vector.recipient_ikm), encapsulatedKey: sealed.encapsulatedKey, ciphertext: sealed.ciphertext, info: new TextEncoder().encode(vector.info), aad: bytes(vector.aad) })), vector.plaintext);
  }
});

test("browser note key derivation exposes only the X25519 public key", () => {
  const vector = named("recipient_hpke_seal_open");
  assert.equal(hex(deriveBrowserX25519PublicKey(bytes(vector.recipient_ikm))), vector.recipient_public_key);
});

test("browser HPKE seals to a published recipient key without receiving private IKM", () => {
  const vector = named("audit_hpke_seal_open");
  const sealed = sealBrowserHpkeToPublicKey({
    recipientPublicKey: bytes(vector.recipient_public_key),
    ephemeralSeed: bytes(vector.sender_seed),
    plaintext: bytes(vector.plaintext),
    info: new TextEncoder().encode(vector.info),
    aad: bytes(vector.aad),
  });
  const opened = openBrowserHpke({
    recipientIkm: bytes(vector.recipient_ikm),
    encapsulatedKey: sealed.encapsulatedKey,
    ciphertext: sealed.ciphertext,
    info: new TextEncoder().encode(vector.info),
    aad: bytes(vector.aad),
  });
  assert.equal(hex(opened), vector.plaintext);
});

test("browser envelope framing and audit AAD are canonical and reject trailing bytes", () => {
  const vector = named("audit_hpke_seal_open");
  const envelope = encodeBrowserEnvelope({ purpose: "audit", keyVersion: 1n, encapsulatedKey: bytes(vector.encapsulated_key), ciphertext: bytes(vector.ciphertext) });
  assert.deepEqual(decodeBrowserEnvelope(envelope), { purpose: "audit", keyVersion: 1n, encapsulatedKey: bytes(vector.encapsulated_key), ciphertext: bytes(vector.ciphertext) });
  assert.throws(() => decodeBrowserEnvelope(Uint8Array.from([...envelope, 0])), /ENCODING_INVALID/);
  assert.equal(hex(browserAuditAad({ chainId: 43113n, pool: bytes(`0x${"11".repeat(20)}`), poolVersion: bytes(`0x${"bb".repeat(32)}`), applicationId: bytes(`0x${"aa".repeat(32)}`), keyVersion: 1n, auditDataCommitment: bytes("0x21089fe7458962e7cdf023b636983fba634ad009846e4ba9cbbe079c28043960"), action: 1, actionReference: bytes(`0x${"01".repeat(32)}`) })), vector.aad);
});

test("browser HPKE rejects wrong AAD", () => {
  const vector = named("audit_hpke_seal_open");
  const aad = bytes(vector.aad); aad[0] ^= 1;
  assert.throws(() => openBrowserHpke({ recipientIkm: bytes(vector.recipient_ikm), encapsulatedKey: bytes(vector.encapsulated_key), ciphertext: bytes(vector.ciphertext), info: new TextEncoder().encode(vector.info), aad }), /CIPHERTEXT_INVALID/);
});

test("browser audit CBOR matches the frozen Rust canonical record", () => {
  const vector = named("audit_hpke_seal_open");
  const witness = buildFixtureDepositWitness();
  const recipientHash = named("recipient_envelope_hash").hash;
  const facts = { ...witness.auditFacts, recipientCiphertextHashes: [recipientHash, witness.auditFacts.recipientCiphertextHashes[1]] };
  assert.equal(hex(encodeBrowserAuditRecord(facts, new TextEncoder().encode("case-1"))), vector.plaintext);
});
