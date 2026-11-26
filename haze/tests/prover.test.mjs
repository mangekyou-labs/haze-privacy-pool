import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  createProverSession,
  deriveShieldedAccount,
  deriveShieldedAccountFromSignature,
  hashArtifactSet,
  keyDerivationDigest,
  spendPublicInputs,
} from "../sdk/typescript/src/prover.ts";
import { secp256k1 } from "@noble/curves/secp256k1";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SPEND = join(HAZE_ROOT, "circuits/vectors/v1/haze-spend-v1.json");
const PROTOCOL = join(HAZE_ROOT, "circuits/vectors/v1/haze-protocol-v1.json");
const PROVER = join(HAZE_ROOT, "circuits/vectors/v1/haze-prover-v1.json");
const MANIFEST = join(HAZE_ROOT, "dev/artifacts/development-circuit-manifest.json");
const BENCHMARK = join(HAZE_ROOT, "dev/artifacts/proving-benchmark.json");

const PUBLIC_SIGNALS = [
  "protocolVersionTag",
  "chainId",
  "poolAddress",
  "poolVersionHi",
  "poolVersionLo",
  "applicationIdHi",
  "applicationIdLo",
  "noteTreeRoot",
  "applicationPolicyVersion",
  "hazePolicyVersion",
  "applicationMembershipRoot",
  "hazeBlocklistRoot",
  "inputNullifier0",
  "inputNullifier1",
  "outputCommitment0",
  "outputCommitment1",
  "action",
  "publicAmount",
  "publicRecipient",
  "authorizedUser",
  "intentHashHi",
  "intentHashLo",
  "recipientCiphertextHash0Hi",
  "recipientCiphertextHash0Lo",
  "recipientCiphertextHash1Hi",
  "recipientCiphertextHash1Lo",
  "auditDataCommitment",
  "auditCiphertextHashHi",
  "auditCiphertextHashLo",
];

function spendCase(name) {
  const file = JSON.parse(readFileSync(SPEND, "utf8"));
  return file.cases.find((entry) => entry.name === name).circom;
}

function fixtureRequest() {
  return {
    chainId: 43113,
    pool: "0x1111111111111111111111111111111111111111",
    wallet: "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
    applicationId: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    poolVersion: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    signingKey: "0x0000000000000000000000000000000000000000000000000000000000000001",
  };
}

test("TypeScript derives a repeatable shielded account from the wallet message", () => {
  const expected = JSON.parse(readFileSync(PROVER, "utf8"));
  const first = deriveShieldedAccount(fixtureRequest());
  const second = deriveShieldedAccount(fixtureRequest());
  assert.equal(first.wallet, fixtureRequest().wallet);
  assert.equal(first.spendingSecret, second.spendingSecret);
  assert.equal(first.x25519PublicKey, second.x25519PublicKey);
  assert.equal(keyDerivationDigest(fixtureRequest()), expected.typedDigest);
  assert.equal(first.spendingSecret, expected.spendingSecret);
  assert.equal(first.spendingCounter, expected.spendingCounter);
  assert.equal(first.x25519PublicKey, expected.x25519PublicKey);
  assert.equal(first.localVaultKey, expected.localVaultKey);
  assert.equal(first.membershipBlinding, expected.membershipBlinding);
  assert.notEqual(first.spendingSecret, "0x" + "00".repeat(32));
});

test("deriveShieldedAccountFromSignature derives identical account from valid signature and rejects mismatch", () => {
  const req = fixtureRequest();
  const expected = deriveShieldedAccount(req);
  const digest = Buffer.from(keyDerivationDigest(req).replace(/^0x/i, ""), "hex");
  const privKey = Buffer.from(req.signingKey.replace(/^0x/i, ""), "hex");
  const sig = secp256k1.sign(digest, privKey, { prehash: false });
  const low = sig.normalizeS();
  const recovery = sig.recovery === undefined ? 0 : sig.recovery;
  const flipped = sig.hasHighS() ? recovery ^ 1 : recovery;
  const sigBytes = Buffer.alloc(65);
  Buffer.from(low.toCompactRawBytes()).copy(sigBytes);
  sigBytes[64] = flipped + 27; // standard Ethereum v = 27 or 28

  const derived = deriveShieldedAccountFromSignature({
    signature: `0x${sigBytes.toString("hex")}`,
    wallet: req.wallet,
    chainId: req.chainId,
    pool: req.pool,
    applicationId: req.applicationId,
    poolVersion: req.poolVersion,
  });
  assert.equal(derived.wallet, expected.wallet);
  assert.equal(derived.spendingSecret, expected.spendingSecret);
  assert.equal(derived.x25519PublicKey, expected.x25519PublicKey);
  assert.equal(derived.x25519Secret, expected.x25519Secret);
  assert.equal(derived.localVaultKey, expected.localVaultKey);

  assert.throws(
    () =>
      deriveShieldedAccountFromSignature({
        signature: `0x${sigBytes.toString("hex")}`,
        wallet: "0x0000000000000000000000000000000000000001",
        chainId: req.chainId,
        pool: req.pool,
        applicationId: req.applicationId,
        poolVersion: req.poolVersion,
      }),
    { code: "UNSUPPORTED_RECOVERY" },
  );
});

test("TypeScript spend public inputs match the frozen order and deposit fixture", () => {
  const protocol = JSON.parse(readFileSync(PROTOCOL, "utf8"));
  const frozen = protocol.positive.find((vector) => vector.name === "normal_public_input_order");
  assert.equal(PUBLIC_SIGNALS.length, frozen.fields.length);
  const inputs = spendPublicInputs(spendCase("deposit"));
  assert.equal(inputs.length, 29);
  assert.equal(inputs[16], "1");
  assert.equal(
    inputs[7],
    "0x0000000000000000000000000000000000000000000000000000000000000000",
  );
});

test("TypeScript spend proving without ceremony keys returns KEYS_MISSING", async () => {
  const session = createProverSession();
  await assert.rejects(() => session.proveSpend(spendCase("deposit")), {
    code: "KEYS_MISSING",
  });
});

test("cancelled TypeScript session does not emit a proof", async () => {
  const session = createProverSession();
  session.cancel();
  await assert.rejects(() => session.proveDevelopment(7), { code: "CANCELLED" });
});

test("TypeScript development proof verifies and clears witness material", async () => {
  const session = createProverSession();
  const secret = session.retainSecret(Uint8Array.from({ length: 32 }, () => 0x11));
  const started = performance.now();
  const proof = await session.proveDevelopment(7);
  const durationMs = Number((performance.now() - started).toFixed(3));
  assert.equal(proof.profile, "development");
  assert.equal(proof.notForProduction, true);
  assert.equal(proof.verified, true);
  session.clear();
  assert.ok(secret.every((byte) => byte === 0));
  assert.equal(existsSync(BENCHMARK), true);
  assert.ok(durationMs < 15000);
});

test("TypeScript hashes development circuit artifacts", async () => {
  const digest = await hashArtifactSet({
    circuit: join(HAZE_ROOT, "circuits/src/spend.circom"),
    fixture: join(HAZE_ROOT, "circuits/vectors/v1/haze-spend-v1.json"),
    manifest: MANIFEST,
  });
  assert.match(digest, /^0x[0-9a-f]{64}$/);
  assert.notEqual(digest, "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
  const expected = JSON.parse(readFileSync(PROVER, "utf8"));
  assert.equal(digest, expected.artifactHash);
});
