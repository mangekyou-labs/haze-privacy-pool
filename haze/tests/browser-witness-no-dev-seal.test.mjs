import assert from "node:assert/strict";
import test from "node:test";
import { buildSealedBrowserWitness } from "../sdk/typescript/src/browser-witness-flow.ts";
import { buildLiveDepositWitness } from "../dev/operator-circuit-witness.mjs";

// The browser must never fall back to the witness's node:crypto dev-key audit sealing.
const requireAuditEnvelope = (input) => {
  if (!input.auditEnvelope) throw new Error("witness built without auditEnvelope (dev-key fallback)");
  return buildLiveDepositWitness(input);
};

test("browser deposit flow never asks the witness to seal with the dev audit key", () => {
  let random = 0;
  const result = buildSealedBrowserWitness({
    buildWitness: requireAuditEnvelope,
    witnessInput: { pool: "0x2A75Ed378cf23Dd724A4077cF122E87491172e71", user: "0xeD37FD0d6F0f69236E7472B36796e133D20EcC32", applicationId: `0x${"00".repeat(30)}0a11`, poolVersion: `0x${"00".repeat(30)}b002`, publicAmount: 1_000_000, applicationPolicyVersion: 1, hazePolicyVersion: 1 },
    chainId: 43113,
    pool: "0x2A75Ed378cf23Dd724A4077cF122E87491172e71",
    poolVersion: `0x${"00".repeat(30)}b002`, applicationId: `0x${"00".repeat(30)}0a11`,
    auditPublicKey: Uint8Array.from("1b9b5de7274e874632960720219be873afa5fd0249347e3900763d8a774c2546".match(/../g), (b) => Number.parseInt(b, 16)),
    auditKeyVersion: 1n, caseTag: new TextEncoder().encode("NO-DEV-SEAL"),
    browserCrypto: { getRandomValues(bytes) { bytes.fill(++random); return bytes; } },
  });
  assert.equal(result.witness.envelopes.auditCiphertextHash, result.auditEnvelope.hash);
});
