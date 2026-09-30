import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HAZE = resolve(dirname(fileURLToPath(import.meta.url)), "..");

test("classifyBrowserError distinguishes submit-time and policy reverts from Groth16 proof failures", async () => {
  const { classifyBrowserError } = await import("../sdk/typescript/src/fuji-browser-error.ts");

  // Submit-phase reverts
  const policyErr = classifyBrowserError(new Error("execution reverted: POLICY_INVALID"), "submitting");
  assert.equal(policyErr.category, "policy");
  assert.match(policyErr.message, /policy|membership/i);

  const eventErr = classifyBrowserError(new Error("FUJI_EVENT_NOT_CONFIRMED"), "submitting");
  assert.equal(eventErr.category, "submit");
  assert.match(eventErr.message, /submission|revert|event/i);

  const genericSubmitErr = classifyBrowserError(new Error("RPC error: transaction reverted"), "submitting");
  assert.equal(genericSubmitErr.category, "submit");

  // Proving-phase failures
  const proofErr = classifyBrowserError(new Error("WASM out of bounds or zkey corrupted"), "proving");
  assert.equal(proofErr.category, "proof");
  assert.match(proofErr.message, /proof/i);

  // Witness / validation errors
  const swapErr = classifyBrowserError(new Error("SWAP_VENUE_UNAVAILABLE"), "building_witness");
  assert.equal(swapErr.category, "swap");
  assert.equal(swapErr.message, "Swap venue unavailable — try again later");

  const noteErr = classifyBrowserError(new Error("DEPOSIT_NOTE_REQUIRED"), "building_witness");
  assert.equal(noteErr.category, "validation");
  assert.equal(noteErr.message, "Shield USDC first");

  const recipientErr = classifyBrowserError(new Error("RECIPIENT_ADDRESS_REQUIRED"), "building_witness");
  assert.equal(recipientErr.category, "validation");
  assert.equal(recipientErr.message, "Enter a haze1 recipient");

  const auditErr = classifyBrowserError(new Error("AUDIT_PUBLIC_KEY_MISSING"), "building_witness");
  assert.equal(auditErr.category, "validation");
  assert.match(auditErr.message, /audit/i);
});

test("fuji-browser-client JSX dynamically sets data-error and wires .haze-confirm to executeSpendWorkflow", () => {
  const source = readFileSync(join(HAZE, "web/apps/haze/app/[route]/fuji-browser-client.tsx"), "utf8");
  assert.doesNotMatch(source, /data-error="proof"/);
  assert.match(source, /data-error=\{errorCategory/);
  assert.match(source, /className="[^"]*haze-confirm[^"]*"/, "fuji-browser-client must contain .haze-confirm button");
  assert.match(source, /onClick=\{[^}]*executeSpendWorkflow/, ".haze-confirm button must trigger executeSpendWorkflow");
});
