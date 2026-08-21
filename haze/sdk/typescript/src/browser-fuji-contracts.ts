import { addressWord, bytes32Word, concatBytes, encodeWords, functionSelector, hexToBuf, toHex, uintWord } from "./abi.ts";
import { POOL_SELECTORS } from "./bindings.ts";
import { AUTH_TYPE, EIP712_DOMAIN_TYPE, intentStructHash, type ApplicationAuthorizationFields, type HazeIntentFields } from "./eip712.ts";
import { POOL_DOMAIN_NAME, POOL_DOMAIN_VERSION } from "./pool.ts";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const ZERO = `0x${"00".repeat(32)}`;
type Witness = { actionReference: string; circom: Record<string, string>; envelopes: Record<string, string> };

function dynamicBytes(value: string) {
  const raw = hexToBuf(value); const padding = new Uint8Array((32 - raw.length % 32) % 32);
  return concatBytes(uintWord(raw.length), raw, padding);
}
function encodeIntent(value: HazeIntentFields) {
  return encodeWords([bytes32Word(value.applicationId), addressWord(value.user), addressWord(value.pool), bytes32Word(value.poolVersion), uintWord(value.action), bytes32Word(value.noteTreeRoot), uintWord(value.applicationPolicyVersion), uintWord(value.hazePolicyVersion), bytes32Word(value.applicationMembershipRoot), bytes32Word(value.hazeBlocklistRoot), bytes32Word(value.inputNullifier0), bytes32Word(value.inputNullifier1), bytes32Word(value.outputCommitment0), bytes32Word(value.outputCommitment1), uintWord(value.publicAmount), addressWord(value.publicRecipient), bytes32Word(value.recipientCiphertextHash0), bytes32Word(value.recipientCiphertextHash1), bytes32Word(value.auditDataCommitment), bytes32Word(value.auditCiphertextHash), addressWord(value.tokenIn), bytes32Word(value.amountIn), uintWord(value.minUsdcOut), bytes32Word(value.routeHash), uintWord(value.deadline)]);
}
function encodeAuthorization(value: ApplicationAuthorizationFields) {
  return encodeWords([bytes32Word(value.applicationId), addressWord(value.user), addressWord(value.pool), bytes32Word(value.poolVersion), uintWord(value.action), bytes32Word(value.intentHash), uintWord(value.applicationPolicyVersion), uintWord(value.hazePolicyVersion), bytes32Word(value.auditDataCommitment), bytes32Word(value.auditCiphertextHash), bytes32Word(value.nonce), uintWord(value.validAfter), uintWord(value.validUntil)]);
}
function parseTypes(signature: string) { return signature.slice(signature.indexOf("(") + 1, -1).split(",").map((part) => { const [type, name] = part.trim().split(/\s+/); return { type, name }; }); }

export function encodeBrowserGroth16Proof(proof: { pi_a?: string[]; pi_b?: string[][]; pi_c?: string[] } | { proof?: { pi_a?: string[]; pi_b?: string[][]; pi_c?: string[] } }) {
  const wrapped = proof as { proof?: { pi_a?: string[]; pi_b?: string[][]; pi_c?: string[] } };
  const value = wrapped.proof ?? proof as { pi_a?: string[]; pi_b?: string[][]; pi_c?: string[] }; const a = value.pi_a; const b = value.pi_b; const c = value.pi_c;
  if (!a || !b || !c || a.length < 2 || b.length < 2 || b[0].length < 2 || b[1].length < 2 || c.length < 2) throw new Error("PROOF_INVALID");
  return toHex(encodeWords([a[0], a[1], b[0][1], b[0][0], b[1][1], b[1][0], c[0], c[1]].map((word) => uintWord(word))));
}

export function planBrowserFujiSpend(input: { witness: Witness; user: string; pool: string; poolVersion: string; applicationId: string; action: 1 | 3; now: number; proof: string; publicRecipient?: string }) {
  const c = input.witness.circom; const e = input.witness.envelopes;
  const intent: HazeIntentFields = { applicationId: input.applicationId, user: input.user, pool: input.pool, poolVersion: input.poolVersion, action: input.action, noteTreeRoot: c.noteTreeRoot, applicationPolicyVersion: Number(c.applicationPolicyVersion), hazePolicyVersion: Number(c.hazePolicyVersion), applicationMembershipRoot: c.applicationMembershipRoot, hazeBlocklistRoot: c.hazeBlocklistRoot, inputNullifier0: c.inputNullifier0, inputNullifier1: c.inputNullifier1, outputCommitment0: c.outputCommitment0, outputCommitment1: c.outputCommitment1, publicAmount: Number(c.publicAmount), publicRecipient: input.publicRecipient ?? ZERO_ADDRESS, recipientCiphertextHash0: e.recipientCiphertextHash0, recipientCiphertextHash1: e.recipientCiphertextHash1, auditDataCommitment: c.auditDataCommitment, auditCiphertextHash: e.auditCiphertextHash, tokenIn: ZERO_ADDRESS, amountIn: ZERO, minUsdcOut: 0, routeHash: ZERO, deadline: 0 };
  const authorization: ApplicationAuthorizationFields = { applicationId: input.applicationId, user: input.user, pool: input.pool, poolVersion: input.poolVersion, action: input.action, intentHash: intentStructHash(intent), applicationPolicyVersion: intent.applicationPolicyVersion, hazePolicyVersion: intent.hazePolicyVersion, auditDataCommitment: intent.auditDataCommitment, auditCiphertextHash: intent.auditCiphertextHash, nonce: input.witness.actionReference, validAfter: input.now - 1, validUntil: input.now + 3600 };
  return { intent, authorization, proof: input.proof, recipientCiphertext0: e.recipientCiphertext0, recipientCiphertext1: e.recipientCiphertext1, auditCiphertext: e.auditCiphertext, typedData: { types: { EIP712Domain: parseTypes(EIP712_DOMAIN_TYPE), ApplicationAuthorization: parseTypes(AUTH_TYPE) }, primaryType: "ApplicationAuthorization", domain: { name: POOL_DOMAIN_NAME, version: POOL_DOMAIN_VERSION, chainId: 43113, verifyingContract: input.pool }, message: authorization } };
}

export function encodeBrowserFujiSpend(input: { plan: ReturnType<typeof planBrowserFujiSpend>; signature: string }) {
  const chunks = [input.signature, input.plan.proof, input.plan.recipientCiphertext0, input.plan.recipientCiphertext1, input.plan.auditCiphertext].map(dynamicBytes);
  let offset = (25 + 13 + 5) * 32; const offsets = chunks.map((chunk) => { const word = uintWord(offset); offset += chunk.length; return word; });
  const tuple = concatBytes(encodeIntent(input.plan.intent), encodeAuthorization(input.plan.authorization), ...offsets, ...chunks);
  const selector = input.plan.intent.action === 1 ? POOL_SELECTORS.deposit : POOL_SELECTORS.transact;
  return { to: input.plan.intent.pool, data: toHex(concatBytes(hexToBuf(selector), uintWord(32), tuple)) };
}

export function encodeErc20Approve(spender: string, amount: number | bigint) { return `0x095ea7b3${toHex(concatBytes(addressWord(spender), uintWord(amount))).slice(2)}`; }
export function encodeMembershipRootUpdate(applicationId: string, root: string) { return `${functionSelector("updateMembershipRoot(bytes32,bytes32)")}${toHex(concatBytes(bytes32Word(applicationId), bytes32Word(root))).slice(2)}`; }
