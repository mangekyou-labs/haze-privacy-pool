import { addressWord, bytes32Word, canonicalUint256, concatBytes, encodeWords, functionSelector, hexToBuf, toHex, uintWord } from "./abi.ts";
import { POOL_SELECTORS, ROUTER_SELECTORS } from "./bindings.ts";
import { AUTH_TYPE, EIP712_DOMAIN_TYPE, intentStructHash, type ApplicationAuthorizationFields, type HazeIntentFields } from "./eip712.ts";
import { keccak256 } from "./keccak.ts";
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

export const SPEND_PUBLIC_CAMEL = [
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
] as const;

export function deriveDevelopmentSpendProof(circom: Record<string, unknown>): string {
  const words = SPEND_PUBLIC_CAMEL.map((key) => {
    const val = circom[key];
    if (typeof val === "string") {
      if (val.startsWith("0x") || val.startsWith("0X")) {
        return hexToBuf(val.slice(2).padStart(64, "0"));
      }
      return hexToBuf(BigInt(val).toString(16).padStart(64, "0"));
    }
    if (typeof val === "number" || typeof val === "bigint") {
      return hexToBuf(BigInt(val).toString(16).padStart(64, "0"));
    }
    throw new Error(`WITNESS_FIELD_INVALID: ${key}`);
  });
  const packed = concatBytes(...words);
  return toHex(keccak256(packed));
}
export function planBrowserFujiSpend(input: {
  witness: Witness;
  user: string;
  pool: string;
  poolVersion: string;
  applicationId: string;
  action: 1 | 2 | 3 | 4;
  now: number;
  proof: string;
  publicRecipient?: string;
  tokenIn?: string;
  amountIn?: string | number | bigint;
  minUsdcOut?: number | bigint;
  routeHash?: string;
  deadline?: number | bigint;
}) {
  const c = input.witness.circom; const e = input.witness.envelopes;
  const intent: HazeIntentFields = {
    applicationId: input.applicationId,
    user: input.user,
    pool: input.pool,
    poolVersion: input.poolVersion,
    action: input.action,
    noteTreeRoot: c.noteTreeRoot,
    applicationPolicyVersion: Number(c.applicationPolicyVersion),
    hazePolicyVersion: Number(c.hazePolicyVersion),
    applicationMembershipRoot: c.applicationMembershipRoot,
    hazeBlocklistRoot: c.hazeBlocklistRoot,
    inputNullifier0: c.inputNullifier0,
    inputNullifier1: c.inputNullifier1,
    outputCommitment0: c.outputCommitment0,
    outputCommitment1: c.outputCommitment1,
    publicAmount: Number(c.publicAmount),
    publicRecipient: input.publicRecipient ?? ZERO_ADDRESS,
    recipientCiphertextHash0: e.recipientCiphertextHash0,
    recipientCiphertextHash1: e.recipientCiphertextHash1,
    auditDataCommitment: c.auditDataCommitment,
    auditCiphertextHash: e.auditCiphertextHash,
    tokenIn: input.tokenIn ?? ZERO_ADDRESS,
    amountIn: canonicalUint256(input.amountIn ?? ZERO),
    minUsdcOut: Number(input.minUsdcOut ?? 0),
    routeHash: input.routeHash ?? ZERO,
    deadline: Number(input.deadline ?? 0),
  };
  const authorization: ApplicationAuthorizationFields = {
    applicationId: input.applicationId,
    user: input.user,
    pool: input.pool,
    poolVersion: input.poolVersion,
    action: input.action,
    intentHash: intentStructHash(intent),
    applicationPolicyVersion: intent.applicationPolicyVersion,
    hazePolicyVersion: intent.hazePolicyVersion,
    auditDataCommitment: intent.auditDataCommitment,
    auditCiphertextHash: intent.auditCiphertextHash,
    nonce: input.witness.actionReference,
    validAfter: input.now - 300,
    validUntil: input.now + 3600,
  };
  return {
    intent,
    authorization,
    proof: input.proof,
    recipientCiphertext0: e.recipientCiphertext0,
    recipientCiphertext1: e.recipientCiphertext1,
    auditCiphertext: e.auditCiphertext,
    typedData: {
      types: {
        EIP712Domain: parseTypes(EIP712_DOMAIN_TYPE),
        ApplicationAuthorization: parseTypes(AUTH_TYPE),
      },
      primaryType: "ApplicationAuthorization",
      domain: {
        name: POOL_DOMAIN_NAME,
        version: POOL_DOMAIN_VERSION,
        chainId: 43113,
        verifyingContract: input.pool,
      },
      message: authorization,
    },
  };
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

export function encodeBrowserSwapAndShield(input: {
  router: string;
  plan: ReturnType<typeof planBrowserFujiSpend>;
  signature: string;
  route: { adapter: string; data: string; expectedRouteHash: string };
}) {
  if (!input.router || !input.route || !input.route.adapter || !input.route.data || !input.route.expectedRouteHash) {
    throw new Error("ENCODING_INVALID");
  }
  const spendChunks = [
    input.signature,
    input.plan.proof,
    input.plan.recipientCiphertext0,
    input.plan.recipientCiphertext1,
    input.plan.auditCiphertext,
  ].map(dynamicBytes);
  let spendOffset = (25 + 13 + 5) * 32;
  const spendOffsets = spendChunks.map((chunk) => {
    const word = uintWord(spendOffset);
    spendOffset += chunk.length;
    return word;
  });
  const transactArgsTuple = concatBytes(
    encodeIntent(input.plan.intent),
    encodeAuthorization(input.plan.authorization),
    ...spendOffsets,
    ...spendChunks,
  );

  const routeDataChunk = dynamicBytes(input.route.data);
  const routeDataOffset = uintWord(3 * 32);
  const swapRouteTuple = concatBytes(
    addressWord(input.route.adapter),
    routeDataOffset,
    bytes32Word(input.route.expectedRouteHash),
    routeDataChunk,
  );

  const headOffsetArgs = uintWord(64);
  const headOffsetRoute = uintWord(64 + transactArgsTuple.length);

  const selector = ROUTER_SELECTORS.swapAndShield;

  const payload = concatBytes(
    hexToBuf(selector),
    headOffsetArgs,
    headOffsetRoute,
    transactArgsTuple,
    swapRouteTuple,
  );

  return {
    to: input.router,
    data: toHex(payload),
  };
}

export function swapRouteHash(adapter: string, data: string): string {
  if (!adapter || !data || !/^0x[0-9a-f]{40}$/i.test(adapter) || !/^0x(?:[0-9a-f]{2})*$/i.test(data)) {
    throw new Error("ENCODING_INVALID");
  }
  const payload = concatBytes(addressWord(adapter), uintWord(64), dynamicBytes(data));
  return toHex(keccak256(payload));
}

export function encodeEmergencyExitRequest(emergencyContract: string, requestId: string) {
  if (!emergencyContract || !requestId || !/^0x[0-9a-f]{64}$/i.test(requestId) || requestId === ZERO) {
    throw new Error("ENCODING_INVALID");
  }
  const selector = functionSelector("requestEmergencyExit(bytes32)");
  return {
    to: emergencyContract,
    data: toHex(concatBytes(hexToBuf(selector), bytes32Word(requestId))),
  };
}

export type EmergencyExecuteArgs = {
  applicationId: string;
  noteTreeRoot: string;
  hazePolicyVersion: number | bigint;
  hazeBlocklistRoot: string;
  nullifier: string;
  publicAmount: number | bigint;
  recipient: string;
  requester: string;
  requestSalt: string;
  auditDataCommitment: string;
  auditCiphertextHash: string;
  auditCiphertext: string;
  proof: string;
};

export function encodeEmergencyExitExecute(emergencyContract: string, args: EmergencyExecuteArgs) {
  if (
    !emergencyContract
    || !args.recipient
    || !args.nullifier
    || !args.publicAmount
    || !args.auditCiphertext
    || !args.proof
  ) {
    throw new Error("ENCODING_INVALID");
  }
  const staticWords = [
    bytes32Word(args.applicationId),
    bytes32Word(args.noteTreeRoot),
    uintWord(args.hazePolicyVersion),
    bytes32Word(args.hazeBlocklistRoot),
    bytes32Word(args.nullifier),
    uintWord(args.publicAmount),
    addressWord(args.recipient),
    addressWord(args.requester),
    bytes32Word(args.requestSalt),
    bytes32Word(args.auditDataCommitment),
    bytes32Word(args.auditCiphertextHash),
  ];
  const dynamicAudit = dynamicBytes(args.auditCiphertext);
  const dynamicProof = dynamicBytes(args.proof);

  let offset = (11 + 2) * 32;
  const auditOffset = uintWord(offset);
  offset += dynamicAudit.length;
  const proofOffset = uintWord(offset);

  const tuple = concatBytes(
    encodeWords(staticWords),
    auditOffset,
    proofOffset,
    dynamicAudit,
    dynamicProof,
  );

  const selector = functionSelector(
    "executeEmergencyExit((bytes32,uint256,uint64,uint256,uint256,uint64,address,address,bytes32,uint256,bytes32,bytes,bytes))",
  );

  return {
    to: emergencyContract,
    data: toHex(concatBytes(hexToBuf(selector), uintWord(32), tuple)),
  };
}
