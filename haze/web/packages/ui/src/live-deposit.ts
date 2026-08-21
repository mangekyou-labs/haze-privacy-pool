import {
  addressWord,
  bytes32Word,
  encodeWords,
  functionSelector,
  hexToBuf,
  keccakHex,
  toHex,
  uintWord,
} from "../../../../sdk/typescript/src/abi.ts";
import { AUTH_TYPE, EIP712_DOMAIN_TYPE, intentDigest, intentStructHash } from "../../../../sdk/typescript/src/eip712.ts";
import type { ApplicationAuthorizationFields, HazeIntentFields } from "../../../../sdk/typescript/src/eip712.ts";
import { POOL_DOMAIN_NAME, POOL_DOMAIN_VERSION, PoolAction } from "../../../../sdk/typescript/src/pool.ts";
import { developmentProofDigest } from "../../../../sdk/typescript/src/prover-session.ts";
import { POOL_SELECTORS } from "../../../../sdk/typescript/src/bindings.ts";
import { liveDepositAllowed, liveOperatorShieldAllowed } from "./site.ts";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const ZERO_BYTES32 = `0x${"00".repeat(32)}`;
const PROTOCOL_VERSION_TAG = "0x2afe8a5679df289719eae23ad89b300434b9dfbb8194dad0b50dee97f91a3868";
const SNARK_SCALAR_FIELD = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;
const LIMB_MASK = (1n << 128n) - 1n;

export type LiveOverlay = {
  chainId: number;
  usdc: string;
  broadcast: boolean;
  applicationId: string;
  poolVersion: string;
  live_rpc?: string;
  addresses: {
    HazePool: string;
    ApplicationRegistry?: string;
    PolicyRegistry?: string;
  };
};

export type LiveSnapshot = {
  membershipVersion: number;
  membershipRoot: string;
  hazePolicyVersion: number;
  hazeBlocklistRoot: string;
};

export type LiveShieldPlan = {
  allowed: boolean;
  reason?: string;
  chainId?: number;
  usdc?: string;
  pool?: string;
  amount?: number;
  approve?: { to: string; data: string };
  typedData?: {
    types: Record<string, { name: string; type: string }[]>;
    primaryType: "ApplicationAuthorization";
    domain: { name: string; version: string; chainId: number; verifyingContract: string };
    message: ApplicationAuthorizationFields;
  };
  intent?: HazeIntentFields;
  authorization?: ApplicationAuthorizationFields;
  recipientCiphertext0?: string;
  recipientCiphertext1?: string;
  auditCiphertext?: string;
  proof?: string;
  operatorHatch?: boolean;
};

export type LiveCircuitWitness = {
  circom: {
    noteTreeRoot: string;
    applicationPolicyVersion: string;
    hazePolicyVersion: string;
    applicationMembershipRoot: string;
    hazeBlocklistRoot: string;
    inputNullifier0: string;
    inputNullifier1: string;
    outputCommitment0: string;
    outputCommitment1: string;
    publicAmount: string;
    auditDataCommitment: string;
  };
  envelopes: {
    recipientCiphertext0: string;
    recipientCiphertext1: string;
    auditCiphertext: string;
    recipientCiphertextHash0: string;
    recipientCiphertextHash1: string;
    auditCiphertextHash: string;
  };
};

function asBytes32(value: string) {
  if (value.startsWith("0x") && value.length === 66) {
    return value.toLowerCase();
  }
  return `0x${BigInt(value).toString(16).padStart(64, "0")}`;
}

function encodeBytes(hex: string) {
  const raw = hexToBuf(hex === "0x" ? "0x" : hex);
  const padded = Buffer.alloc(Math.ceil(raw.length / 32) * 32);
  raw.copy(padded);
  return Buffer.concat([uintWord(raw.length), padded]);
}

export function snapshotFromChainReturns(appReturn: string, versionReturn: string, rootReturn: string): LiveSnapshot {
  const words = appReturn.replace(/^0x/i, "").match(/.{64}/g) ?? [];
  const start = BigInt(`0x${words[0] ?? "0"}`) === 32n ? 1 : 0;
  return {
    membershipRoot: asBytes32(`0x${words[start + 4] ?? ""}`),
    membershipVersion: Number(BigInt(`0x${words[start + 5] ?? "0"}`)),
    hazePolicyVersion: Number(BigInt(versionReturn)),
    hazeBlocklistRoot: asBytes32(rootReturn),
  };
}

export async function fetchLiveSnapshot(sidecar: LiveOverlay): Promise<LiveSnapshot> {
  const rpc = sidecar.live_rpc;
  const applicationRegistry = sidecar.addresses.ApplicationRegistry;
  const policyRegistry = sidecar.addresses.PolicyRegistry;
  if (!rpc || !applicationRegistry || !policyRegistry) {
    throw new Error("SNAPSHOT_MISSING");
  }
  async function ethCall(to: string, data: string) {
    const response = await fetch(rpc, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "eth_call",
        params: [{ to, data }, "latest"],
      }),
    });
    const json = (await response.json()) as { result?: string };
    if (!json.result || json.result === "0x") {
      throw new Error("SNAPSHOT_MISSING");
    }
    return json.result;
  }
  const appData = `${functionSelector("getApplication(bytes32)")}${asBytes32(sidecar.applicationId).slice(2)}`;
  const [appReturn, versionReturn, rootReturn] = await Promise.all([
    ethCall(applicationRegistry, appData),
    ethCall(policyRegistry, functionSelector("activeVersion()")),
    ethCall(policyRegistry, functionSelector("activeRoot()")),
  ]);
  return snapshotFromChainReturns(appReturn, versionReturn, rootReturn);
}

export function encodeErc20BalanceOf(holder: string): string {
  return `${functionSelector("balanceOf(address)")}${toHex(addressWord(holder)).slice(2)}`;
}

export function decodeErc20Balance(result: string): bigint {
  if (!result || result === "0x") {
    return 0n;
  }
  return BigInt(result);
}

export function formatUsdc(amount: bigint | number | string, decimals = 6): string {
  const n = typeof amount === "bigint" ? amount : BigInt(amount);
  const scale = 10n ** BigInt(decimals);
  const whole = n / scale;
  const frac = n % scale;
  const fracStr = frac.toString().padStart(decimals, "0").replace(/0+$/, "");
  const shown = fracStr.length === 0 ? "00" : fracStr.padEnd(2, "0");
  return `${whole}.${shown}`;
}

export async function fetchLiveErc20Balance(sidecar: LiveOverlay, holder: string) {
  const rpc = sidecar.live_rpc;
  if (!rpc || !sidecar.usdc) {
    throw new Error("SNAPSHOT_MISSING");
  }
  const response = await fetch(rpc, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "eth_call",
      params: [{ to: sidecar.usdc, data: encodeErc20BalanceOf(holder) }, "latest"],
    }),
  });
  const json = (await response.json()) as { result?: string };
  const raw = decodeErc20Balance(json.result ?? "0x0");
  return { raw, formatted: formatUsdc(raw) };
}

async function fetchLivePoolCall(sidecar: LiveOverlay, data: string) {
  const rpc = sidecar.live_rpc;
  const pool = sidecar.addresses.HazePool;
  if (!rpc || !pool) {
    throw new Error("SNAPSHOT_MISSING");
  }
  const response = await fetch(rpc, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "eth_call",
      params: [{ to: pool, data }, "latest"],
    }),
  });
  const json = (await response.json()) as { result?: string };
  if (!json.result || json.result === "0x") {
    throw new Error("SNAPSHOT_MISSING");
  }
  return json.result;
}

export async function fetchLivePoolNextIndex(sidecar: LiveOverlay): Promise<number> {
  const result = await fetchLivePoolCall(sidecar, functionSelector("nextIndex()"));
  const nextIndex = BigInt(result);
  if (nextIndex > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("SNAPSHOT_MISSING");
  }
  return Number(nextIndex);
}

export async function fetchLivePoolCommitmentExists(sidecar: LiveOverlay, commitment: string): Promise<boolean> {
  const data = `${functionSelector("commitmentExists(uint256)")}${toHex(uintWord(BigInt(commitment))).slice(2)}`;
  const result = await fetchLivePoolCall(sidecar, data);
  return BigInt(result) !== 0n;
}

function splitLimbs(value: string) {
  const n = BigInt(asBytes32(value));
  return { hi: n >> 128n, lo: n & LIMB_MASK };
}

export function publicInputsForIntent(intent: HazeIntentFields, chainId: number) {
  const digest = intentDigest(intent, chainId);
  const pool = splitLimbs(intent.poolVersion);
  const app = splitLimbs(intent.applicationId);
  const intentLimbs = splitLimbs(digest);
  const c0 = splitLimbs(intent.recipientCiphertextHash0);
  const c1 = splitLimbs(intent.recipientCiphertextHash1);
  const audit = splitLimbs(intent.auditCiphertextHash);
  return [
    PROTOCOL_VERSION_TAG,
    String(chainId),
    intent.pool,
    `0x${pool.hi.toString(16)}`,
    `0x${pool.lo.toString(16)}`,
    `0x${app.hi.toString(16)}`,
    `0x${app.lo.toString(16)}`,
    intent.noteTreeRoot,
    String(intent.applicationPolicyVersion),
    String(intent.hazePolicyVersion),
    intent.applicationMembershipRoot,
    intent.hazeBlocklistRoot,
    intent.inputNullifier0,
    intent.inputNullifier1,
    intent.outputCommitment0,
    intent.outputCommitment1,
    String(intent.action),
    String(intent.publicAmount),
    intent.publicRecipient,
    intent.user,
    `0x${intentLimbs.hi.toString(16)}`,
    `0x${intentLimbs.lo.toString(16)}`,
    `0x${c0.hi.toString(16)}`,
    `0x${c0.lo.toString(16)}`,
    `0x${c1.hi.toString(16)}`,
    `0x${c1.lo.toString(16)}`,
    intent.auditDataCommitment,
    `0x${audit.hi.toString(16)}`,
    `0x${audit.lo.toString(16)}`,
  ];
}

function encodeIntent(intent: HazeIntentFields) {
  return encodeWords([
    bytes32Word(intent.applicationId),
    addressWord(intent.user),
    addressWord(intent.pool),
    bytes32Word(intent.poolVersion),
    uintWord(intent.action),
    bytes32Word(intent.noteTreeRoot),
    uintWord(intent.applicationPolicyVersion),
    uintWord(intent.hazePolicyVersion),
    bytes32Word(intent.applicationMembershipRoot),
    bytes32Word(intent.hazeBlocklistRoot),
    bytes32Word(intent.inputNullifier0),
    bytes32Word(intent.inputNullifier1),
    bytes32Word(intent.outputCommitment0),
    bytes32Word(intent.outputCommitment1),
    uintWord(intent.publicAmount),
    addressWord(intent.publicRecipient),
    bytes32Word(intent.recipientCiphertextHash0),
    bytes32Word(intent.recipientCiphertextHash1),
    bytes32Word(intent.auditDataCommitment),
    bytes32Word(intent.auditCiphertextHash),
    addressWord(intent.tokenIn),
    bytes32Word(intent.amountIn),
    uintWord(intent.minUsdcOut),
    bytes32Word(intent.routeHash),
    uintWord(intent.deadline),
  ]);
}

function encodeApprove(pool: string, amount: number) {
  return toHex(
    Buffer.concat([
      hexToBuf(functionSelector("approve(address,uint256)")),
      addressWord(pool),
      uintWord(amount),
    ]),
  );
}

function eip712Types() {
  return {
    EIP712Domain: EIP712_DOMAIN_TYPE.slice(EIP712_DOMAIN_TYPE.indexOf("(") + 1, -1)
      .split(",")
      .map((part) => {
        const match = part.trim().match(/^(string|uint256|address)\s+(.+)$/);
        return { type: match?.[1] ?? "", name: match?.[2] ?? "" };
      }),
    ApplicationAuthorization: AUTH_TYPE.slice(AUTH_TYPE.indexOf("(") + 1, -1)
      .split(",")
      .map((part) => {
        const match = part.trim().match(/^(bytes32|address|uint8|uint64|uint48|uint256)\s+(.+)$/);
        return { type: match?.[1] ?? "", name: match?.[2] ?? "" };
      }),
  };
}

function encodeAuthorization(auth: ApplicationAuthorizationFields) {
  return encodeWords([
    bytes32Word(auth.applicationId),
    addressWord(auth.user),
    addressWord(auth.pool),
    bytes32Word(auth.poolVersion),
    uintWord(auth.action),
    bytes32Word(auth.intentHash),
    uintWord(auth.applicationPolicyVersion),
    uintWord(auth.hazePolicyVersion),
    bytes32Word(auth.auditDataCommitment),
    bytes32Word(auth.auditCiphertextHash),
    bytes32Word(auth.nonce),
    uintWord(auth.validAfter),
    uintWord(auth.validUntil),
  ]);
}

export function planLiveShieldDeposit(input: {
  path: string;
  live: boolean;
  sidecar: LiveOverlay;
  user: string;
  amount: number;
  now: number;
  snapshot: LiveSnapshot;
}): LiveShieldPlan {
  if (!liveDepositAllowed({
    path: input.path,
    live: input.live,
    sidecarBroadcast: input.sidecar.broadcast === true,
  })) {
    return { allowed: false, reason: "LIVE_DEPOSIT_DENIED" };
  }

  const pool = input.sidecar.addresses.HazePool;
  const recipientCiphertext0 = "0xc0";
  const recipientCiphertext1 = "0x";
  const auditCiphertext = "0xaa";
  const commitmentSeed = keccakHex(
    Buffer.concat([
      Buffer.from("haze-fuji-live-deposit"),
      hexToBuf(input.user),
      uintWord(input.amount),
      uintWord(input.now),
    ]),
  );
  const outputCommitment0 = asBytes32(
    `0x${(BigInt(commitmentSeed) % SNARK_SCALAR_FIELD).toString(16).padStart(64, "0")}`,
  );

  const intent: HazeIntentFields = {
    applicationId: input.sidecar.applicationId,
    user: input.user,
    pool,
    poolVersion: input.sidecar.poolVersion,
    action: PoolAction.Deposit,
    noteTreeRoot: ZERO_BYTES32,
    applicationPolicyVersion: input.snapshot.membershipVersion,
    hazePolicyVersion: input.snapshot.hazePolicyVersion,
    applicationMembershipRoot: asBytes32(input.snapshot.membershipRoot),
    hazeBlocklistRoot: asBytes32(input.snapshot.hazeBlocklistRoot),
    inputNullifier0: ZERO_BYTES32,
    inputNullifier1: ZERO_BYTES32,
    outputCommitment0,
    outputCommitment1: ZERO_BYTES32,
    publicAmount: input.amount,
    publicRecipient: ZERO_ADDRESS,
    recipientCiphertextHash0: keccakHex(hexToBuf(recipientCiphertext0)),
    recipientCiphertextHash1: keccakHex(hexToBuf(recipientCiphertext1)),
    auditDataCommitment: asBytes32("0xad"),
    auditCiphertextHash: keccakHex(hexToBuf(auditCiphertext)),
    tokenIn: ZERO_ADDRESS,
    amountIn: ZERO_BYTES32,
    minUsdcOut: 0,
    routeHash: ZERO_BYTES32,
    deadline: 0,
  };

  const authorization: ApplicationAuthorizationFields = {
    applicationId: intent.applicationId,
    user: intent.user,
    pool: intent.pool,
    poolVersion: intent.poolVersion,
    action: intent.action,
    intentHash: intentStructHash(intent),
    applicationPolicyVersion: intent.applicationPolicyVersion,
    hazePolicyVersion: intent.hazePolicyVersion,
    auditDataCommitment: intent.auditDataCommitment,
    auditCiphertextHash: intent.auditCiphertextHash,
    nonce: keccakHex(
      Buffer.concat([Buffer.from("haze-fuji-live-nonce"), hexToBuf(input.user), uintWord(input.now)]),
    ),
    validAfter: input.now - 1,
    validUntil: input.now + 3600,
  };

  const proof = developmentProofDigest(publicInputsForIntent(intent, input.sidecar.chainId));
  const approveData = encodeApprove(pool, input.amount);

  return {
    allowed: true,
    chainId: input.sidecar.chainId,
    usdc: input.sidecar.usdc,
    pool,
    amount: input.amount,
    approve: { to: input.sidecar.usdc, data: approveData },
    typedData: {
      types: eip712Types(),
      primaryType: "ApplicationAuthorization",
      domain: {
        name: POOL_DOMAIN_NAME,
        version: POOL_DOMAIN_VERSION,
        chainId: input.sidecar.chainId,
        verifyingContract: pool,
      },
      message: authorization,
    },
    intent,
    authorization,
    recipientCiphertext0,
    recipientCiphertext1,
    auditCiphertext,
    proof,
  };
}

export function planLiveOperatorShield(input: {
  path: string;
  live: boolean;
  operatorProve: boolean;
  zkeyExists: boolean;
  sidecar: LiveOverlay;
  user: string;
  amount: number;
  now: number;
  witness: LiveCircuitWitness;
  productionCeremonyApproved?: boolean;
  writeCommittedFuji?: boolean;
}): LiveShieldPlan {
  if (
    !liveOperatorShieldAllowed({
      path: input.path,
      live: input.live,
      operatorProve: input.operatorProve,
      zkeyExists: input.zkeyExists,
      productionCeremonyApproved: input.productionCeremonyApproved,
      writeCommittedFuji: input.writeCommittedFuji,
    })
  ) {
    return { allowed: false, reason: "KEYS_MISSING" };
  }

  const pool = input.sidecar.addresses.HazePool;
  const circom = input.witness.circom;
  const envelopes = input.witness.envelopes;
  const intent: HazeIntentFields = {
    applicationId: input.sidecar.applicationId,
    user: input.user,
    pool,
    poolVersion: input.sidecar.poolVersion,
    action: PoolAction.Deposit,
    noteTreeRoot: circom.noteTreeRoot,
    applicationPolicyVersion: Number(circom.applicationPolicyVersion),
    hazePolicyVersion: Number(circom.hazePolicyVersion),
    applicationMembershipRoot: circom.applicationMembershipRoot,
    hazeBlocklistRoot: circom.hazeBlocklistRoot,
    inputNullifier0: circom.inputNullifier0,
    inputNullifier1: circom.inputNullifier1,
    outputCommitment0: circom.outputCommitment0,
    outputCommitment1: circom.outputCommitment1,
    publicAmount: Number(circom.publicAmount),
    publicRecipient: ZERO_ADDRESS,
    recipientCiphertextHash0: envelopes.recipientCiphertextHash0,
    recipientCiphertextHash1: envelopes.recipientCiphertextHash1,
    auditDataCommitment: circom.auditDataCommitment,
    auditCiphertextHash: envelopes.auditCiphertextHash,
    tokenIn: ZERO_ADDRESS,
    amountIn: ZERO_BYTES32,
    minUsdcOut: 0,
    routeHash: ZERO_BYTES32,
    deadline: 0,
  };

  const authorization: ApplicationAuthorizationFields = {
    applicationId: intent.applicationId,
    user: intent.user,
    pool: intent.pool,
    poolVersion: intent.poolVersion,
    action: intent.action,
    intentHash: intentStructHash(intent),
    applicationPolicyVersion: intent.applicationPolicyVersion,
    hazePolicyVersion: intent.hazePolicyVersion,
    auditDataCommitment: intent.auditDataCommitment,
    auditCiphertextHash: intent.auditCiphertextHash,
    nonce: keccakHex(
      Buffer.concat([
        Buffer.from("haze-fuji-poseidon-deposit"),
        hexToBuf(input.user),
        uintWord(input.now),
      ]),
    ),
    validAfter: input.now - 1,
    validUntil: input.now + 3600,
  };

  return {
    allowed: true,
    operatorHatch: true,
    chainId: input.sidecar.chainId,
    usdc: input.sidecar.usdc,
    pool,
    amount: Number(circom.publicAmount),
    approve: { to: input.sidecar.usdc, data: encodeApprove(pool, Number(circom.publicAmount)) },
    typedData: {
      types: eip712Types(),
      primaryType: "ApplicationAuthorization",
      domain: {
        name: POOL_DOMAIN_NAME,
        version: POOL_DOMAIN_VERSION,
        chainId: input.sidecar.chainId,
        verifyingContract: pool,
      },
      message: authorization,
    },
    intent,
    authorization,
    recipientCiphertext0: envelopes.recipientCiphertext0,
    recipientCiphertext1: envelopes.recipientCiphertext1,
    auditCiphertext: envelopes.auditCiphertext,
    proof: "0x",
  };
}

export function encodeTransactCall(input: {
  plan: LiveShieldPlan;
  signature: string;
  selector: string;
}) {
  const plan = input.plan;
  if (!plan.allowed || !plan.intent || !plan.authorization || !plan.pool) {
    throw new Error("LIVE_DEPOSIT_DENIED");
  }
  const intent = encodeIntent(plan.intent);
  const auth = encodeAuthorization(plan.authorization);
  const sig = encodeBytes(input.signature);
  const proof = encodeBytes(plan.proof ?? "0x");
  const c0 = encodeBytes(plan.recipientCiphertext0 ?? "0x");
  const c1 = encodeBytes(plan.recipientCiphertext1 ?? "0x");
  const audit = encodeBytes(plan.auditCiphertext ?? "0x");
  const headWords = 25 + 13 + 5;
  const headSize = headWords * 32;
  let offset = headSize;
  const offsets = [sig, proof, c0, c1, audit].map((chunk) => {
    const current = offset;
    offset += chunk.length;
    return uintWord(current);
  });
  const tuple = Buffer.concat([intent, auth, ...offsets, sig, proof, c0, c1, audit]);
  const payload = Buffer.concat([uintWord(32), tuple]);
  return { to: plan.pool, data: toHex(Buffer.concat([hexToBuf(input.selector), payload])) };
}

export function encodeLiveDeposit(input: { plan: LiveShieldPlan; signature: string }) {
  return encodeTransactCall({ ...input, selector: POOL_SELECTORS.deposit });
}
