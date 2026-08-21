import { AUTH_TYPE, EIP712_DOMAIN_TYPE, intentStructHash } from "../../../../sdk/typescript/src/eip712.ts";
import type { ApplicationAuthorizationFields, HazeIntentFields } from "../../../../sdk/typescript/src/eip712.ts";
import { POOL_SELECTORS } from "../../../../sdk/typescript/src/bindings.ts";
import { POOL_DOMAIN_NAME, POOL_DOMAIN_VERSION, PoolAction } from "../../../../sdk/typescript/src/pool.ts";
import { encodeTransactCall, type LiveOverlay, type LiveShieldPlan } from "./live-deposit.ts";
import { liveOperatorWithdrawAllowed } from "./site.ts";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const ZERO_BYTES32 = `0x${"00".repeat(32)}`;

export type LiveWithdrawWitness = {
  actionReference: string;
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

export function planLiveOperatorWithdraw(input: {
  path: string;
  live: boolean;
  operatorProve: boolean;
  zkeyExists: boolean;
  sidecar: LiveOverlay;
  user: string;
  amount: number;
  recipient: string;
  now: number;
  witness: LiveWithdrawWitness;
  productionCeremonyApproved?: boolean;
  writeCommittedFuji?: boolean;
}): LiveShieldPlan {
  if (
    !liveOperatorWithdrawAllowed({
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
    action: PoolAction.Withdraw,
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
    publicRecipient: input.recipient,
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
    nonce: input.witness.actionReference,
    validAfter: input.now - 1,
    validUntil: input.now + 3600,
  };

  return {
    allowed: true,
    chainId: input.sidecar.chainId,
    usdc: input.sidecar.usdc,
    pool,
    amount: Number(circom.publicAmount),
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

export function encodeLiveWithdraw(input: { plan: LiveShieldPlan; signature: string }) {
  return encodeTransactCall({ ...input, selector: POOL_SELECTORS.transact });
}
