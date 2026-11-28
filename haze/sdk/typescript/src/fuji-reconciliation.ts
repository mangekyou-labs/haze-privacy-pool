import { keccak_256 } from "@noble/hashes/sha3";
import { concatBytes, hexToBuf } from "./abi.ts";
import { decodeBrowserEnvelope, deriveBrowserX25519PublicKey, openBrowserHpke, parseBrowserRecipientPlaintext } from "./browser-crypto.ts";
import { u64be } from "./field.ts";
import { encryptionKeyHash, noteCommitment, nullifier } from "./note.ts";

const PRIVATE_TRANSACTION_SIGNATURE = "PrivateTransaction(bytes32,uint8,address,uint64,uint64,uint256,uint256,uint256,uint256,uint256,uint64,address,bytes32,bytes32,uint256,bytes32,bytes,bytes,bytes)";

function toHex(bytes: Uint8Array): string {
  return `0x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

export const PRIVATE_TRANSACTION_TOPIC = toHex(keccak_256(new TextEncoder().encode(PRIVATE_TRANSACTION_SIGNATURE)));

export type FujiRpc = (method: string, params: unknown[]) => Promise<unknown>;
export type FujiLog = {
  address: string;
  topics: string[];
  data: string;
  blockNumber?: string | number;
  blockHash?: string;
  transactionHash?: string;
  transactionIndex?: string | number;
  logIndex?: string | number;
};
export type FujiReceipt = {
  status?: string;
  transactionHash?: string;
  transactionIndex?: string | number;
  blockNumber?: string | number;
  blockHash?: string;
  logs?: FujiLog[];
};

export type FinalityProvenance = {
  inclusionBlock: number;
  confirmationCount: number;
  canonicalBlockHash?: string;
  verifiedAtBlock?: number;
};

import type { BrowserOperationKind } from "./browser-operation-vault.ts";

export type FujiAction = 1 | 2 | 3 | 4;

export const FUJI_ACTIONS = {
  SHIELD: 1 as FujiAction,
  SEND: 2 as FujiAction,
  WITHDRAW: 3 as FujiAction,
  SWAP: 4 as FujiAction,
} as const;

export function fujiActionToKind(action: FujiAction): BrowserOperationKind {
  switch (action) {
    case 1:
      return "deposit";
    case 2:
      return "private_send";
    case 3:
      return "withdrawal";
    case 4:
      return "swap";
  }
}

export function kindToFujiAction(kind: BrowserOperationKind): FujiAction {
  switch (kind) {
    case "deposit":
      return 1;
    case "private_send":
    case "transfer":
      return 2;
    case "withdrawal":
      return 3;
    case "swap":
      return 4;
    default:
      return 1;
  }
}

export type DecodedPrivateTransaction = {
  pool: string;
  applicationId: string;
  action: number;
  user: string;
  applicationPolicyVersion: bigint;
  hazePolicyVersion: bigint;
  noteTreeRoot: string;
  inputNullifier0: string;
  inputNullifier1: string;
  outputCommitment0: string;
  outputCommitment1: string;
  publicAmount: bigint;
  publicRecipient: string;
  auditDataCommitment: string;
  auditCiphertextHash: string;
};

export type FujiTransactionEvidence = {
  action: FujiAction;
  wallet: string;
  deploymentId?: string;
  sourceSha?: string;
  candidateGitSha?: string;
  phase: "preflight" | "broadcast" | "mined" | "event_validated" | "finalized" | "failed";
  transactionHash: string;
  receipt?: FujiReceipt;
  decodedEvent?: DecodedPrivateTransaction;
  assetTransfers?: {
    token: string;
    from: string;
    to: string;
    amount: string;
  }[];
  blockNumber?: number;
  blockHash?: string;
  confirmationCount: number;
  screenshots?: string[];
  cliSession?: string;
  failureReason?: string;
  verifiedAtBlock?: number;
  canonicalBlockHash?: string;
};

export type FujiAttemptRecord = {
  id: string;
  timestamp: number;
  action: FujiAction;
  wallet: string;
  expectedPool: string;
  expectedApplicationId: string;
  phase: "preflight" | "broadcast" | "mined" | "event_validated" | "finalized" | "failed";
  transactionHash?: string;
  receiptStatus?: number;
  blockNumber?: number;
  confirmations?: number;
  error?: string;
  failureStage?: string;
};

export type FujiMvpAcceptanceManifestV2 = {
  schema: "haze-fuji-mvp-acceptance-v2";
  runId: string;
  timestamp: string;
  origin: string;
  chainId: number;
  pool: string;
  poolVersion: string;
  applicationId: string;
  status: "PASS" | "FAIL";
  candidateGitSha: string;
  vercelDeploymentId?: string;
  deployment?: {
    sourceSha: string;
    clean: boolean;
    ready: boolean;
    sourceShaVerified: boolean;
  };
  namedCliSession: string;
  tools: {
    dappwright: boolean;
    playwrightCli: boolean;
  };
  accounts: {
    accountA: { address: string; hazeAddress?: string };
    accountB: { address: string; hazeAddress?: string };
  };
  operations: {
    shield?: FujiTransactionEvidence;
    send?: FujiTransactionEvidence;
    withdraw?: FujiTransactionEvidence;
    swap?: FujiTransactionEvidence;
  };
  attempts: FujiAttemptRecord[];
  auditorCase?: {
    caseId: string;
    withdrawalHash: string;
    disclosedActionReference: string;
    verifiedJws: boolean;
    exportHash: string;
  };
  faucet?: {
    enabled: boolean;
    mintHash?: string;
    venueLiquidityUsdc?: string;
  };
  historyReconciliation?: {
    recoveredOnReload: boolean;
    spendableNoteCount: number;
  };
  screenshots: Record<string, string>;
};

export type FujiOperationBinding = {
  chainId: number;
  pool: string;
  poolVersion: string;
  applicationId: string;
  user: string;
  action: FujiAction | number;
  commitment?: string;
  nullifier?: string;
  kind?: BrowserOperationKind;
  destination?: string;
  transactionHash?: string;
};

function normalizedWord(value: string): string {
  const hex = value.toLowerCase().replace(/^0x/, "");
  return `0x${hex.padStart(64, "0")}`;
}

function dataWords(data: string): string[] {
  const hex = data.replace(/^0x/, "");
  if (hex.length < 13 * 64 || hex.length % 64 !== 0) return [];
  return hex.match(/.{64}/g)?.map((word) => `0x${word.toLowerCase()}`) ?? [];
}

export function decodePrivateTransaction(log: FujiLog): DecodedPrivateTransaction | undefined {
  if (log.topics.length < 4 || log.topics[0].toLowerCase() !== PRIVATE_TRANSACTION_TOPIC) return undefined;
  const words = dataWords(log.data);
  if (words.length < 13) return undefined;
  return {
    pool: log.address.toLowerCase(),
    applicationId: normalizedWord(log.topics[1]),
    action: Number(BigInt(log.topics[2])),
    user: `0x${log.topics[3].slice(-40).toLowerCase()}`,
    applicationPolicyVersion: BigInt(words[0]),
    hazePolicyVersion: BigInt(words[1]),
    noteTreeRoot: words[2],
    inputNullifier0: words[3],
    inputNullifier1: words[4],
    outputCommitment0: words[5],
    outputCommitment1: words[6],
    publicAmount: BigInt(words[7]),
    publicRecipient: `0x${words[8].slice(-40)}`,
    auditDataCommitment: words[11],
    auditCiphertextHash: words[12],
  };
}

function matches(event: DecodedPrivateTransaction | undefined, binding: FujiOperationBinding): boolean {
  if (!event) return false;
  if (event.pool !== binding.pool.toLowerCase()
    || event.applicationId !== normalizedWord(binding.applicationId)
    || event.user !== binding.user.toLowerCase()
    || event.action !== binding.action) return false;
  if (binding.commitment && event.outputCommitment0 !== normalizedWord(binding.commitment)
    && event.outputCommitment1 !== normalizedWord(binding.commitment)) return false;
  if (binding.nullifier && event.inputNullifier0 !== normalizedWord(binding.nullifier)
    && event.inputNullifier1 !== normalizedWord(binding.nullifier)) return false;
  return true;
}

export function reconcileFujiOperation(input: FujiOperationBinding & {
  receipt?: FujiReceipt;
  headBlockNumber?: number | bigint;
  canonicalBlockHash?: string;
  refetchedReceipt?: FujiReceipt;
}) {
  const action = typeof input.action === "number" ? input.action : (input.kind === "withdrawal" ? 3 : (input.kind === "private_send" || input.kind === "transfer" ? 2 : (input.kind === "swap" ? 4 : 1)));
  const isSpendSpendableBeforeConfirm = action === 2 || action === 3 || input.kind === "withdrawal" || input.kind === "private_send" || input.kind === "transfer";
  const base = {
    noteSpendable: isSpendSpendableBeforeConfirm,
    disclosureState: "not_requested" as const,
    bindings: { chainId: input.chainId, pool: input.pool, poolVersion: input.poolVersion, applicationId: input.applicationId, action, destination: input.destination },
  };
  if (!input.receipt) return { ...base, confirmed: false, status: "failed" as const, reason: "RECEIPT_MISSING" as const };
  if (input.receipt.status !== "0x1") return { ...base, confirmed: false, status: "failed" as const, reason: "RECEIPT_REVERTED" as const };
  const decoded = (input.receipt.logs ?? []).map(decodePrivateTransaction).filter(Boolean) as DecodedPrivateTransaction[];
  if (decoded.length === 0) return { ...base, confirmed: false, status: "failed" as const, reason: "EVENT_MISSING" as const };
  const event = decoded.find((candidate) => matches(candidate, input));
  if (!event) return { ...base, confirmed: false, status: "failed" as const, reason: "EVENT_MISMATCH" as const };
  const inclusionBlock = input.receipt.blockNumber !== undefined ? BigInt(input.receipt.blockNumber) : undefined;
  const headBlock = input.headBlockNumber !== undefined ? BigInt(input.headBlockNumber) : undefined;

  if (inclusionBlock !== undefined && headBlock !== undefined) {
    const confirmations = headBlock >= inclusionBlock ? Number(headBlock - inclusionBlock + 1n) : 0;
    if (confirmations < 12) {
      return {
        ...base,
        confirmed: false,
        status: "pending_finality" as const,
        confirmations,
        reason: "AWAITING_CONFIRMATIONS" as const,
        event,
      };
    }
    if (input.canonicalBlockHash && input.receipt.blockHash) {
      if (input.canonicalBlockHash.toLowerCase() !== input.receipt.blockHash.toLowerCase()) {
        return {
          ...base,
          confirmed: false,
          status: "failed" as const,
          confirmations,
          reason: "BLOCK_HASH_MISMATCH" as const,
          event,
        };
      }
    }
    if (input.refetchedReceipt) {
      const refetched = input.refetchedReceipt;
      if (
        refetched.status !== "0x1"
        || (input.receipt.blockHash && refetched.blockHash && refetched.blockHash.toLowerCase() !== input.receipt.blockHash.toLowerCase())
        || (input.receipt.transactionHash && refetched.transactionHash && refetched.transactionHash.toLowerCase() !== input.receipt.transactionHash.toLowerCase())
      ) {
        return {
          ...base,
          confirmed: false,
          status: "failed" as const,
          confirmations,
          reason: "RECEIPT_MUTATED" as const,
          event,
        };
      }
    }
    const finalityProvenance: FinalityProvenance = {
      inclusionBlock: Number(inclusionBlock),
      confirmationCount: confirmations,
      canonicalBlockHash: input.receipt.blockHash,
      verifiedAtBlock: Number(headBlock),
    };
    const confirmedNoteSpendable = (action === 1 || action === 4 || input.kind === "deposit" || input.kind === "swap");
    return {
      ...base,
      confirmed: true,
      status: "confirmed" as const,
      confirmations,
      finalityProvenance,
      noteSpendable: confirmedNoteSpendable,
      event,
    };
  }

  const confirmedNoteSpendable = (action === 1 || action === 4 || input.kind === "deposit" || input.kind === "swap");
  return { ...base, confirmed: true, status: "confirmed" as const, noteSpendable: confirmedNoteSpendable, event };
}
export async function broadcastFujiTransaction(input: {
  rpc: FujiRpc;
  transaction: Record<string, unknown>;
  approvalHash?: string;
}): Promise<string> {
  if (input.approvalHash) {
    const approval = await input.rpc("eth_getTransactionReceipt", [input.approvalHash]) as FujiReceipt | undefined;
    if (approval?.status !== "0x1") throw new Error("APPROVAL_NOT_SUCCESSFUL");
  }
  try {
    await input.rpc("eth_call", [input.transaction, "latest"]);
  } catch {
    throw new Error("PREFLIGHT_FAILED");
  }
  const hash = await input.rpc("eth_sendTransaction", [input.transaction]);
  if (typeof hash !== "string" || !/^0x[0-9a-f]{64}$/i.test(hash)) throw new Error("BROADCAST_FAILED");
  return hash;
}

export async function recoverFujiOperation(input: FujiOperationBinding & {
  rpc: FujiRpc;
  transactionHash?: string;
  headBlockNumber?: number | bigint;
  canonicalBlockHash?: string;
}) {
  let receipt: FujiReceipt | undefined;
  if (input.transactionHash) {
    receipt = await input.rpc("eth_getTransactionReceipt", [input.transactionHash]) as FujiReceipt | undefined;
  } else {
    const logs = await input.rpc("eth_getLogs", [{
      address: input.pool,
      fromBlock: "0x0",
      toBlock: "latest",
      topics: [PRIVATE_TRANSACTION_TOPIC, normalizedWord(input.applicationId)],
    }]) as FujiLog[];
    if (Array.isArray(logs)) {
      for (const log of logs) {
        const decoded = decodePrivateTransaction(log);
        if (decoded && matches(decoded, input) && log.transactionHash) {
          const fetched = await input.rpc("eth_getTransactionReceipt", [log.transactionHash]) as FujiReceipt | undefined;
          if (fetched) {
            receipt = fetched;
            break;
          }
        }
      }
    }
  }
  return reconcileFujiOperation({ ...input, receipt });
}

export type RecoveredSpendableNote = {
  action: FujiAction;
  commitment: string;
  nullifier: string;
  value: number;
  secret: string;
  blinding: string;
  npk: string;
  enc: string;
  x25519: string;
  leafIndex: number;
  spendable: boolean;
  transactionHash?: string;
};

export function extractLogEnvelope(dataHex: string, wordIndex: number) {
  try {
    const raw = dataHex.replace(/^0x/, "");
    if (raw.length < 16 * 64) return undefined;
    const offsetHex = raw.slice(wordIndex * 64, (wordIndex + 1) * 64);
    const byteOffset = Number(BigInt(`0x${offsetHex}`));
    const charOffset = byteOffset * 2;
    if (raw.length < charOffset + 64) return undefined;
    const lenHex = raw.slice(charOffset, charOffset + 64);
    const byteLength = Number(BigInt(`0x${lenHex}`));
    const dataSlice = raw.slice(charOffset + 64, charOffset + 64 + byteLength * 2);
    if (byteLength === 0 || dataSlice.length < byteLength * 2) return undefined;
    return decodeBrowserEnvelope(hexToBuf(`0x${dataSlice}`));
  } catch {
    return undefined;
  }
}

export function recoverSpendableNotesFromLogs(input: {
  chainId: number;
  pool: string;
  poolVersion: string;
  applicationId: string;
  recipientIkm: Uint8Array;
  logs: FujiLog[];
}): RecoveredSpendableNote[] {
  const notes: RecoveredSpendableNote[] = [];
  const seen = new Set<string>();
  const spent = new Set<string>();
  for (const log of input.logs) {
    const event = decodePrivateTransaction(log);
    if (!event) continue;
    for (const candidate of [event.inputNullifier0, event.inputNullifier1]) {
      if (candidate && BigInt(candidate) !== 0n) spent.add(normalizedWord(candidate));
    }
  }
  let leafIndex = 0;
  const info = new TextEncoder().encode("haze/avalanche/v1/recipient-note");
  for (const log of input.logs) {
    const event = decodePrivateTransaction(log);
    if (!event) continue;
    const action = event.action;
    if (action !== 1 && action !== 2 && action !== 3 && action !== 4) continue;
    const outs = [
      { commitment: event.outputCommitment0, envelope: extractLogEnvelope(log.data, 13), index: 0 },
      { commitment: event.outputCommitment1, envelope: extractLogEnvelope(log.data, 14), index: 1 },
    ];
    for (const out of outs) {
      if (!out.commitment || BigInt(out.commitment) === 0n) continue;
      const curLeafIndex = leafIndex;
      leafIndex += 1;
      if (!out.envelope || out.envelope.ciphertext.length === 0) continue;
      try {
        const aad = concatBytes(
          u64be(input.chainId),
          hexToBuf(input.pool),
          hexToBuf(input.poolVersion),
          hexToBuf(input.applicationId),
          Uint8Array.of(out.index),
          hexToBuf(out.commitment),
          Uint8Array.of(1),
        );
        const opened = openBrowserHpke({
          recipientIkm: input.recipientIkm,
          encapsulatedKey: out.envelope.encapsulatedKey,
          ciphertext: out.envelope.ciphertext,
          info,
          aad,
        });
        const plaintext = parseBrowserRecipientPlaintext(opened);
        if (!plaintext.spendingSecret) continue;
        const cm = noteCommitment({
          chainId: input.chainId,
          pool: input.pool,
          poolVersion: input.poolVersion,
          applicationId: input.applicationId,
          value: plaintext.value,
          ownerNotePublicKey: plaintext.notePublicKey,
          ownerEncryptionKeyHash: plaintext.encryptionKeyHash,
          blinding: plaintext.blinding,
        });
        if (cm.toLowerCase() !== out.commitment.toLowerCase()) continue;
        const key = cm.toLowerCase();
        if (seen.has(key)) continue;
        const spentNullifier = nullifier({
          chainId: input.chainId,
          pool: input.pool,
          poolVersion: input.poolVersion,
          applicationId: input.applicationId,
          commitment: cm,
          leafIndex: curLeafIndex,
          spendingSecret: plaintext.spendingSecret,
        });
        if (spent.has(normalizedWord(spentNullifier))) continue;
        seen.add(key);
        const ownerX25519 = toHex(deriveBrowserX25519PublicKey(input.recipientIkm));
        notes.push({
          action,
          commitment: cm,
          nullifier: spentNullifier,
          value: Number(plaintext.value),
          secret: plaintext.spendingSecret,
          blinding: plaintext.blinding,
          npk: plaintext.notePublicKey,
          enc: plaintext.encryptionKeyHash,
          x25519: ownerX25519,
          leafIndex: curLeafIndex,
          spendable: encryptionKeyHash(ownerX25519).toLowerCase() === plaintext.encryptionKeyHash.toLowerCase(),
          transactionHash: log.transactionHash,
        });
      } catch {
        // Envelope is not for this wallet.
      }
    }
  }
  return notes;
}
