import { keccak_256 } from "@noble/hashes/sha3";

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

type FujiOperationBinding = {
  chainId: number;
  pool: string;
  poolVersion: string;
  applicationId: string;
  user: string;
  action: number;
  commitment?: string;
  nullifier?: string;
  kind: BrowserOperationKind;
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

export function decodePrivateTransaction(log: FujiLog) {
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

function matches(event: ReturnType<typeof decodePrivateTransaction>, binding: FujiOperationBinding): boolean {
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
  const base = {
    noteSpendable: input.kind === "withdrawal",
    disclosureState: "not_requested" as const,
    bindings: { chainId: input.chainId, pool: input.pool, poolVersion: input.poolVersion, applicationId: input.applicationId, action: input.action },
  };
  if (!input.receipt) return { ...base, confirmed: false, status: "failed" as const, reason: "RECEIPT_MISSING" as const };
  if (input.receipt.status !== "0x1") return { ...base, confirmed: false, status: "failed" as const, reason: "RECEIPT_REVERTED" as const };
  const decoded = (input.receipt.logs ?? []).map(decodePrivateTransaction).filter(Boolean);
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
    return {
      ...base,
      confirmed: true,
      status: "confirmed" as const,
      confirmations,
      finalityProvenance,
      noteSpendable: input.kind === "withdrawal" ? false : base.noteSpendable,
      event,
    };
  }

  return { ...base, confirmed: true, status: "confirmed" as const, noteSpendable: input.kind === "withdrawal" ? false : base.noteSpendable, event };
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
