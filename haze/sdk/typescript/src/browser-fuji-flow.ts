import type { BrowserOperation } from "./browser-operation-vault.ts";

type Receipt = { status?: string; blockNumber?: string | number; blockHash?: string; logs?: unknown[] };

const GENERIC_RPC_MESSAGES = new Set([
  "execution reverted",
  "Internal JSON-RPC error.",
  "Internal JSON-RPC error",
]);

function decodeRevertReason(value: string): string | undefined {
  if (!/^0x08c379a0[0-9a-fA-F]+$/.test(value) || value.length < 138) return undefined;
  try {
    const length = Number.parseInt(value.slice(74, 138), 16);
    const payload = value.slice(138, 138 + length * 2);
    if (!Number.isSafeInteger(length) || payload.length !== length * 2) return undefined;
    const bytes = Uint8Array.from(payload.match(/.{2}/g) ?? [], (byte) => Number.parseInt(byte, 16));
    const reason = new TextDecoder().decode(bytes).trim();
    return reason ? `execution reverted: ${reason}` : undefined;
  } catch {
    return undefined;
  }
}

export function extractFujiRpcError(error: unknown): string {
  const seen = new Set<object>();
  const candidates: string[] = [];

  const visit = (value: unknown): void => {
    if (typeof value === "string") {
      const decoded = decodeRevertReason(value);
      candidates.push(decoded ?? value);
      return;
    }
    if (!value || typeof value !== "object" || seen.has(value)) return;
    seen.add(value);
    const record = value as Record<string, unknown>;
    for (const key of ["originalError", "cause", "error", "data"]) visit(record[key]);
    visit(record.message);
  };

  visit(error);
  return candidates.find((message) => /^execution reverted:\s*\S/i.test(message))
    ?? candidates.find((message) => message && !/^0x[0-9a-f]+$/i.test(message) && !GENERIC_RPC_MESSAGES.has(message))
    ?? candidates.find((message) => message && !GENERIC_RPC_MESSAGES.has(message))
    ?? candidates.find(Boolean)
    ?? "PREFLIGHT_REVERT";
}

export async function updateFujiMembershipRoot(input: {
  membershipRoot: string;
  applicationId: string;
  policyAuthority: string;
  wallet: string;
  readApplication: () => Promise<{ membershipVersion: bigint; membershipRoot: string }>;
  sendUpdate: (applicationId: string, membershipRoot: string) => Promise<string>;
  waitReceipt: (hash: string) => Promise<Receipt | undefined>;
  sleep?: (ms: number) => Promise<void>;
}) {
  if (input.wallet.toLowerCase() !== input.policyAuthority.toLowerCase()) throw new Error("POLICY_AUTHORITY_REQUIRED");
  const before = await input.readApplication();
  if (before.membershipRoot.toLowerCase() === input.membershipRoot.toLowerCase()) return before;
  const hash = await input.sendUpdate(input.applicationId, input.membershipRoot);
  const receipt = await input.waitReceipt(hash);
  if (receipt?.status !== "0x1") throw new Error("MEMBERSHIP_UPDATE_FAILED");
  const pause = input.sleep ?? ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms)));
  for (let attempt = 0; attempt < 15; attempt += 1) {
    const after = await input.readApplication();
    if (after.membershipVersion === before.membershipVersion + 1n
      && after.membershipRoot.toLowerCase() === input.membershipRoot.toLowerCase()) {
      return after;
    }
    await pause(1_000);
  }
  const after = await input.readApplication();
  if (after.membershipVersion !== before.membershipVersion + 1n
    || after.membershipRoot.toLowerCase() !== input.membershipRoot.toLowerCase()) {
    throw new Error("MEMBERSHIP_UPDATE_MISMATCH");
  }
  return after;
}

export async function ensureFujiMembershipRoot(input: {
  membershipRoot: string;
  applicationId: string;
  policyAuthority: string;
  wallet: string;
  readApplication: () => Promise<{ membershipVersion: bigint; membershipRoot: string }>;
  sendUpdate?: (applicationId: string, membershipRoot: string) => Promise<string>;
  waitReceipt?: (hash: string) => Promise<Receipt | undefined>;
  sleep?: (ms: number) => Promise<void>;
  relayUpdate?: (input: { applicationId: string; membershipRoot: string }) => Promise<{ membershipVersion: bigint; membershipRoot: string }>;
}): Promise<{ membershipVersion: bigint; membershipRoot: string }> {
  const before = await input.readApplication();
  if (before.membershipRoot.toLowerCase() === input.membershipRoot.toLowerCase()) {
    return before;
  }
  if (input.wallet.toLowerCase() === input.policyAuthority.toLowerCase()) {
    if (!input.sendUpdate || !input.waitReceipt) {
      throw new Error("AUTHORITY_TRANSACTION_HELPERS_REQUIRED");
    }
    return updateFujiMembershipRoot({
      membershipRoot: input.membershipRoot,
      applicationId: input.applicationId,
      policyAuthority: input.policyAuthority,
      wallet: input.wallet,
      readApplication: input.readApplication,
      sendUpdate: input.sendUpdate,
      waitReceipt: input.waitReceipt,
      sleep: input.sleep,
    });
  }
  if (!input.relayUpdate) {
    throw new Error("MEMBERSHIP_RELAYER_UNAVAILABLE");
  }
  return input.relayUpdate({
    applicationId: input.applicationId,
    membershipRoot: input.membershipRoot,
  });
}

export async function executeFujiBrowserTransaction(input: {
  operation: BrowserOperation;
  approvalTransaction?: Record<string, unknown>;
  poolTransaction: Record<string, unknown>;
  send: (transaction: Record<string, unknown>) => Promise<string>;
  waitReceipt: (hash: string) => Promise<Receipt | undefined>;
  preflight: (transaction: Record<string, unknown>) => Promise<void>;
  markSubmittedBeforeBroadcast: <T>(id: string, transaction: Record<string, unknown>, broadcast: () => Promise<T>) => Promise<T>;
  recordSubmittedHash?: (id: string, hash: string) => Promise<unknown>;
  reconcile: (receipt: Receipt | undefined) => { confirmed: boolean; noteSpendable?: boolean; event?: unknown };
  sleep?: (ms: number) => Promise<void>;
}) {
  if (input.approvalTransaction) {
    const approvalHash = await input.send(input.approvalTransaction);
    const approvalReceipt = await input.waitReceipt(approvalHash);
    if (approvalReceipt?.status !== "0x1") throw new Error("APPROVAL_NOT_SUCCESSFUL");
  }
  const pause = input.sleep ?? ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms)));
  let preflightError: unknown;
  for (let attempt = 0; attempt < 35; attempt += 1) {
    try {
      await input.preflight(input.poolTransaction);
      preflightError = undefined;
      break;
    } catch (error) {
      preflightError = error;
      await pause(2_000);
    }
  }
  if (preflightError) {
    throw preflightError;
  }
  const transactionHash = await input.markSubmittedBeforeBroadcast(
    input.operation.id,
    { hash: "pending", bindings: input.operation.transaction },
    () => input.send(input.poolTransaction),
  );
  await input.recordSubmittedHash?.(input.operation.id, transactionHash);
  const receipt = await input.waitReceipt(transactionHash);
  const result = input.reconcile(receipt);
  return { ...result, transactionHash, receipt };
}
