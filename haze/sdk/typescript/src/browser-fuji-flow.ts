import type { BrowserOperation } from "./browser-operation-vault.ts";

type Receipt = { status?: string; logs?: unknown[] };

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
  for (let attempt = 0; attempt < 15; attempt += 1) {
    try {
      await input.preflight(input.poolTransaction);
      preflightError = undefined;
      break;
    } catch (error) {
      preflightError = error;
      await pause(1_000);
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
