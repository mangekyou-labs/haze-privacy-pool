/** React-free wallet session persistence for the hosted Haze app shell. */

export const SESSION_STORAGE_KEY = "haze.wallet-session.v1";

export type PersistedWalletSession = {
  address: string;
  keyDerivationSignature: string;
  vaultUnlockSignature: string;
};

export type SilentResumeResult =
  | { ok: true; address: string }
  | { ok: false; reason: "no-account" | "mismatch" | "locked" };

export function savePersistedWalletSession(
  session: PersistedWalletSession,
  storage: Pick<Storage, "setItem">,
): void {
  storage.setItem(SESSION_STORAGE_KEY, JSON.stringify(session));
}

export function loadPersistedWalletSession(
  storage: Pick<Storage, "getItem">,
): PersistedWalletSession | null {
  const raw = storage.getItem(SESSION_STORAGE_KEY);
  if (!raw) {
    return null;
  }
  try {
    const parsed = JSON.parse(raw);
    if (
      typeof parsed?.address === "string" &&
      typeof parsed?.keyDerivationSignature === "string" &&
      typeof parsed?.vaultUnlockSignature === "string"
    ) {
      return parsed as PersistedWalletSession;
    }
  } catch {
    // Corrupt session storage is treated as locked, not a crash.
  }
  return null;
}

export function clearPersistedWalletSession(
  storage: Pick<Storage, "removeItem">,
): void {
  storage.removeItem(SESSION_STORAGE_KEY);
}

export function canSilentResume(input: {
  authorizedAccounts: string[];
  persisted: PersistedWalletSession | null;
}): SilentResumeResult {
  const [account] = input.authorizedAccounts;
  if (!account) {
    return { ok: false, reason: "no-account" };
  }
  if (!input.persisted) {
    return { ok: false, reason: "locked" };
  }
  if (account.toLowerCase() !== input.persisted.address.toLowerCase()) {
    return { ok: false, reason: "mismatch" };
  }
  return { ok: true, address: input.persisted.address };
}

export function shouldReusePersistedSignatures(input: {
  accounts: string[];
  persisted: PersistedWalletSession | null;
}): boolean {
  if (!input.persisted) {
    return false;
  }
  const [account] = input.accounts;
  if (!account) {
    return false;
  }
  return account.toLowerCase() === input.persisted.address.toLowerCase();
}

export type VaultHydrationState = {
  vaultReady: boolean;
  vaultGeneration: number;
};

export const INITIAL_VAULT_HYDRATION: VaultHydrationState = {
  vaultReady: false,
  vaultGeneration: 0,
};

/** Call after openVault even when address/status already painted connected from sessionStorage. */
export function markVaultOpened(previous: VaultHydrationState): VaultHydrationState {
  return {
    vaultReady: true,
    vaultGeneration: previous.vaultGeneration + 1,
  };
}

export function markVaultClosed(): VaultHydrationState {
  return { vaultReady: false, vaultGeneration: 0 };
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

export function formatOverviewPublicBalance(rawHex: string | null | undefined, connected = true): string {
  if (!connected || rawHex == null || rawHex === "") return "—";
  return `${formatUsdc(decodeErc20Balance(rawHex))} USDC`;
}

export function formatOverviewPrivateBalance(spendableSum: bigint | number | null | undefined, connected = true): string {
  if (!connected) return "—";
  if (spendableSum == null || spendableSum === 0 || spendableSum === 0n) return "0.00 USDC";
  return `${formatUsdc(spendableSum)} USDC`;
}

export function sumSpendableNotes(
  notes?: Array<{ note?: { value?: number | bigint; spendable?: boolean }; state?: string }> | null,
): bigint {
  if (!notes || notes.length === 0) return 0n;
  let total = 0n;
  for (const item of notes) {
    if (item?.note?.value != null && item.note.spendable !== false && item.state === "confirmed") {
      total += BigInt(item.note.value);
    }
  }
  return total;
}

export type RecentOperationType = "Shield" | "Send" | "Withdraw" | "Swap";

export type RecentOperationRow = {
  id: string;
  date: string;
  type: RecentOperationType;
  amount: string;
  status: string;
  receipt: string;
  receiptHref?: string;
};

type RecentOperationInput = {
  id: string;
  kind?: string;
  state?: string;
  note?: {
    amount?: number | bigint | string;
    value?: number | bigint | string;
    spendable?: boolean;
    consumed?: boolean;
    wiped?: boolean;
  };
  transaction?: {
    hash?: string;
    transactionHash?: string;
    action?: number;
    timestamp?: number;
    finalityProvenance?: { confirmationCount?: number; inclusionBlock?: number };
    failureDetails?: { timestamp?: number };
  };
};

const RECENT_OP_STATES = new Set(["confirmed", "submitted", "pending_finality", "failed"]);

function recentOperationType(item: RecentOperationInput): RecentOperationType {
  const action = item.transaction?.action;
  if (action === 1) return "Shield";
  if (action === 2) return "Send";
  if (action === 3) return "Withdraw";
  if (action === 4) return "Swap";
  if (item.kind === "deposit") return "Shield";
  if (item.kind === "transfer" || item.kind === "private_send") return "Send";
  if (item.kind === "withdrawal") return "Withdraw";
  return "Swap";
}

function recentOperationStatus(item: RecentOperationInput): string {
  if (item.state === "confirmed") return "Finalized";
  if (item.state === "submitted") return "Submitted";
  if (item.state === "failed") return "Failed";
  const confirmations = item.transaction?.finalityProvenance?.confirmationCount ?? 0;
  return `Pending finality (${confirmations}/12)`;
}

function recentOperationTimestamp(item: RecentOperationInput): number {
  const tx = item.transaction;
  if (typeof tx?.timestamp === "number") return tx.timestamp;
  if (typeof tx?.failureDetails?.timestamp === "number") return tx.failureDetails.timestamp;
  if (typeof tx?.finalityProvenance?.inclusionBlock === "number") {
    return tx.finalityProvenance.inclusionBlock;
  }
  return 0;
}

function recentOperationReceipt(hash?: string): { receipt: string; receiptHref?: string } {
  if (!hash || hash === "pending") return { receipt: "—" };
  return {
    receipt: `${hash.slice(0, 10)}…${hash.slice(-4)}`,
    receiptHref: `https://testnet.snowtrace.io/tx/${hash}`,
  };
}

export function recentOperationsFromVault(
  notes?: RecentOperationInput[] | null,
  options: { limit?: number } = {},
): RecentOperationRow[] {
  if (!notes || notes.length === 0) return [];
  const limit = options.limit ?? 8;
  const visible = notes.filter((item) => {
    if (!item || !RECENT_OP_STATES.has(item.state ?? "")) return false;
    if (item.note?.wiped === true) return false;
    if (item.note?.consumed === true) return false;
    return true;
  });
  visible.sort((a, b) => recentOperationTimestamp(b) - recentOperationTimestamp(a));
  return visible.slice(0, limit).map((item) => {
    const hash =
      typeof item.transaction?.hash === "string" && item.transaction.hash !== "pending"
        ? item.transaction.hash
        : typeof item.transaction?.transactionHash === "string" &&
            item.transaction.transactionHash !== "pending"
          ? item.transaction.transactionHash
          : undefined;
    const amountRaw = item.note?.amount ?? item.note?.value ?? 0;
    const { receipt, receiptHref } = recentOperationReceipt(hash);
    const timestamp = recentOperationTimestamp(item);
    const date =
      timestamp > 1_000_000_000_000
        ? new Date(timestamp).toISOString().slice(0, 10)
        : timestamp > 1_000_000_000
          ? new Date(timestamp * 1000).toISOString().slice(0, 10)
          : "—";
    return {
      id: item.id,
      date,
      type: recentOperationType(item),
      amount: formatUsdc(amountRaw),
      status: recentOperationStatus(item),
      receipt,
      receiptHref,
    };
  });
}
