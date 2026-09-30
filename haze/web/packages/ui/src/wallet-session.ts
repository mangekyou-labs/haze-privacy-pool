/** React-free wallet session persistence for the hosted Haze app shell. */

export const SESSION_STORAGE_KEY = "haze.wallet-session.v1";

export type PersistedWalletSession = {
  address: string;
  keyDerivationSignature: string;
  vaultUnlockSignature: string;
  providerRdns?: string;
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
      const session: PersistedWalletSession = {
        address: parsed.address,
        keyDerivationSignature: parsed.keyDerivationSignature,
        vaultUnlockSignature: parsed.vaultUnlockSignature,
      };
      if (typeof parsed?.providerRdns === "string") {
        session.providerRdns = parsed.providerRdns;
      }
      return session;
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
