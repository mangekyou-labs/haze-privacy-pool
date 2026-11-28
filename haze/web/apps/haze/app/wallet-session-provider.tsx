"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import type { MutableRefObject, ReactNode } from "react";
import { createPortal } from "react-dom";
import { useRouter } from "next/navigation";
import {
  canSilentResume,
  clearPersistedWalletSession,
  INITIAL_VAULT_HYDRATION,
  loadPersistedWalletSession,
  markVaultClosed,
  markVaultOpened,
  savePersistedWalletSession,
  shouldReusePersistedSignatures,
  type PersistedWalletSession,
} from "../../../packages/ui/src/wallet-session.ts";
import { injectedProvider } from "../../../packages/ui/src/wallet-provider.ts";
import { encodeHazeAddress } from "../../../../sdk/typescript/src/address.ts";
import {
  deriveBrowserShieldedAccountFromSignature,
  type BrowserShieldedAccount,
} from "../../../../sdk/typescript/src/browser-crypto.ts";
import { notePublicKey } from "../../../../sdk/typescript/src/note.ts";
import { FUJI_V2 } from "../../../../sdk/typescript/src/fuji-v2-defaults.ts";
import {
  createBrowserOperationVault,
  createIndexedDbOperationStore,
} from "../../../../sdk/typescript/src/browser-operation-vault.ts";

const CHAIN_ID = 43113;
const CHAIN_HEX = "0xa869";
const APPLICATION_ID = `0x${"00".repeat(30)}0a11`;
const POOL_B002: string = process.env.NEXT_PUBLIC_HAZE_POOL || FUJI_V2.pool;
const POOL_VERSION_B002 = `0x${"00".repeat(30)}b001`;

type Ethereum = { request(input: { method: string; params?: unknown[] }): Promise<unknown> };

export type WalletSessionState = {
  address: string;
  myHazeAddress: string;
  status: "disconnected" | "connecting" | "connected";
  error: string;
  vaultReady: boolean;
  vaultGeneration: number;
  vaultRef: MutableRefObject<Awaited<ReturnType<typeof createBrowserOperationVault>> | undefined>;
  accountRef: MutableRefObject<BrowserShieldedAccount | undefined>;
  connect(): Promise<void>;
  disconnect(): Promise<void>;
};

const WalletSessionContext = createContext<WalletSessionState | null>(null);

function ethereum(): Ethereum {
  return injectedProvider();
}

function syncAddressCookie(address?: string | null) {
  if (typeof document === "undefined") return;
  if (address) {
    document.cookie = `haze-address=${address}; path=/; SameSite=Lax`;
  } else {
    document.cookie = "haze-address=; path=/; max-age=0; SameSite=Lax";
    document.cookie = "haze-role=; path=/; max-age=0; SameSite=Lax";
  }
}

export function WalletSessionProvider({ children }: { children: ReactNode }) {
  const router = useRouter();
  const [address, setAddress] = useState<string>(() => {
    if (typeof window !== "undefined") {
      const persisted = loadPersistedWalletSession(window.sessionStorage);
      return persisted?.address || "";
    }
    return "";
  });
  const [myHazeAddress, setMyHazeAddress] = useState<string>("");
  const [status, setStatus] = useState<WalletSessionState["status"]>(() => {
    if (typeof window !== "undefined") {
      const persisted = loadPersistedWalletSession(window.sessionStorage);
      return persisted?.address ? "connected" : "disconnected";
    }
    return "disconnected";
  });
  const [error, setError] = useState("");
  const [vaultHydration, setVaultHydration] = useState(INITIAL_VAULT_HYDRATION);
  const { vaultReady, vaultGeneration } = vaultHydration;
  const [portalTarget, setPortalTarget] = useState<HTMLElement | null>(null);
  const account = useRef<BrowserShieldedAccount | undefined>(undefined);
  const vault = useRef<Awaited<ReturnType<typeof createBrowserOperationVault>> | undefined>(undefined);

  useEffect(() => {
    const updateTarget = () => {
      const root = document.getElementById("haze-session-root");
      if (root) {
        Array.from(root.children).forEach((child) => {
          if (!child.classList.contains("haze-session-control")) {
            child.remove();
          }
        });
      }
      setPortalTarget(root);
    };
    updateTarget();
    const observer = new MutationObserver(updateTarget);
    observer.observe(document.body, { childList: true, subtree: true });
    return () => observer.disconnect();
  }, []);

  // Intercept all internal navigation links for client-side routing to keep session mounted across tab changes
  useEffect(() => {
    const handleLinkClick = (event: MouseEvent) => {
      const target = event.target as HTMLElement | null;
      const link = target?.closest<HTMLAnchorElement>(
        "a.haze-tab, a.haze-more-link, a.haze-side-link, a.haze-brand, a.haze-plane-link, a.haze-button, a[href]",
      );
      if (link && link.href) {
        const url = new URL(link.href, window.location.origin);
        if (
          url.origin === window.location.origin &&
          !url.pathname.startsWith("/api") &&
          !url.pathname.startsWith("/_next") &&
          !link.hasAttribute("download") &&
          link.target !== "_blank" &&
          !event.ctrlKey &&
          !event.metaKey &&
          !event.shiftKey &&
          !event.altKey &&
          event.button === 0
        ) {
          event.preventDefault();
          router.push(`${url.pathname}${url.search}${url.hash}`);
        }
      }
    };
    document.addEventListener("click", handleLinkClick);
    return () => {
      document.removeEventListener("click", handleLinkClick);
    };
  }, [router]);

  const openVault = useCallback(async (unlockSignature: string, wallet: string) => {
    const active = await createBrowserOperationVault({
      database: createIndexedDbOperationStore(),
      signature: unlockSignature,
      binding: { chainId: CHAIN_ID, applicationId: APPLICATION_ID, pool: POOL_B002, wallet },
    });
    vault.current = active;
    return active;
  }, []);

  const persistSession = useCallback(
    (wallet: string, keyDerivationSignature: string, vaultUnlockSignature: string) => {
      savePersistedWalletSession(
        { address: wallet, keyDerivationSignature, vaultUnlockSignature },
        window.sessionStorage,
      );
    },
    [],
  );

  // Silent resume: eth_accounts only; reconstruct vault only when storage matches.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const accounts = (await ethereum().request({ method: "eth_accounts" })) as string[];
        if (cancelled) return;
        const persisted = loadPersistedWalletSession(window.sessionStorage);
        const resume = canSilentResume({ authorizedAccounts: accounts, persisted });
        if (!resume.ok) return;
        const selected = accountFromSignature(persisted!.keyDerivationSignature, resume.address);
        account.current = selected;
        setMyHazeAddress(deriveHazeAddress(selected));
        await openVault(persisted!.vaultUnlockSignature, resume.address);
        if (cancelled) return;
        setVaultHydration((previous) => markVaultOpened(previous));
        setAddress(resume.address);
        syncAddressCookie(resume.address);
        setStatus("connected");
      } catch {
        // No provider or no matching session: stay disconnected without a popup.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [openVault]);

  const connect = useCallback(async () => {
    setStatus("connecting");
    setError("");
    try {
      const accounts = (await ethereum().request({ method: "eth_requestAccounts" })) as string[];
      const wallet = accounts[0];
      const currentChain = await ethereum().request({ method: "eth_chainId" });
      console.log("[WALLET PROVIDER] connect() accounts:", accounts, "chainId:", currentChain);
      if (!wallet || String(currentChain).toLowerCase() !== CHAIN_HEX.toLowerCase()) {
        throw new Error(`FUJI_REQUIRED: current chain is ${currentChain}, expected ${CHAIN_HEX}`);
      }
      const persisted = loadPersistedWalletSession(window.sessionStorage);
      if (shouldReusePersistedSignatures({ accounts, persisted }) && persisted) {
        const selected = accountFromSignature(persisted.keyDerivationSignature, wallet);
        await openVault(persisted.vaultUnlockSignature, wallet);
        account.current = selected;
        setMyHazeAddress(deriveHazeAddress(selected));
        setVaultHydration((previous) => markVaultOpened(previous));
        setAddress(wallet);
        syncAddressCookie(wallet);
        setStatus("connected");
        return;
      }

      const keyDerivationTypedData = {
        types: {
          EIP712Domain: [
            { name: "name", type: "string" },
            { name: "version", type: "string" },
            { name: "chainId", type: "uint256" },
            { name: "verifyingContract", type: "address" },
          ],
          HazeKeyDerivation: [
            { name: "wallet", type: "address" },
            { name: "applicationId", type: "bytes32" },
            { name: "poolVersion", type: "bytes32" },
          ],
        },
        primaryType: "HazeKeyDerivation",
        domain: {
          name: "Haze Shielded Account",
          version: "1",
          chainId: CHAIN_ID,
          verifyingContract: POOL_B002,
        },
        message: {
          wallet,
          applicationId: APPLICATION_ID,
          poolVersion: POOL_VERSION_B002,
        },
      };
      const keySig = (await ethereum().request({
        method: "eth_signTypedData_v4",
        params: [wallet, JSON.stringify(keyDerivationTypedData)],
      })) as string;
      const selected = accountFromSignature(keySig, wallet);
      const unlockSig = (await ethereum().request({
        method: "personal_sign",
        params: [`Unlock Haze Fuji recovery vault\n${APPLICATION_ID}\n${POOL_B002}`, wallet],
      })) as string;
      await openVault(unlockSig, wallet);
      account.current = selected;
      setMyHazeAddress(deriveHazeAddress(selected));
      persistSession(wallet, keySig, unlockSig);
      setVaultHydration((previous) => markVaultOpened(previous));
      setAddress(wallet);
      syncAddressCookie(wallet);
      setStatus("connected");
    } catch (error) {
      console.error("[WALLET PROVIDER] connect error:", error);
      setStatus("disconnected");
      setError(error instanceof Error ? error.message : "WALLET_ERROR");
    }
  }, [openVault, persistSession]);

  const disconnect = useCallback(async () => {
    clearPersistedWalletSession(window.sessionStorage);
    vault.current = undefined;
    account.current = undefined;
    setVaultHydration(markVaultClosed());
    setAddress("");
    setMyHazeAddress("");
    setError("");
    setStatus("disconnected");
    syncAddressCookie(null);
    // No location.reload(): in-memory keys drop; provider state survives a tab switch.
  }, []);

  const value = useMemo(
    () => ({
      address,
      myHazeAddress,
      status,
      error,
      vaultReady,
      vaultGeneration,
      vaultRef: vault,
      accountRef: account,
      connect,
      disconnect,
    }),
    [address, myHazeAddress, status, error, vaultReady, vaultGeneration, connect, disconnect],
  );

  const sessionControl = (
    <div className="haze-session-control" data-session-status={status} data-vault-ready={vaultReady ? "true" : "false"}>
      {status === "connected" && address ? (
        <>
          <span className="haze-chip haze-chip-wallet" data-address={address}>
            {address.slice(0, 6)}…{address.slice(-4)}
          </span>
          <button
            className="haze-button haze-button-secondary haze-session-disconnect"
            type="button"
            data-action="disconnect"
            onClick={() => void disconnect()}
          >
            Disconnect
          </button>
        </>
      ) : (
        <button
          className="haze-button haze-session-connect"
          type="button"
          data-action="connect"
          onClick={() => void connect()}
          disabled={status === "connecting"}
        >
          {status === "connecting" ? "Connecting…" : "Connect"}
        </button>
      )}
    </div>
  );

  return (
    <WalletSessionContext.Provider value={value}>
      {children}
      {portalTarget ? createPortal(sessionControl, portalTarget) : null}
    </WalletSessionContext.Provider>
  );
}

export function useWalletSession(): WalletSessionState {
  const session = useContext(WalletSessionContext);
  if (!session) {
    throw new Error("useWalletSession must be used within WalletSessionProvider");
  }
  return session;
}

function accountFromSignature(signature: string, wallet: string): BrowserShieldedAccount {
  return deriveBrowserShieldedAccountFromSignature({
    signature,
    wallet,
    chainId: CHAIN_ID,
    pool: POOL_B002,
    applicationId: APPLICATION_ID,
    poolVersion: POOL_VERSION_B002,
  });
}

function deriveHazeAddress(account: BrowserShieldedAccount): string {
  return encodeHazeAddress({
    chainId: CHAIN_ID,
    applicationId: APPLICATION_ID,
    poolVersion: POOL_VERSION_B002,
    notePublicKey: notePublicKey(account.spendingSecret),
    x25519PublicKey: account.x25519PublicKey,
  });
}
