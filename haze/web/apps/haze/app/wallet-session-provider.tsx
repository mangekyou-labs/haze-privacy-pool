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
  loadPersistedWalletSession,
  savePersistedWalletSession,
  type PersistedWalletSession,
} from "../../../packages/ui/src/wallet-session.ts";
import { encodeHazeAddress } from "../../../../sdk/typescript/src/address.ts";
import {
  deriveBrowserShieldedAccountFromSignature,
  type BrowserShieldedAccount,
} from "../../../../sdk/typescript/src/browser-crypto.ts";
import { notePublicKey } from "../../../../sdk/typescript/src/note.ts";
import {
  createBrowserOperationVault,
  createIndexedDbOperationStore,
  type BrowserOperationVault,
} from "../../../../sdk/typescript/src/browser-operation-vault.ts";

const CHAIN_ID = 43113;
const CHAIN_HEX = "0xa869";
const APPLICATION_ID = `0x${"00".repeat(30)}0a11`;
const POOL_B002 = "0x00BEB0A5D709d0F093952fD374Dbbf3d0d21d550";
const POOL_VERSION_B002 = `0x${"00".repeat(30)}b001`;
export type EthereumProvider = {
  request(input: { method: string; params?: unknown[] }): Promise<unknown>;
  on?(event: string, listener: (...args: unknown[]) => void): void;
  removeListener?(event: string, listener: (...args: unknown[]) => void): void;
};

type WindowWithInjectedProviders = Window & {
  avalanche?: EthereumProvider;
  ethereum?: EthereumProvider & {
    isAvalanche?: boolean;
    isRabby?: boolean;
    isMetaMask?: boolean;
  };
};

export type EIP6963ProviderDetail = {
  info: {
    uuid: string;
    name: string;
    icon: string;
    rdns: string;
  };
  provider: EthereumProvider;
};

export type WalletSessionState = {
  address: string;
  myHazeAddress: string;
  status: "disconnected" | "connecting" | "connected";
  error: string;
  activeProvider: EthereumProvider | null;
  vaultRef: MutableRefObject<BrowserOperationVault | undefined>;
  accountRef: MutableRefObject<BrowserShieldedAccount | undefined>;
  connect(provider?: EthereumProvider, rdns?: string): Promise<void>;
  disconnect(): Promise<void>;
  openConnectModal(): void;
  closeConnectModal(): void;
};

const WalletSessionContext = createContext<WalletSessionState | null>(null);

function defaultEthereum(): EthereumProvider | null {
  if (typeof window === "undefined") return null;
  return (window as WindowWithInjectedProviders).ethereum ?? null;
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
  const [address, setAddress] = useState("");
  const [myHazeAddress, setMyHazeAddress] = useState("");
  const [status, setStatus] = useState<WalletSessionState["status"]>("disconnected");
  const [error, setError] = useState("");
  const [activeProvider, setActiveProvider] = useState<EthereumProvider | null>(null);
  const [discoveredProviders, setDiscoveredProviders] = useState<EIP6963ProviderDetail[]>([]);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [modalMessage, setModalMessage] = useState("");
  const [connectingWalletName, setConnectingWalletName] = useState("");
  const [portalTarget, setPortalTarget] = useState<HTMLElement | null>(null);

  const account = useRef<BrowserShieldedAccount | undefined>(undefined);
  const vault = useRef<BrowserOperationVault | undefined>(undefined);

  // Monitor DOM for #haze-session-root and replace SSR fallback cleanly
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

  // EIP-6963 provider announcement listener
  useEffect(() => {
    const handleAnnouncement = (event: Event) => {
      const customEvent = event as CustomEvent<EIP6963ProviderDetail>;
      if (!customEvent.detail || !customEvent.detail.info) return;
      setDiscoveredProviders((prev) => {
        if (prev.some((p) => p.info.rdns === customEvent.detail.info.rdns || p.info.uuid === customEvent.detail.info.uuid)) {
          return prev;
        }
        return [...prev, customEvent.detail];
      });
    };

    window.addEventListener("eip6963:announceProvider", handleAnnouncement);
    window.dispatchEvent(new Event("eip6963:requestProvider"));

    return () => {
      window.removeEventListener("eip6963:announceProvider", handleAnnouncement);
    };
  }, []);

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
    (wallet: string, keyDerivationSignature: string, vaultUnlockSignature: string, providerRdns?: string) => {
      savePersistedWalletSession(
        { address: wallet, keyDerivationSignature, vaultUnlockSignature, providerRdns },
        window.sessionStorage,
      );
    },
    [],
  );

  // Silent resume: check accounts and load vault
  useEffect(() => {
    let cancelled = false;
    const tryResume = async () => {
      try {
        const persisted = loadPersistedWalletSession(window.sessionStorage);
        if (!persisted) return;
        let provider = activeProvider;
        if (!provider && persisted.providerRdns) {
          const match = discoveredProviders.find((p) => p.info.rdns === persisted.providerRdns);
          if (match) {
            provider = match.provider;
          }
        }
        if (!provider) {
          provider = defaultEthereum();
        }
        if (!provider) return;
        const accounts = (await provider.request({ method: "eth_accounts" })) as string[];
        if (cancelled || !accounts || accounts.length === 0) return;
        const resume = canSilentResume({ authorizedAccounts: accounts, persisted });
        if (!resume.ok) return;
        const selected = accountFromSignature(persisted.keyDerivationSignature, resume.address);
        account.current = selected;
        setMyHazeAddress(deriveHazeAddress(selected));
        await openVault(persisted.vaultUnlockSignature, resume.address);
        if (cancelled) return;
        setAddress(resume.address);
        setActiveProvider(provider);
        setStatus("connected");
        syncAddressCookie(resume.address);
      } catch {
        // Stay disconnected without crashing
      }
    };
    tryResume();
    return () => {
      cancelled = true;
    };
  }, [discoveredProviders, openVault, activeProvider]);

  const connect = useCallback(
    async (explicitProvider?: EthereumProvider, rdns?: string) => {
      const provider = explicitProvider ?? activeProvider ?? defaultEthereum();
      if (!provider) {
        setError("No Ethereum provider available. Please install a supported wallet.");
        return;
      }
      setStatus("connecting");
      setError("");
      try {
        console.log("[WALLET] Requesting accounts...");
        const accounts = (await provider.request({ method: "eth_requestAccounts" })) as string[];
        const wallet = accounts[0];
        console.log("[WALLET] Accounts received:", accounts);
        if (!wallet) throw new Error("NO_ACCOUNT_SELECTED");

        let chainId = (await provider.request({ method: "eth_chainId" })) as string;
        console.log("[WALLET] Current chainId:", chainId);
        if (chainId !== CHAIN_HEX && Number(chainId) !== CHAIN_ID) {
          try {
            await provider.request({
              method: "wallet_switchEthereumChain",
              params: [{ chainId: CHAIN_HEX }],
            });
            chainId = (await provider.request({ method: "eth_chainId" })) as string;
          } catch {
            throw new Error("FUJI_REQUIRED");
          }
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
        console.log("[WALLET] Requesting key derivation signature...");
        const keySig = (await provider.request({
          method: "eth_signTypedData_v4",
          params: [wallet, JSON.stringify(keyDerivationTypedData)],
        })) as string;
        console.log("[WALLET] Key derivation signed. Requesting vault unlock signature...");
        const selected = accountFromSignature(keySig, wallet);
        const unlockSig = (await provider.request({
          method: "personal_sign",
          params: [`Unlock Haze Fuji recovery vault\n${APPLICATION_ID}\n${POOL_B002}`, wallet],
        })) as string;
        console.log("[WALLET] Vault unlock signed. Opening browser vault...");
        await openVault(unlockSig, wallet);
        console.log("[WALLET] Vault opened successfully.");
        account.current = selected;
        setMyHazeAddress(deriveHazeAddress(selected));
        persistSession(wallet, keySig, unlockSig, rdns);
        setAddress(wallet);
        setActiveProvider(provider);
        setStatus("connected");
        syncAddressCookie(wallet);
        setIsModalOpen(false);
        setConnectingWalletName("");
        console.log("[WALLET] Connect complete for address:", wallet);
      } catch (err: unknown) {
        console.error("[WALLET] Connect error:", err);
        setStatus("disconnected");
        setConnectingWalletName("");
        const msg = err instanceof Error ? err.message : String(err ?? "WALLET_ERROR");
        setError(msg);
        setModalMessage(msg === "FUJI_REQUIRED" ? "Please switch your wallet to Avalanche Fuji testnet." : msg);
      }
    },
    [activeProvider, openVault, persistSession],
  );

  const disconnect = useCallback(async () => {
    clearPersistedWalletSession(window.sessionStorage);
    vault.current = undefined;
    account.current = undefined;
    setAddress("");
    setMyHazeAddress("");
    setError("");
    setActiveProvider(null);
    setStatus("disconnected");
    setIsModalOpen(false);
    syncAddressCookie(null);
  }, []);

  const openConnectModal = useCallback(() => {
    if (status === "connected") return;
    setError("");
    setModalMessage("");
    setIsModalOpen(true);
  }, [status]);

  const closeConnectModal = useCallback(() => {
    setIsModalOpen(false);
    setConnectingWalletName("");
  }, []);

  // Intercept navigation links for client-side routing to keep session mounted
  useEffect(() => {
    const handleLinkClick = (event: MouseEvent) => {
      const target = event.target as HTMLElement | null;
      const link = target?.closest<HTMLAnchorElement>("a.haze-tab, a.haze-more-link, a.haze-side-link, a.haze-brand, a.haze-plane-link");
      if (link && link.href) {
        const url = new URL(link.href, window.location.origin);
        if (
          url.origin === window.location.origin &&
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

  // Sync session state with DOM elements if present
  useEffect(() => {
    const chips = document.querySelectorAll("[data-shielded-balance]");
    if (chips.length > 0 && vault.current) {
      vault.current.list().then((notes) => {
        const sum = notes
          .filter((n) => n.kind === "deposit" && n.state === "confirmed")
          .reduce((acc, n) => acc + Number(n.note.value ?? 0), 0);
        const formatted = (sum / 1_000_000).toFixed(2);
        chips.forEach((c) => {
          c.textContent = `${formatted} USDC`;
        });
      });
    }
  }, [address, status]);

  const value = useMemo(
    () => ({
      address,
      myHazeAddress,
      status,
      error,
      activeProvider,
      vaultRef: vault,
      accountRef: account,
      connect,
      disconnect,
      openConnectModal,
      closeConnectModal,
    }),
    [address, myHazeAddress, status, error, activeProvider, connect, disconnect, openConnectModal, closeConnectModal],
  );

  const sessionControl = (
    <div className="haze-session-control" data-session-status={status}>
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
          onClick={() => void openConnectModal()}
          disabled={status === "connecting"}
        >
          {status === "connecting" ? "Connecting…" : "Connect wallet"}
        </button>
      )}
    </div>
  );

  // Resolved wallet choices: Core, Rabby, MetaMask + announced EIP-6963 + WalletConnect
  const handleSelectWallet = (name: string, provider?: EthereumProvider, rdns?: string) => {
    setModalMessage("");
    if (name === "WalletConnect") {
      const projectId = process.env.NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID;
      if (!projectId) {
        setModalMessage("WalletConnect is not configured");
        return;
      }
      return;
    }

    let targetProvider = provider;
    if (!targetProvider && typeof window !== "undefined") {
      const win = window as WindowWithInjectedProviders;
      if (name === "Core" && (win.avalanche || win.ethereum?.isAvalanche)) {
        targetProvider = win.avalanche || win.ethereum;
      } else if (name === "Rabby" && win.ethereum?.isRabby) {
        targetProvider = win.ethereum;
      } else if (name === "MetaMask" && win.ethereum?.isMetaMask) {
        targetProvider = win.ethereum;
      } else if (win.ethereum) {
        targetProvider = win.ethereum;
      }
    }

    if (!targetProvider) {
      setModalMessage(`${name} is not installed`);
      return;
    }

    setConnectingWalletName(name);
    connect(targetProvider, rdns);
  };

  const isWalletInstalled = (name: string, rdns?: string) => {
    if (discoveredProviders.some((p) => p.info.name.toLowerCase().includes(name.toLowerCase()) || p.info.rdns === rdns)) {
      return true;
    }
    if (typeof window === "undefined") return false;
    const win = window as WindowWithInjectedProviders;
    if (name === "Core") return Boolean(win.avalanche || win.ethereum?.isAvalanche);
    if (name === "Rabby") return Boolean(win.ethereum?.isRabby);
    if (name === "MetaMask") return Boolean(win.ethereum?.isMetaMask);
    return false;
  };

  return (
    <WalletSessionContext.Provider value={value}>
      {children}
      {portalTarget ? createPortal(sessionControl, portalTarget) : null}

      {/* EIP-6963 Wallet Modal Overlay */}
      {isModalOpen && (
        <div className="haze-modal-backdrop" onClick={closeConnectModal}>
          <div
            className="haze-modal-dialog haze-wallet-modal"
            onClick={(e) => e.stopPropagation()}
            role="dialog"
            aria-labelledby="wallet-modal-title"
          >
            <div className="haze-modal-header">
              <h2 id="wallet-modal-title" className="haze-title" style={{ margin: 0, fontSize: "18px" }}>
                {status === "connecting" ? "Connecting…" : "Connect Wallet"}
              </h2>
              <button
                type="button"
                className="haze-modal-close"
                onClick={closeConnectModal}
                aria-label="Close modal"
              >
                ✕
              </button>
            </div>

            {status === "connecting" ? (
              <div className="haze-connecting-state" style={{ padding: "24px 0", textAlign: "center" }}>
                <div className="haze-spinner" style={{ margin: "0 auto 16px" }}></div>
                <p style={{ margin: 0, fontWeight: 600 }}>
                  Connecting to {connectingWalletName || "Wallet"}…
                </p>
                <p className="haze-muted" style={{ fontSize: "12px", marginTop: "8px" }}>
                  Please approve the connection and sign the recovery vault unlock in your wallet.
                </p>
              </div>
            ) : (
              <div className="haze-wallet-list" style={{ display: "flex", flexDirection: "column", gap: "8px", marginTop: "16px" }}>
                {/* Core */}
                <button
                  type="button"
                  className="haze-wallet-row"
                  onClick={() => handleSelectWallet("Core", undefined, "app.core.extension")}
                >
                  <span className="haze-wallet-name">Core</span>
                  <span className="haze-badge">{isWalletInstalled("Core", "app.core.extension") ? "Installed" : "Install"}</span>
                </button>

                {/* Rabby */}
                <button
                  type="button"
                  className="haze-wallet-row"
                  onClick={() => handleSelectWallet("Rabby", undefined, "io.rabby")}
                >
                  <span className="haze-wallet-name">Rabby</span>
                  <span className="haze-badge">{isWalletInstalled("Rabby", "io.rabby") ? "Installed" : "Install"}</span>
                </button>

                {/* MetaMask */}
                <button
                  type="button"
                  className="haze-wallet-row"
                  onClick={() => handleSelectWallet("MetaMask", undefined, "io.metamask")}
                >
                  <span className="haze-wallet-name">MetaMask</span>
                  <span className="haze-badge">{isWalletInstalled("MetaMask", "io.metamask") ? "Installed" : "Install"}</span>
                </button>

                {/* Other Discovered Providers */}
                {discoveredProviders
                  .filter((p) => !["core", "rabby", "metamask"].some((k) => p.info.name.toLowerCase().includes(k)))
                  .map((p) => (
                    <button
                      key={p.info.uuid}
                      type="button"
                      className="haze-wallet-row"
                      onClick={() => handleSelectWallet(p.info.name, p.provider, p.info.rdns)}
                    >
                      <span className="haze-wallet-name">{p.info.name}</span>
                      <span className="haze-badge">Installed</span>
                    </button>
                  ))}

                {/* WalletConnect */}
                <button
                  type="button"
                  className="haze-wallet-row"
                  onClick={() => handleSelectWallet("WalletConnect")}
                >
                  <span className="haze-wallet-name">WalletConnect</span>
                  <span className="haze-badge haze-muted">QR Code</span>
                </button>
              </div>
            )}

            {modalMessage && (
              <div className="haze-banner" style={{ marginTop: "16px" }} role="alert">
                {modalMessage}
              </div>
            )}
          </div>
        </div>
      )}
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
