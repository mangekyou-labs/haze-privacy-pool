// Injected-wallet discovery. Several extensions (Core, Phantom, Backpack) overwrite
// window.ethereum and some impersonate MetaMask, so window.ethereum alone can point the
// app at the wrong wallet and chain. EIP-6963 lets each wallet announce itself; prefer
// the MetaMask announcement and fall back to window.ethereum, then any announced wallet.

export type InjectedProvider = { request(input: { method: string; params?: unknown[] }): Promise<unknown> };

type Announcement = { info?: { rdns?: string }; provider?: InjectedProvider };
type DiscoveryWindow = {
  ethereum?: InjectedProvider;
  addEventListener(type: string, listener: (event: { detail?: Announcement }) => void): void;
  dispatchEvent(event: { type: string }): boolean;
};

export const PREFERRED_WALLET_RDNS = "io.metamask";

export function createInjectedProviderResolver(win: DiscoveryWindow | undefined): () => InjectedProvider {
  const announced: Announcement[] = [];
  if (win) {
    win.addEventListener("eip6963:announceProvider", (event) => {
      const detail = event?.detail;
      if (detail?.provider && !announced.some((item) => item.provider === detail.provider)) announced.push(detail);
    });
    win.dispatchEvent(new Event("eip6963:requestProvider"));
  }
  return () => {
    const preferred = announced.find((item) => item.info?.rdns === PREFERRED_WALLET_RDNS)?.provider;
    const provider = preferred ?? win?.ethereum ?? announced[0]?.provider;
    if (!provider) throw new Error("WALLET_UNAVAILABLE");
    return provider;
  };
}

let browserResolver: (() => InjectedProvider) | undefined;

/** Shared browser resolver; starts EIP-6963 discovery on first use. */
export function injectedProvider(): InjectedProvider {
  if (!browserResolver) {
    browserResolver = createInjectedProviderResolver(
      typeof window === "undefined" ? undefined : (window as unknown as DiscoveryWindow),
    );
  }
  return browserResolver();
}
