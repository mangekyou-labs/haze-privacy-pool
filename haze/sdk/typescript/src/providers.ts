/** Fail-closed provider error codes. */
export type ProviderErrorCode = "UNAVAILABLE" | "REJECTED" | "QUOTE_STALE" | "CHAIN_MISMATCH";

/** Provider-neutral swap quote request. */
export interface SwapQuoteRequest {
  tokenIn: string;
  amountIn: string;
  minUsdcOut: string;
  deadline: number;
}

/** Provider-neutral swap quote. */
export interface SwapQuote {
  tokenIn: string;
  usdcOut: string;
  routeHash: string;
  deadline: number;
}

/** Quote source for swap-and-shield. */
export interface DexQuoteSource {
  quote(request: SwapQuoteRequest): Promise<SwapQuote>;
}

/** Narrow EVM transport. */
export interface ChainRpc {
  chainId(): Promise<number>;
}

/** Application-owned key unwrap. */
export interface KeyManagement {
  unwrapDataKey(applicationId: string, keyRef: string, wrappedKey: Uint8Array): Promise<Uint8Array>;
}

/** OIDC/SAML session intake. */
export interface IdentityProvider {
  authenticate(assertion: string): Promise<{ issuer: string; subject: string; expiresAt: number }>;
}

/** Object storage for ciphertext and manifests. */
export interface ObjectStore {
  put(key: string, value: Uint8Array): Promise<void>;
  get(key: string): Promise<Uint8Array>;
}

/** DEX mock that is down. */
export class UnavailableDex implements DexQuoteSource {
  async quote(_request: SwapQuoteRequest): Promise<SwapQuote> {
    throw Object.assign(new Error("UNAVAILABLE"), { code: "UNAVAILABLE" as const });
  }
}
