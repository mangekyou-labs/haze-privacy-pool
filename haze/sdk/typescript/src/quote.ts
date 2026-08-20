import { keccakHex } from "./abi.ts";
import { SdkError } from "./errors.ts";
import type { SwapQuoteRequest } from "./providers.ts";
import { routeHash } from "./router.ts";

/** Provider-neutral swap quote bound into a Haze intent. */
export type HazeSwapQuote = {
  tokenIn: string;
  usdcOut: string;
  minUsdcOut: string;
  adapter: string;
  routeHash: string;
  calldataHash: string;
  expiry: number;
  gasEstimate: number;
};

export interface QuoteAdapter {
  quote(request: SwapQuoteRequest): Promise<HazeSwapQuote>;
}

/** Fixed quote used by tests and fail-closed local development. */
export function createStaticQuoteAdapter(config: {
  usdcOut: string;
  adapter: string;
  data: string;
  gasEstimate: number;
}): QuoteAdapter {
  return {
    async quote(request) {
      if (BigInt(config.usdcOut) < BigInt(request.minUsdcOut)) {
        throw new SdkError("QUOTE_STALE");
      }
      const payload = config.data.startsWith("0x") ? config.data.slice(2) : config.data;
      return {
        tokenIn: request.tokenIn,
        usdcOut: config.usdcOut,
        minUsdcOut: request.minUsdcOut,
        adapter: config.adapter,
        routeHash: routeHash(config.adapter, config.data),
        calldataHash: keccakHex(Buffer.from(payload, "hex")),
        expiry: request.deadline,
        gasEstimate: config.gasEstimate,
      };
    },
  };
}

/** Quote source that is down. */
export function createUnavailableQuoteAdapter(): QuoteAdapter {
  return {
    async quote() {
      throw new SdkError("UNAVAILABLE");
    },
  };
}
