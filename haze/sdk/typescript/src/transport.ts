import { SdkError } from "./errors.ts";
import type { ChainRpc } from "./providers.ts";

/** Narrow provider-neutral EVM transport used by SDK bindings. */
export interface EvmTransport extends ChainRpc {
  call(request: { to: string; data: string }): Promise<string>;
  getBlockNumber(): Promise<number>;
}

function selectorOf(data: string): string {
  return data.slice(0, 10).toLowerCase();
}

/** In-memory transport for tests and offline view lookups. */
export function createMemoryTransport(config: {
  chainId: number;
  views?: Record<string, Record<string, string>>;
  blockNumber?: number;
}): EvmTransport {
  const views = new Map<string, Map<string, string>>();
  for (const [address, selectors] of Object.entries(config.views ?? {})) {
    const bySelector = new Map<string, string>();
    for (const [selector, value] of Object.entries(selectors)) {
      bySelector.set(selector.toLowerCase(), value);
    }
    views.set(address.toLowerCase(), bySelector);
  }
  return {
    async chainId() {
      return config.chainId;
    },
    async call(request) {
      const value = views.get(request.to.toLowerCase())?.get(selectorOf(request.data));
      if (value === undefined) {
        throw new SdkError("UNAVAILABLE");
      }
      return value;
    },
    async getBlockNumber() {
      return config.blockNumber ?? 1;
    },
  };
}

/** Fail closed when the bound transport is not the expected chain. */
export async function assertBoundChain(transport: ChainRpc, expected: number): Promise<void> {
  if ((await transport.chainId()) !== expected) {
    throw new SdkError("CHAIN_MISMATCH");
  }
}
