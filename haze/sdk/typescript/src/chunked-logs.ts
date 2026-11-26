// Reads eth_getLogs over a long block range on RPCs that cap each request
// (Fuji public RPC and MetaMask both reject ranges over 100 blocks).
// The range is split into windows, fetched with bounded concurrency and
// retries, and cached per filter so later reads only fetch new blocks.

export type LogRpc = (method: string, params: unknown[]) => Promise<unknown>;
export type LogFilter = { address: string; topics: (string | null)[] };
export type RpcLog = { blockNumber?: string; logIndex?: string; [key: string]: unknown };

export function blockWindows(from: number, to: number, size: number): [number, number][] {
  const windows: [number, number][] = [];
  for (let start = from; start <= to; start += size) windows.push([start, Math.min(start + size - 1, to)]);
  return windows;
}

const hex = (n: number) => `0x${n.toString(16)}`;

export function createChunkedLogReader(options: {
  rpc: LogRpc;
  startBlock: number;
  chunkSize?: number;
  concurrency?: number;
  retries?: number;
}) {
  const chunkSize = options.chunkSize ?? 100;
  const concurrency = options.concurrency ?? 8;
  const retries = options.retries ?? 3;
  const cache = new Map<string, { toBlock: number; logs: RpcLog[] }>();
  const inflight = new Map<string, Promise<RpcLog[]>>();

  async function fetchWindow(filter: LogFilter, from: number, to: number): Promise<RpcLog[]> {
    let lastError: unknown;
    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        const logs = await options.rpc("eth_getLogs", [{ address: filter.address, topics: filter.topics, fromBlock: hex(from), toBlock: hex(to) }]);
        if (!Array.isArray(logs)) throw new Error("eth_getLogs returned a non-array result");
        return logs as RpcLog[];
      } catch (error) {
        lastError = error;
      }
    }
    throw lastError instanceof Error ? lastError : new Error(`eth_getLogs failed: ${JSON.stringify(lastError)}`);
  }

  async function fetchRange(filter: LogFilter, from: number, to: number): Promise<RpcLog[]> {
    const windows = blockWindows(from, to, chunkSize);
    const results: RpcLog[][] = new Array(windows.length);
    let next = 0;
    const worker = async () => {
      while (next < windows.length) {
        const index = next++;
        const [start, end] = windows[index];
        results[index] = await fetchWindow(filter, start, end);
      }
    };
    await Promise.all(Array.from({ length: Math.min(concurrency, windows.length) }, worker));
    return results.flat();
  }

  async function readUncached(key: string, filter: LogFilter): Promise<RpcLog[]> {
    const head = Number(BigInt(await options.rpc("eth_blockNumber", []) as string));
    const cached = cache.get(key);
    const from = cached ? cached.toBlock + 1 : options.startBlock;
    const fresh = from <= head ? await fetchRange(filter, from, head) : [];
    const logs = [...(cached?.logs ?? []), ...fresh];
    cache.set(key, { toBlock: Math.max(head, cached?.toBlock ?? from - 1), logs });
    return logs;
  }

  return {
    read(filter: LogFilter): Promise<RpcLog[]> {
      const key = JSON.stringify([filter.address.toLowerCase(), filter.topics.map((t) => t?.toLowerCase() ?? null)]);
      const pending = inflight.get(key);
      if (pending) return pending;
      const promise = readUncached(key, filter).finally(() => inflight.delete(key));
      inflight.set(key, promise);
      return promise;
    },
  };
}
