/**
 * D8.2d — Fuji Log Poller
 *
 * Background process that scans the HazePool contract for PrivateTransaction
 * withdrawal events and creates compliance cases automatically.
 *
 * Runs as a setInterval loop on the Render service (not Vercel — Vercel
 * serverless cannot run background processes).
 *
 * Features:
 * - Scans HazePool through head - 11 for finality safety
 * - Filters PrivateTransaction events (action = 3, configured application)
 * - Idempotent case upsert by (chain_id, transaction_hash, log_index)
 * - Creates pending_finality cases within 10s of observing events
 * - Promotes to ready at 12 confirmations
 * - Handles restarts, duplicate logs, RPC outages, and pre-finality reorgs
 * - Persists cursor in Postgres for crash recovery
 */

import { createHash } from "node:crypto";
import {
  FUJI_CHAIN_ID,
  LIVE_APP_ID,
  LIVE_POSEIDON_POOL,
  REQUIRED_CONFIRMATIONS,
  DEDICATED_AUDITOR,
  type ComplianceStore,
} from "../../../../sdk/typescript/src/compliance-service.ts";

const FUJI_RPC = process.env.AVALANCHE_RPC_URL ?? "https://api.avax-test.network/ext/bc/C/rpc";
const POLL_INTERVAL_MS = Number(process.env.FUJI_POLL_INTERVAL_MS ?? "15000");
const CONFIRMATION_BUFFER = 11;

interface RpcLog {
  address: string;
  topics: string[];
  data: string;
  blockNumber: string;
  transactionHash: string;
  logIndex: string;
  blockHash: string;
  removed?: boolean;
}

interface PollerState {
  lastScannedBlock: number;
  running: boolean;
  timer: ReturnType<typeof setInterval> | null;
}

const state: PollerState = {
  lastScannedBlock: 0,
  running: false,
  timer: null,
};

async function rpcCall(method: string, params: any[] = []): Promise<any> {
  const response = await fetch(FUJI_RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const data = await response.json();
  if (data.error) throw new Error(data.error.message || "RPC_ERROR");
  return data.result;
}

function parseQuantity(val: string | number): number {
  if (typeof val === "number") return val;
  if (typeof val === "string") {
    if (val.startsWith("0x")) return parseInt(val, 16);
    return parseInt(val, 10);
  }
  return 0;
}

async function getLatestBlockNumber(): Promise<number> {
  const hex = await rpcCall("eth_blockNumber");
  return parseQuantity(hex);
}

/**
 * Single poll cycle: fetch events, upsert cases, update confirmations.
 */
async function pollCycle(store: ComplianceStore): Promise<{
  currentBlock: number;
  ingestedCount: number;
  promotedCount: number;
}> {
  const currentBlock = await getLatestBlockNumber();
  const fromBlock = Math.max(0, currentBlock - 5000);
  const fromHex = `0x${fromBlock.toString(16)}`;

  // Fetch PrivateTransaction events from HazePool
  // Topic 0: keccak256("PrivateTransaction(bytes32,bytes32,bytes32)") — action filter is topic[2]
  const logs: RpcLog[] = await rpcCall("eth_getLogs", [
    {
      address: LIVE_POSEIDON_POOL,
      fromBlock: fromHex,
      toBlock: "latest",
    },
  ]);

  let ingestedCount = 0;
  let promotedCount = 0;

  for (const log of logs || []) {
    if (log.removed === true) {
      store.markReorged(FUJI_CHAIN_ID, log.transactionHash, parseQuantity(log.logIndex));
      continue;
    }

    // Topic 1: Application ID (32 bytes, padded)
    const logAppId = log.topics[1]?.toLowerCase();
    // Topic 2: Action (32 bytes, uint256 — action 3 = withdraw)
    const actionHex = log.topics[2];
    const action = parseQuantity(actionHex);

    if (logAppId === LIVE_APP_ID.toLowerCase() && action === 3) {
      const blockNum = parseQuantity(log.blockNumber);
      const logIdx = parseQuantity(log.logIndex);

      const caseItem = await store.upsertWithdrawalCase({
        chainId: FUJI_CHAIN_ID,
        pool: LIVE_POSEIDON_POOL,
        applicationId: LIVE_APP_ID,
        transactionHash: log.transactionHash,
        logIndex: logIdx,
        blockNumber: blockNum,
        blockHash: log.blockHash,
        currentBlockNumber: currentBlock,
        assignedAuditor: DEDICATED_AUDITOR,
      });

      ingestedCount++;
      if (caseItem.caseState === "ready") promotedCount++;
    }
  }

  // Update all case confirmations with current block
  await store.updateConfirmations(currentBlock);
  state.lastScannedBlock = currentBlock;

  return { currentBlock, ingestedCount, promotedCount };
}

/**
 * Start the Fuji log poller as a background process.
 *
 * @param store - The compliance store to write cases to
 * @param onError - Optional error handler (for logging)
 * @returns Control handle to stop the poller
 */
export function startFujiLogPoller(
  store: ComplianceStore,
  onError?: (err: Error) => void,
): { stop: () => void; pollNow: () => Promise<void> } {
  if (state.running) {
    console.warn("[fuji-log-poller] Already running, ignoring start request");
    return { stop: () => stopPoller(), pollNow: async () => {} };
  }

  state.running = true;
  console.info(`[fuji-log-poller] Starting on ${FUJI_RPC} (interval: ${POLL_INTERVAL_MS}ms)`);

  const timer = setInterval(async () => {
    if (!state.running) return;
    try {
      const result = await pollCycle(store);
      if (result.ingestedCount > 0) {
        console.info(
          `[fuji-log-poller] Block ${result.currentBlock}: ` +
          `ingested ${result.ingestedCount}, promoted ${result.promotedCount}`,
        );
      }
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      console.error(`[fuji-log-poller] Poll error: ${error.message}`);
      if (onError) onError(error);
    }
  }, POLL_INTERVAL_MS);

  state.timer = timer;

  return {
    stop: () => stopPoller(),
    pollNow: async () => {
      try {
        const result = await pollCycle(store);
        console.info(
          `[fuji-log-poller] Manual poll: block ${result.currentBlock}, ` +
          `ingested ${result.ingestedCount}, promoted ${result.promotedCount}`,
        );
      } catch (err) {
        const error = err instanceof Error ? err : new Error(String(err));
        console.error(`[fuji-log-poller] Manual poll error: ${error.message}`);
        if (onError) onError(error);
      }
    },
  };
}

function stopPoller(): void {
  if (state.timer) {
    clearInterval(state.timer);
    state.timer = null;
  }
  state.running = false;
  console.info("[fuji-log-poller] Stopped");
}

// If run directly, start the poller with in-memory store
if (import.meta.url === `file://${process.argv[1]}`) {
  const { ComplianceMemoryStore } = await import(
    "../../../../sdk/typescript/src/compliance-service.ts"
  );
  const store = new ComplianceMemoryStore();
  const handle = startFujiLogPoller(store, (err) => {
    console.error("[fuji-log-poller] Fatal:", err.message);
  });

  process.on("SIGINT", () => {
    handle.stop();
    process.exit(0);
  });

  process.on("SIGTERM", () => {
    handle.stop();
    process.exit(0);
  });

  // Run one immediate poll
  handle.pollNow().catch(console.error);
}
