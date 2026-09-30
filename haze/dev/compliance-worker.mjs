#!/usr/bin/env node
import {
  FUJI_CHAIN_ID,
  LIVE_APP_ID,
  LIVE_POSEIDON_POOL,
  REQUIRED_CONFIRMATIONS,
  globalComplianceStore,
} from "../sdk/typescript/src/compliance-service.ts";
import { PRIVATE_TRANSACTION_TOPIC } from "./operator-circuit-live.mjs";

const FUJI_RPC = process.env.AVALANCHE_RPC_URL ?? "https://api.avax-test.network/ext/bc/C/rpc";

export function parseQuantity(val) {
  if (typeof val === "number") return val;
  if (typeof val === "string") {
    if (val.startsWith("0x")) return Number.parseInt(val, 16);
    return Number.parseInt(val, 10);
  }
  return 0;
}

export async function rpcCall(method, params = []) {
  const response = await fetch(FUJI_RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method,
      params,
    }),
  });
  const data = await response.json();
  if (data.error) {
    throw new Error(data.error.message || "RPC_ERROR");
  }
  return data.result;
}

export async function getLatestBlockNumber() {
  const hex = await rpcCall("eth_blockNumber");
  return parseQuantity(hex);
}

export async function pollFujiWithdrawals(options = {}) {
  const store = options.store ?? globalComplianceStore;
  const pool = options.pool ?? LIVE_POSEIDON_POOL;
  const appId = options.appId ?? LIVE_APP_ID;
  const currentBlock = options.currentBlock ?? (await getLatestBlockNumber());

  // Fetch recent logs
  const fromBlock = options.fromBlock ?? `0x${Math.max(0, currentBlock - 5000).toString(16)}`;
  const logs = await rpcCall("eth_getLogs", [
    {
      address: pool,
      topics: [PRIVATE_TRANSACTION_TOPIC],
      fromBlock,
      toBlock: "latest",
    },
  ]);

  const ingested = [];
  for (const log of logs || []) {
    if (log.removed === true) {
      store.markReorged(FUJI_CHAIN_ID, log.transactionHash, parseQuantity(log.logIndex));
      continue;
    }
    // Topic 1: Application ID
    // Topic 2: Action (3 for withdraw)
    const logAppId = log.topics[1]?.toLowerCase();
    const actionHex = log.topics[2];
    const action = parseQuantity(actionHex);

    if (logAppId === appId.toLowerCase() && action === 3) {
      const blockNum = parseQuantity(log.blockNumber);
      const logIdx = parseQuantity(log.logIndex);
      const caseItem = store.upsertWithdrawalCase({
        chainId: FUJI_CHAIN_ID,
        pool,
        applicationId: appId,
        transactionHash: log.transactionHash,
        logIndex: logIdx,
        blockNumber: blockNum,
        blockHash: log.blockHash,
        currentBlockNumber: currentBlock,
      });
      ingested.push(caseItem);
    }
  }

  store.updateConfirmations(currentBlock);
  return { currentBlock, ingestedCount: ingested.length, cases: ingested };
}

export function startComplianceWorker(options = {}) {
  const intervalMs = options.intervalMs ?? 5000;
  let running = true;

  const timer = setInterval(async () => {
    if (!running) return;
    try {
      await pollFujiWithdrawals(options);
    } catch (err) {
      if (options.onError) options.onError(err);
    }
  }, intervalMs);

  return {
    stop: () => {
      running = false;
      clearInterval(timer);
    },
    pollNow: () => pollFujiWithdrawals(options),
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  console.log(`Starting Fuji compliance ingestion worker against ${FUJI_RPC}...`);
  startComplianceWorker({
    onError: (err) => console.error("Worker error:", err.message),
  });
}
