import { type NextRequest, NextResponse } from "next/server.js";
import { FUJI_V2 } from "../../../../../../../../sdk/typescript/src/fuji-v2-defaults.ts";
import { PRIVATE_TRANSACTION_TOPIC } from "../../../../../../../../sdk/typescript/src/fuji-reconciliation.ts";
import { createChunkedLogReader } from "../../../../../../../../sdk/typescript/src/chunked-logs.ts";
import { DEFAULT_APPLICATION_ID, validateOrigin } from "../../_lib.ts";

// The browser cannot read pool history itself: Fuji's public RPC and
// MetaMask cap eth_getLogs at 100 blocks, and the public RPC also allows only
// a few calls a minute. This route reads the pool's PrivateTransaction logs
// from the deploy block in large windows on an RPC that allows them, and
// caches them so later calls only fetch new blocks.
export const maxDuration = 60;
export const dynamic = "force-dynamic";

const POOL = (process.env.NEXT_PUBLIC_HAZE_POOL || FUJI_V2.pool).toLowerCase();
const LOGS_RPC = process.env.HAZE_FUJI_LOGS_RPC || "https://avalanche-fuji-c-chain-rpc.publicnode.com";
const LOGS_CHUNK = Number(process.env.HAZE_FUJI_LOGS_CHUNK) || 50_000;

async function rpc(method: string, params: unknown[]): Promise<unknown> {
  const res = await fetch(LOGS_RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`logs rpc HTTP ${res.status}`);
  const body = (await res.json()) as { result?: unknown; error?: { message?: string } };
  if (body.error) throw new Error(`logs rpc: ${body.error.message ?? JSON.stringify(body.error)}`);
  return body.result;
}

const reader = createChunkedLogReader({ rpc, startBlock: FUJI_V2.deploymentBlock, chunkSize: LOGS_CHUNK, concurrency: 4 });

export async function GET(req: NextRequest) {
  if (!validateOrigin(req)) return NextResponse.json({ error: "FORBIDDEN_ORIGIN" }, { status: 403 });
  const address = (req.nextUrl.searchParams.get("address") || POOL).toLowerCase();
  if (address !== POOL) return NextResponse.json({ error: "UNSUPPORTED_POOL" }, { status: 400 });
  try {
    const logs = await reader.read({ address: POOL, topics: [PRIVATE_TRANSACTION_TOPIC, DEFAULT_APPLICATION_ID] });
    return NextResponse.json({ logs }, { headers: { "cache-control": "no-store" } });
  } catch (error) {
    console.error("pool logs read failed", error);
    return NextResponse.json({ error: "LOGS_UNAVAILABLE" }, { status: 502 });
  }
}
