import { type NextRequest, NextResponse } from "next/server.js";
import { functionSelector } from "../../../../../../../../sdk/typescript/src/abi.ts";
import { FUJI_V2 } from "../../../../../../../../sdk/typescript/src/fuji-v2-defaults.ts";
import { validateOrigin } from "../../_lib.ts";

// Registry reads and receipts come from a public RPC, not the wallet. A
// wallet's own Fuji RPC can be a load-balanced endpoint whose backends lag
// one another, so a read right after a confirmed membership update could
// return the old root. Only the calls the browser flow needs are allowed.
export const dynamic = "force-dynamic";

const READ_RPC = process.env.HAZE_FUJI_READ_RPC || process.env.HAZE_FUJI_LOGS_RPC || "https://avalanche-fuji-c-chain-rpc.publicnode.com";
const APPLICATION_REGISTRY = (process.env.NEXT_PUBLIC_HAZE_APPLICATION_REGISTRY || FUJI_V2.applicationRegistry).toLowerCase();
const POLICY_REGISTRY = (process.env.NEXT_PUBLIC_HAZE_POLICY_REGISTRY || FUJI_V2.policyRegistry).toLowerCase();
const ALLOWED_CALLS: Record<string, string[]> = {
  [APPLICATION_REGISTRY]: [functionSelector("getApplication(bytes32)")],
  [POLICY_REGISTRY]: [functionSelector("activeVersion()"), functionSelector("activeRoot()")],
};
const HASH = /^0x[0-9a-fA-F]{64}$/;
const HEX = /^0x[0-9a-fA-F]*$/;

function allowedRead(method: unknown, params: unknown): unknown[] | undefined {
  if (!Array.isArray(params)) return undefined;
  if (method === "eth_getTransactionReceipt") {
    return params.length === 1 && typeof params[0] === "string" && HASH.test(params[0]) ? [params[0]] : undefined;
  }
  if (method !== "eth_call") return undefined;
  const call = params[0] as { to?: unknown; data?: unknown } | undefined;
  if (typeof call?.to !== "string" || typeof call.data !== "string" || !HEX.test(call.data)) return undefined;
  const selectors = ALLOWED_CALLS[call.to.toLowerCase()];
  if (!selectors?.some((selector) => call.data === selector || (call.data as string).startsWith(selector))) return undefined;
  return [{ to: call.to, data: call.data }, "latest"];
}

export async function POST(req: NextRequest) {
  if (!validateOrigin(req)) return NextResponse.json({ error: "FORBIDDEN_ORIGIN" }, { status: 403 });
  const body = (await req.json().catch(() => null)) as { method?: unknown; params?: unknown } | null;
  const params = allowedRead(body?.method, body?.params);
  if (!params) return NextResponse.json({ error: "UNSUPPORTED_READ" }, { status: 400 });
  try {
    const res = await fetch(READ_RPC, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: body?.method, params }),
      cache: "no-store",
    });
    const out = (await res.json()) as { result?: unknown; error?: unknown };
    if (!res.ok || out.error) throw new Error(`read rpc HTTP ${res.status}`);
    return NextResponse.json({ result: out.result ?? null }, { headers: { "cache-control": "no-store" } });
  } catch (error) {
    console.error("pool read failed", error);
    return NextResponse.json({ error: "READ_UNAVAILABLE" }, { status: 502 });
  }
}
