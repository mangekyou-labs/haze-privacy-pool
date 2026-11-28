import { NextResponse } from "next/server.js";
import { CHAIN_ID } from "../_lib.ts";
import { addressWord, functionSelector } from "../../../../../../../sdk/typescript/src/abi.ts";
import fujiV2Manifest from "../../../../../../../deployments/fuji-v2.live.json" with { type: "json" };
const fujiVenue = (fujiV2Manifest as { venue?: { fujiPilotToken?: string; fujiPilotVenue?: string } }).venue;

const MIN_VENUE_LIQUIDITY_UNITS = 5_000_000n; // 5 USDC
const USDC = "0x5425890298aed601595a70AB815c96711a31Bc65";
const BALANCE_OF = functionSelector("balanceOf(address)");

export async function GET() {
  const authOrigin = process.env.HAZE_AUTH_ORIGIN;
  let authStatus = "local";
  let authReady = true;

  if (authOrigin) {
    try {
      const res = await fetch(`${authOrigin.replace(/\/+$/, "")}/readyz`, {
        signal: AbortSignal.timeout(3000),
      });
      authReady = res.ok;
      authStatus = res.ok ? "ready" : "unavailable";
    } catch {
      authReady = false;
      authStatus = "unreachable";
    }
  }

  // Venue liquidity check
  const venue = process.env.HAZE_FUJI_PILOT_VENUE || fujiVenue?.fujiPilotVenue;
  let venueLiquidity: bigint | undefined;
  let venueHealthy = true;

  if (venue && /^0x[0-9a-fA-F]{40}$/.test(venue) && !/^0xF0{2,}/i.test(venue) && process.env.NODE_ENV !== "test") {
    try {
      const rpcUrl = process.env.AVALANCHE_FUJI_RPC || "https://api.avax-test.network/ext/bc/C/rpc";
      const res = await fetch(rpcUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "eth_call",
          params: [{ to: USDC, data: `${BALANCE_OF}${addressWord(venue)}` }, "latest"],
        }),
        signal: AbortSignal.timeout(3000),
      });
      if (res.ok) {
        const data = await res.json();
        if (typeof data.result === "string") {
          venueLiquidity = BigInt(data.result || "0x0");
          if (venueLiquidity < MIN_VENUE_LIQUIDITY_UNITS) {
            venueHealthy = false;
          }
        }
      }
    } catch {
      // Non-fatal if RPC fails temporarily during read, unless strictly required
    }
  }

  if (authReady && venueHealthy) {
    return NextResponse.json({
      status: "ready",
      chainId: CHAIN_ID,
      circuitVersion: "spend-v1",
      schemaVersion: 6,
      bff: "healthy",
      auth: authStatus,
      venueLiquidity: venueLiquidity ? venueLiquidity.toString() : undefined,
    });
  }

  return NextResponse.json(
    {
      status: "unavailable",
      chainId: CHAIN_ID,
      bff: "healthy",
      auth: authStatus,
      venueStatus: venueHealthy ? "healthy" : "insufficient_liquidity",
      venueLiquidity: venueLiquidity ? venueLiquidity.toString() : undefined,
    },
    { status: 503 },
  );
}
