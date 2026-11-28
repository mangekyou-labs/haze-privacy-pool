import { type NextRequest, NextResponse } from "next/server.js";
import { FUJI_V2 } from "../../../../../../../../sdk/typescript/src/fuji-v2-defaults.ts";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { addressWord, concatBytes, functionSelector, toHex, uintWord } from "../../../../../../../../sdk/typescript/src/abi.ts";
import { swapRouteHash } from "../../../../../../../../sdk/typescript/src/browser-fuji-contracts.ts";
import fujiV2Manifest from "../../../../../../../../deployments/fuji-v2.live.json" with { type: "json" };
const fujiVenue = (fujiV2Manifest as { venue?: { fujiPilotToken?: string; fujiPilotVenue?: string } }).venue;

const ROUTER = process.env.NEXT_PUBLIC_HAZE_ROUTER || FUJI_V2.router;
const SWAP_EXACT_IN_SELECTOR = functionSelector("swapExactIn(address,uint256,uint256,address)");

function isPlaceholder(addr: string): boolean {
  if (!addr || typeof addr !== "string") return true;
  if (!/^0x[0-9a-f]{40}$/i.test(addr)) return true;
  if (/^0xF0{2,}/i.test(addr)) return true;
  if (addr === "0x0000000000000000000000000000000000000000") return true;
  return false;
}

function getVenueConfig(): { pilotToken: string; pilotVenue: string } {
  const envToken = process.env.HAZE_FUJI_PILOT_TOKEN;
  const envVenue = process.env.HAZE_FUJI_PILOT_VENUE;
  if (envToken && envVenue) {
    return { pilotToken: envToken, pilotVenue: envVenue };
  }
  if (fujiVenue?.fujiPilotToken && fujiVenue?.fujiPilotVenue) {
    return {
      pilotToken: envToken || fujiVenue!.fujiPilotToken,
      pilotVenue: envVenue || fujiVenue!.fujiPilotVenue,
    };
  }
  return { pilotToken: envToken || "", pilotVenue: envVenue || "" };
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    const { tokenIn, amountIn, slippageBps = 50 } = body;

    const config = getVenueConfig();
    if (isPlaceholder(config.pilotToken) || isPlaceholder(config.pilotVenue)) {
      return NextResponse.json(
        {
          code: "SWAP_VENUE_UNAVAILABLE",
          error: "SWAP_VENUE_UNAVAILABLE",
          message: "Fuji pilot swap venue is not configured or uses placeholder addresses.",
        },
        { status: 503 },
      );
    }

    if (!amountIn || typeof amountIn !== "string" || !/^\d+$/.test(amountIn)) {
      return NextResponse.json(
        { code: "BAD_REQUEST", error: "BAD_REQUEST", message: "Valid numeric amountIn string required" },
        { status: 400 },
      );
    }

    const numericIn = BigInt(amountIn);
    if (numericIn <= 0n) {
      return NextResponse.json(
        { code: "BAD_REQUEST", error: "BAD_REQUEST", message: "amountIn must be greater than zero" },
        { status: 400 },
      );
    }

    if (tokenIn && tokenIn.toLowerCase() !== config.pilotToken.toLowerCase()) {
      return NextResponse.json(
        { code: "TOKEN_NOT_ALLOWED", error: "TOKEN_NOT_ALLOWED", message: `tokenIn must be FujiPilotToken (${config.pilotToken})` },
        { status: 400 },
      );
    }

    const rateNumerator = 1n;
    const rateDenominator = 1n;
    const usdcOut = (numericIn * rateNumerator) / rateDenominator;
    const minUsdcOut = (usdcOut * (10000n - BigInt(slippageBps))) / 10000n;
    const deadline = Math.floor(Date.now() / 1000) + 1200; // 20 min

    const data = `${SWAP_EXACT_IN_SELECTOR}${toHex(
      concatBytes(
        addressWord(config.pilotToken),
        uintWord(numericIn),
        uintWord(minUsdcOut),
        addressWord(ROUTER),
      ),
    ).slice(2)}`;

    const calculatedRouteHash = swapRouteHash(config.pilotVenue, data);

    return NextResponse.json({
      tokenIn: config.pilotToken,
      amountIn: String(numericIn),
      amountOut: String(usdcOut),
      usdcOut: String(usdcOut),
      minUsdcOut: String(minUsdcOut),
      deadline,
      routeHash: calculatedRouteHash,
      expectedRouteHash: calculatedRouteHash,
      adapter: config.pilotVenue,
      data,
      venue: "FujiPilotVenue",
      rate: "1:1",
      expiry: deadline,
    });
  } catch {
    return NextResponse.json(
      { code: "QUOTE_FAILED", error: "QUOTE_FAILED", message: "Failed to fetch venue quote" },
      { status: 400 },
    );
  }
}
