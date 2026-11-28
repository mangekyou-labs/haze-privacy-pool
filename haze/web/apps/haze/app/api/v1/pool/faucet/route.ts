import { type NextRequest, NextResponse } from "next/server.js";
import { secp256k1 } from "@noble/curves/secp256k1";
import { addressWord, concatBytes, functionSelector, toHex, uintWord } from "../../../../../../../../sdk/typescript/src/abi.ts";
import { keccak256 } from "../../../../../../../../sdk/typescript/src/keccak.ts";
import { introspectSession, isFixtureMode, requireRole, validateOrigin } from "../../_lib.ts";
import fujiV2Manifest from "../../../../../../../../deployments/fuji-v2.live.json" with { type: "json" };
const fujiVenue = (fujiV2Manifest as { venue?: { fujiPilotToken?: string; fujiPilotVenue?: string } }).venue;

const CHAIN_ID = 43113;
const MINT_AMOUNT_UNITS = 5_000_000n; // 5 PILOT (6 decimals)
const COOLDOWN_MS = 24 * 60 * 60 * 1000; // 24 hours

const MINT_SELECTOR = functionSelector("mint(address,uint256)");
const BALANCE_OF_SELECTOR = functionSelector("balanceOf(address)");

function getPilotToken(): string {
  return (
    process.env.HAZE_FUJI_PILOT_TOKEN ||
    fujiVenue?.fujiPilotToken ||
    "0x4fAB93a23313CC032D8310Cf0f34A9BDF4E19c72"
  );
}

function getMintAuthorityKey(): string | null {
  const key =
    process.env.HAZE_FUJI_MINT_AUTHORITY_KEY ||
    process.env.HAZE_FUJI_POLICY_AUTHORITY_KEY ||
    process.env.PRIVATE_KEY;
  if (!key) return null;
  const clean = key.replace(/^0x/i, "").trim();
  return clean.length === 64 ? clean : null;
}

// In-memory rate limiting map: wallet (lowercase) -> next eligible timestamp (ms)
const faucetCooldowns = new Map<string, number>();

function rlpEncodeItem(item: unknown): Uint8Array {
  if (typeof item === "number" || typeof item === "bigint") {
    const val = BigInt(item);
    if (val === 0n) return new Uint8Array([0x80]);
    let hex = val.toString(16);
    if (hex.length % 2 !== 0) hex = `0${hex}`;
    const bytes = Uint8Array.from(hex.match(/.{2}/g) ?? [], (b) => Number.parseInt(b, 16));
    if (bytes.length === 1 && bytes[0] < 0x80) return bytes;
    if (bytes.length <= 55) return new Uint8Array([0x80 + bytes.length, ...bytes]);
    const lenHex = bytes.length.toString(16);
    const lenBytes = Uint8Array.from((lenHex.length % 2 !== 0 ? `0${lenHex}` : lenHex).match(/.{2}/g) ?? [], (b) => Number.parseInt(b, 16));
    return new Uint8Array([0xb7 + lenBytes.length, ...lenBytes, ...bytes]);
  }
  if (typeof item === "string") {
    const hex = item.replace(/^0x/, "");
    if (hex.length === 0) return new Uint8Array([0x80]);
    const bytes = Uint8Array.from((hex.length % 2 !== 0 ? `0${hex}` : hex).match(/.{2}/g) ?? [], (b) => Number.parseInt(b, 16));
    if (bytes.length === 1 && bytes[0] < 0x80) return bytes;
    if (bytes.length <= 55) return new Uint8Array([0x80 + bytes.length, ...bytes]);
    const lenHex = bytes.length.toString(16);
    const lenBytes = Uint8Array.from((lenHex.length % 2 !== 0 ? `0${lenHex}` : lenHex).match(/.{2}/g) ?? [], (b) => Number.parseInt(b, 16));
    return new Uint8Array([0xb7 + lenBytes.length, ...lenBytes, ...bytes]);
  }
  if (item instanceof Uint8Array) {
    if (item.length === 0) return new Uint8Array([0x80]);
    if (item.length === 1 && item[0] < 0x80) return item;
    if (item.length <= 55) return new Uint8Array([0x80 + item.length, ...item]);
    const lenHex = item.length.toString(16);
    const lenBytes = Uint8Array.from((lenHex.length % 2 !== 0 ? `0${lenHex}` : lenHex).match(/.{2}/g) ?? [], (b) => Number.parseInt(b, 16));
    return new Uint8Array([0xb7 + lenBytes.length, ...lenBytes, ...item]);
  }
  if (Array.isArray(item)) {
    const encodedChildren = item.map((child) => rlpEncodeItem(child));
    const totalLength = encodedChildren.reduce((acc, curr) => acc + curr.length, 0);
    const combined = new Uint8Array(totalLength);
    let offset = 0;
    for (const child of encodedChildren) {
      combined.set(child, offset);
      offset += child.length;
    }
    if (totalLength <= 55) return new Uint8Array([0xc0 + totalLength, ...combined]);
    const lenHex = totalLength.toString(16);
    const lenBytes = Uint8Array.from((lenHex.length % 2 !== 0 ? `0${lenHex}` : lenHex).match(/.{2}/g) ?? [], (b) => Number.parseInt(b, 16));
    return new Uint8Array([0xf7 + lenBytes.length, ...lenBytes, ...combined]);
  }
  return new Uint8Array([0x80]);
}

async function rpcCall(method: string, params: unknown[] = []): Promise<unknown> {
  const rpcUrl = process.env.AVALANCHE_FUJI_RPC || "https://api.avax-test.network/ext/bc/C/rpc";
  const res = await fetch(rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: Date.now(), method, params }),
  });
  if (!res.ok) throw new Error(`RPC_HTTP_ERROR: ${res.status}`);
  const data = await res.json();
  if (data.error) throw new Error(`RPC_ERROR: ${JSON.stringify(data.error)}`);
  return data.result;
}

export async function POST(req: NextRequest) {
  if (!validateOrigin(req)) {
    return NextResponse.json(
      { code: "FORBIDDEN", error: "CSRF_ORIGIN_INVALID", message: "Origin validation failed" },
      { status: 403 },
    );
  }

  const session = await introspectSession(req);
  const authErr = requireRole(session, "pool-user");
  if (authErr || !session) {
    return authErr ?? NextResponse.json(
      { code: "UNAUTHORIZED", error: "UNAUTHORIZED", message: "Authentication required" },
      { status: 401 },
    );
  }
  try {
    const wallet = session.wallet.trim();
    if (!wallet || !/^0x[0-9a-fA-F]{40}$/.test(wallet)) {
      return NextResponse.json(
        {
          code: "INVALID_WALLET",
          error: "INVALID_WALLET",
          message: "Authenticated session wallet must be a valid 20-byte EVM address",
        },
        { status: 400 },
      );
    }

    const normalizedWallet = wallet.toLowerCase();
    const now = Date.now();
    const nextEligible = faucetCooldowns.get(normalizedWallet) || 0;

    if (now < nextEligible && !isFixtureMode()) {
      const remainingMs = nextEligible - now;
      return NextResponse.json(
        {
          code: "RATE_LIMITED",
          error: "RATE_LIMITED",
          message: `Cooldown active. Allowed once every 24 hours. Eligible in ${Math.ceil(remainingMs / 60000)} minutes.`,
          nextEligibleAt: nextEligible,
          cooldownMs: remainingMs,
        },
        { status: 429 },
      );
    }
    const pilotToken = getPilotToken();
    const keyHex = getMintAuthorityKey();

    if (!keyHex) {
      if (isFixtureMode()) {
        const mockHash = `0x${"f0".repeat(32)}`;
        faucetCooldowns.set(normalizedWallet, now + COOLDOWN_MS);
        return NextResponse.json({
          ok: true,
          amount: String(MINT_AMOUNT_UNITS),
          amountFormatted: "5 PILOT",
          hash: mockHash,
          token: pilotToken,
          recipient: wallet,
          resultingBalance: "5000000",
          nextEligibleAt: now + COOLDOWN_MS,
          cooldownSeconds: 86400,
        });
      }
      return NextResponse.json(
        {
          code: "UNAVAILABLE",
          error: "MINT_AUTHORITY_UNAVAILABLE",
          message: "Fuji mint authority is not configured on this host",
        },
        { status: 503 },
      );
    }

    const privKeyBytes = Uint8Array.from(keyHex.match(/.{2}/g) ?? [], (b) => Number.parseInt(b, 16));
    const pubKey = secp256k1.getPublicKey(privKeyBytes, false);
    const senderAddress = `0x${toHex(keccak256(pubKey.slice(1))).slice(-40)}`;

    const txData = `${MINT_SELECTOR}${addressWord(wallet)}${uintWord(MINT_AMOUNT_UNITS)}`;

    // Build and sign transaction
    const nonceHex = (await rpcCall("eth_getTransactionCount", [senderAddress, "pending"])) as string;
    const nonce = Number.parseInt(nonceHex, 16);
    const gasPriceHex = (await rpcCall("eth_gasPrice", [])) as string;
    const gasPrice = BigInt(gasPriceHex || "0x5d21dba00");
    const maxPriorityFeePerGas = 1500000000n;
    const maxFeePerGas = gasPrice > 25000000000n ? gasPrice * 2n : 35000000000n;
    const gasLimit = 120000n;

    const txFields = [
      CHAIN_ID,
      nonce,
      maxPriorityFeePerGas,
      maxFeePerGas,
      gasLimit,
      pilotToken,
      0n,
      txData,
      [],
    ];

    const rlp = rlpEncodeItem(txFields);
    const payloadToSign = new Uint8Array(1 + rlp.length);
    payloadToSign[0] = 0x02;
    payloadToSign.set(rlp, 1);
    const digest = keccak256(payloadToSign);

    const sig = secp256k1.sign(digest, privKeyBytes, { prehash: false });
    const signedFields = [
      ...txFields,
      sig.recovery,
      sig.r,
      sig.s,
    ];
    const signedRlp = rlpEncodeItem(signedFields);
    const rawTx = new Uint8Array(1 + signedRlp.length);
    rawTx[0] = 0x02;
    rawTx.set(signedRlp, 1);
    const rawTxHex = toHex(rawTx);

    const txHash = (await rpcCall("eth_sendRawTransaction", [rawTxHex])) as string;

    // Record cooldown timestamp
    const nextEligibleAt = now + COOLDOWN_MS;
    faucetCooldowns.set(normalizedWallet, nextEligibleAt);

    // Read resulting balance
    let resultingBalance = "5000000";
    try {
      const balanceData = `${BALANCE_OF_SELECTOR}${addressWord(wallet)}`;
      const balanceHex = (await rpcCall("eth_call", [{ to: pilotToken, data: balanceData }, "latest"])) as string;
      resultingBalance = BigInt(balanceHex || "0x0").toString();
    } catch {}

    return NextResponse.json({
      ok: true,
      amount: String(MINT_AMOUNT_UNITS),
      amountFormatted: "5 PILOT",
      hash: txHash,
      token: pilotToken,
      recipient: wallet,
      resultingBalance,
      nextEligibleAt,
      cooldownSeconds: 86400,
    });
  } catch (error) {
    return NextResponse.json(
      {
        code: "MINT_FAILED",
        error: error instanceof Error ? error.message : "MINT_FAILED",
      },
      { status: 500 },
    );
  }
}
