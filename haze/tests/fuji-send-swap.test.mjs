import assert from "node:assert/strict";
import test from "node:test";
import { addressWord, concatBytes, functionSelector, hexToBuf, toHex, uintWord } from "../sdk/typescript/src/abi.ts";
import { encodeBrowserSwapAndShield, swapRouteHash } from "../sdk/typescript/src/browser-fuji-contracts.ts";
import { keccak256 } from "../sdk/typescript/src/keccak.ts";

test("swapRouteHash matches Solidity keccak256(abi.encode(address, bytes))", () => {
  const adapter = "0x1111111111111111111111111111111111111111";
  const data = "0x12345678";
  const hash = swapRouteHash(adapter, data);
  assert.ok(/^0x[0-9a-f]{64}$/i.test(hash));

  // Verify direct manual encoding
  const rawData = hexToBuf(data);
  const padding = new Uint8Array((32 - (rawData.length % 32)) % 32);
  const expectedPayload = concatBytes(
    addressWord(adapter),
    uintWord(64),
    uintWord(rawData.length),
    rawData,
    padding,
  );
  const expectedHash = toHex(keccak256(expectedPayload));
  assert.equal(hash, expectedHash);
});

test("FujiPilotVenue swapExactIn calldata produces exact swapRouteHash", () => {
  const venue = "0x2222222222222222222222222222222222222222";
  const tokenIn = "0x3333333333333333333333333333333333333333";
  const router = "0xdb386aeAd1C0b859903702454a7ECDfC306800F6";
  const amountIn = 1_000_000n;
  const minUsdcOut = 995_000n;

  const selector = functionSelector("swapExactIn(address,uint256,uint256,address)");
  const data = `${selector}${toHex(
    concatBytes(
      addressWord(tokenIn),
      uintWord(amountIn),
      uintWord(minUsdcOut),
      addressWord(router),
    ),
  ).slice(2)}`;

  const calculatedHash = swapRouteHash(venue, data);
  assert.ok(/^0x[0-9a-f]{64}$/i.test(calculatedHash));
  assert.notEqual(calculatedHash, `0x${"00".repeat(32)}`);
  assert.notEqual(calculatedHash, `0x${"00".repeat(31)}01`);
});

test("quote route returns 503 SWAP_VENUE_UNAVAILABLE on placeholder venue address", async () => {
  const { POST } = await import("../web/apps/haze/app/api/v1/pool/quote/route.ts");
  const prevToken = process.env.HAZE_FUJI_PILOT_TOKEN;
  const prevVenue = process.env.HAZE_FUJI_PILOT_VENUE;
  try {
    process.env.HAZE_FUJI_PILOT_TOKEN = "0xF002000000000000000000000000000000000002";
    process.env.HAZE_FUJI_PILOT_VENUE = "0xF003000000000000000000000000000000000003";
    const req = {
      json: async () => ({ tokenIn: "0xF002000000000000000000000000000000000002", amountIn: "1000000" }),
    };
    const res = await POST(req);
    assert.equal(res.status, 503);
    const body = await res.json();
    assert.equal(body.code, "SWAP_VENUE_UNAVAILABLE");
  } finally {
    if (prevToken) process.env.HAZE_FUJI_PILOT_TOKEN = prevToken; else delete process.env.HAZE_FUJI_PILOT_TOKEN;
    if (prevVenue) process.env.HAZE_FUJI_PILOT_VENUE = prevVenue; else delete process.env.HAZE_FUJI_PILOT_VENUE;
  }
});

test("quote route returns valid routeHash when real venue is configured", async () => {
  const { POST } = await import("../web/apps/haze/app/api/v1/pool/quote/route.ts");
  const prevToken = process.env.HAZE_FUJI_PILOT_TOKEN;
  const prevVenue = process.env.HAZE_FUJI_PILOT_VENUE;
  try {
    const realToken = "0x1111111111111111111111111111111111111111";
    const realVenue = "0x2222222222222222222222222222222222222222";
    process.env.HAZE_FUJI_PILOT_TOKEN = realToken;
    process.env.HAZE_FUJI_PILOT_VENUE = realVenue;

    const req = {
      json: async () => ({ tokenIn: realToken, amountIn: "2000000" }),
    };
    const res = await POST(req);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.amountIn, "2000000");
    assert.equal(body.amountOut, "2000000");
    assert.equal(body.usdcOut, "2000000");
    assert.equal(body.adapter, realVenue);
    assert.equal(body.routeHash, body.expectedRouteHash);
    assert.equal(body.routeHash, swapRouteHash(realVenue, body.data));
  } finally {
    if (prevToken) process.env.HAZE_FUJI_PILOT_TOKEN = prevToken; else delete process.env.HAZE_FUJI_PILOT_TOKEN;
    if (prevVenue) process.env.HAZE_FUJI_PILOT_VENUE = prevVenue; else delete process.env.HAZE_FUJI_PILOT_VENUE;
  }
});

test("quote route returns 200 with deployed sidecar venue config", async () => {
  const { POST } = await import("../web/apps/haze/app/api/v1/pool/quote/route.ts");
  const prevToken = process.env.HAZE_FUJI_PILOT_TOKEN;
  const prevVenue = process.env.HAZE_FUJI_PILOT_VENUE;
  try {
    delete process.env.HAZE_FUJI_PILOT_TOKEN;
    delete process.env.HAZE_FUJI_PILOT_VENUE;

    const req = {
      json: async () => ({ tokenIn: "0x4fAB93a23313CC032D8310Cf0f34A9BDF4E19c72", amountIn: "1000000" }),
    };
    const res = await POST(req);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.adapter, "0x30d94144722582BCDbcB030dDa274d9CE7ab4baB");
    assert.equal(body.amountIn, "1000000");
    assert.equal(body.usdcOut, "1000000");
  } finally {
    if (prevToken) process.env.HAZE_FUJI_PILOT_TOKEN = prevToken; else delete process.env.HAZE_FUJI_PILOT_TOKEN;
    if (prevVenue) process.env.HAZE_FUJI_PILOT_VENUE = prevVenue; else delete process.env.HAZE_FUJI_PILOT_VENUE;
  }
});

test("quote route calculates minUsdcOut based on slippageBps", async () => {
  const { POST } = await import("../web/apps/haze/app/api/v1/pool/quote/route.ts");
  const req = {
    json: async () => ({
      tokenIn: "0x4fAB93a23313CC032D8310Cf0f34A9BDF4E19c72",
      amountIn: "1000000",
      slippageBps: 100, // 1%
    }),
  };
  const res = await POST(req);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.amountIn, "1000000");
  assert.equal(body.usdcOut, "1000000");
  assert.equal(body.minUsdcOut, "990000"); // 1% off 1_000_000
});

test("FujiBrowserClient source defines labeled action rows: Asset, Amount, Shielded Balance, Network", async () => {
  const { readFileSync } = await import("node:fs");
  const { fileURLToPath } = await import("node:url");
  const { dirname, resolve } = await import("node:path");
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const source = readFileSync(resolve(root, "web/apps/haze/app/[route]/fuji-browser-client.tsx"), "utf8");

  // Verify labeled rows are present in the component source
  assert.match(source, /Asset/);
  assert.match(source, /Shielded Balance/);
  assert.match(source, /Network/);
  assert.match(source, /data-row="asset"/);
  assert.match(source, /data-row="shielded-balance"/);
  assert.match(source, /data-row="network"/);
  assert.match(source, /data-network-badge="testnet"/);
  assert.match(source, /data-balance="shielded"/);
});

test("FujiBrowserClient source handles Swap Quote and Slippage rows and Fuji Pilot copy", async () => {
  const { readFileSync } = await import("node:fs");
  const { fileURLToPath } = await import("node:url");
  const { dirname, resolve } = await import("node:path");
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const source = readFileSync(resolve(root, "web/apps/haze/app/[route]/fuji-browser-client.tsx"), "utf8");

  // Swap rows
  assert.match(source, /data-row="quote"/);
  assert.match(source, /data-row="slippage"/);
  assert.match(source, /Fuji Pilot/);
  assert.match(source, /test.*swapped 1:1 into USDC/i);
  assert.match(source, /PILOT/);
  assert.match(source, /Swap \$\{amount\} PILOT/);
  assert.match(source, /INSUFFICIENT_PILOT/);
  assert.match(source, /amountIn: string; usdcOut: string; minUsdcOut: string/);
  assert.match(source, /value: quote\.usdcOut/);
});

test("FujiBrowserClient source handles Send haze1 copy and empty-note CTA", async () => {
  const { readFileSync } = await import("node:fs");
  const { fileURLToPath } = await import("node:url");
  const { dirname, resolve } = await import("node:path");
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const source = readFileSync(resolve(root, "web/apps/haze/app/[route]/fuji-browser-client.tsx"), "utf8");

  assert.match(source, /data-haze-address/);
  assert.match(source, /haze-address-copy/);
  assert.match(source, /haze-empty-note/);
  assert.match(source, /Recipient haze1/);
  assert.match(source, /buildSealedBrowserTransferWitness/);
});

test("FujiBrowserClient reloads vault notes when vaultGeneration flips after silent resume", async () => {
  const { readFileSync } = await import("node:fs");
  const { fileURLToPath } = await import("node:url");
  const { dirname, resolve } = await import("node:path");
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const source = readFileSync(resolve(root, "web/apps/haze/app/[route]/fuji-browser-client.tsx"), "utf8");

  assert.match(source, /vaultReady/);
  assert.match(source, /vaultGeneration/);
  assert.match(source, /loadVaultNotes/);
  const deps = source.match(/\}, \[([^\]]*)\]/g) || [];
  assert.ok(
    deps.some((block) => block.includes("vaultGeneration")),
    "load/recover effects must depend on vaultGeneration so silent resume retriggers after openVault",
  );
  assert.match(source, /Restoring vault|Recovering operations from Fuji/);
  assert.match(source, /haze-history-card/);
  assert.match(source, /data-haze-address=\{myHazeAddress\}/);
  assert.match(source, /recovering/);
  assert.match(source, /Recovering operations from Fuji/);
  assert.match(source, /!vaultReady\s*\|\|\s*recovering/);
  assert.doesNotMatch(source, /void recover\(/);
});

test("POST /api/v1/pool/faucet rejects unauthenticated or invalid requests", async () => {
  const { POST } = await import("../web/apps/haze/app/api/v1/pool/faucet/route.ts");

  // Invalid origin
  const badOriginReq = {
    method: "POST",
    headers: new Headers({ origin: "http://malicious-site.com" }),
  };
  const badOriginRes = await POST(badOriginReq);
  assert.equal(badOriginRes.status, 403);

  // Unauthenticated request (no session cookie)
  const unauthReq = {
    method: "POST",
    headers: new Headers({ origin: "http://127.0.0.1:3010", host: "127.0.0.1:3010" }),
  };
  const unauthRes = await POST(unauthReq);
  assert.equal(unauthRes.status, 401);
});

test("POST /api/v1/pool/faucet issues 5 PILOT to authenticated session wallet and rate-limits", async () => {
  const { POST } = await import("../web/apps/haze/app/api/v1/pool/faucet/route.ts");
  const { createChallengeBFF, verifyChallengeBFF, FUJI_SESSION_COOKIE, DEFAULT_APPLICATION_ID } = await import("../web/apps/haze/app/api/v1/_lib.ts");
  const prevFixture = process.env.HAZE_FIXTURE_MODE;
  try {
    process.env.HAZE_FIXTURE_MODE = "true";
    const testWallet = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

    // Create authenticated session
    const challenge = await createChallengeBFF(testWallet, DEFAULT_APPLICATION_ID, "pool-user");
    const { token } = await verifyChallengeBFF(challenge.challengeId, challenge.message, "0x" + "11".repeat(65));

    const req1 = {
      method: "POST",
      headers: new Headers({
        origin: "http://127.0.0.1:3010",
        host: "127.0.0.1:3010",
        cookie: `${FUJI_SESSION_COOKIE}=${token}`,
      }),
    };
    const res1 = await POST(req1);
    assert.equal(res1.status, 200);
    const body1 = await res1.json();
    assert.equal(body1.ok, true);
    assert.equal(body1.amount, "5000000");
    assert.equal(body1.amountFormatted, "5 PILOT");
    assert.equal(body1.recipient.toLowerCase(), testWallet.toLowerCase());
    assert.ok(body1.hash);
    assert.ok(body1.nextEligibleAt > Date.now());
  } finally {
    if (prevFixture) process.env.HAZE_FIXTURE_MODE = prevFixture; else delete process.env.HAZE_FIXTURE_MODE;
  }
});
