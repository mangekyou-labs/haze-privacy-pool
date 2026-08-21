import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { createCommercialHost } from "../dev/commercial-host.mjs";
import { LOCAL_TEST_SEED, planDappwrightBootstrap } from "../dev/dappwright-bootstrap.mjs";
import { validateQaWalletConfig } from "../dev/setup-metamask.mjs";
import {
  FIXTURE_ACCOUNTS,
  canSignAction,
  createHazeSite,
  failClosedReasons,
  liveDepositAllowed,
  liveOperatorWithdrawAllowed,
  sessionFromAddress,
} from "../web/packages/ui/src/site.ts";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const APP_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

test("commercial site is one origin with pool and compliance nav groups", () => {
  const site = createHazeSite({ role: "pool-user", applicationId: APP_A });
  assert.equal(site.origin, "single");
  assert.deepEqual(
    site.nav.map((item) => item.path),
    ["/swap", "/shield", "/send", "/withdraw", "/history", "/emergency-exit", "/migrate", "/admin", "/audit", "/governance"],
  );
  assert.equal(site.nav.filter((item) => item.group === "pool").length, 7);
  assert.equal(site.nav.filter((item) => item.group === "compliance").length, 3);
});

test("pool-user chrome is a centered DEX card, not a compliance workstation", async () => {
  const { renderHazePage } = await import("../web/packages/ui/src/html.ts");
  const site = createHazeSite({ role: "pool-user", applicationId: APP_A });
  assert.equal(site.homePath(), "/shield");
  const html = renderHazePage(site, "/shield", {
    address: FIXTURE_ACCOUNTS[0].address,
    walletStatus: "connected",
  });
  assert.match(html, /data-chrome="dex"/);
  assert.match(html, /data-card="pool"/);
  assert.match(html, /class="haze-dex-tabs"/);
  assert.match(html, /href="\/shield"/);
  assert.match(html, /href="\/send"/);
  assert.match(html, /href="\/withdraw"/);
  assert.match(html, /haze-token[^>]*>USDC/);
  assert.match(html, /class="haze-amount/);
  assert.match(html, /data-review="public-facts"/);
  assert.match(html, /data-code="KEYS_MISSING"|KEYS_MISSING/);
  assert.doesNotMatch(html, /haze-inspector/);
  assert.doesNotMatch(html, /haze-group-label">Compliance/);
  assert.doesNotMatch(html, /Fail-closed/);
  const published = JSON.parse(readFileSync(join(HAZE_ROOT, "deployments/fuji-v1.json"), "utf8"));
  assert.equal(published.broadcast, false);
  assert.equal(published.spend_prove, "KEYS_MISSING");
});

test("DEX chrome shows public and private USDC, pool backing, and Fuji chip when live", async () => {
  const { renderHazePage } = await import("../web/packages/ui/src/html.ts");
  const theme = readFileSync(join(HAZE_ROOT, "web/packages/ui/src/theme.css"), "utf8");
  const site = createHazeSite({ role: "pool-user", applicationId: APP_A });
  const local = renderHazePage(site, "/shield", {
    address: FIXTURE_ACCOUNTS[0].address,
    walletStatus: "connected",
    publicUsdc: "12.50",
    privateUsdc: "0.00",
    poolUsdc: "0.00",
  });
  assert.match(local, /data-chrome="dex"/);
  assert.match(local, /data-balance="public"/);
  assert.match(local, /data-balance="private"/);
  assert.match(local, /data-pool-usdc/);
  assert.match(local, /12\.50/);
  assert.match(local, /data-network[^>]*>Local · 31337/);
  assert.doesNotMatch(local, /haze-inspector/);
  assert.match(theme, /\.haze-balances/);
  assert.match(theme, /font-variant-numeric:\s*tabular-nums/);
  assert.doesNotMatch(theme, /Inter|#000|#18181b|violet/);

  const live = renderHazePage(site, "/shield", {
    live: true,
    operatorProve: true,
    zkeyExists: true,
    address: FIXTURE_ACCOUNTS[0].address,
    walletStatus: "connected",
    publicUsdc: "11.50",
    privateUsdc: "1.00",
    poolUsdc: "3.00",
  });
  assert.match(live, /data-network[^>]*>Fuji · 43113/);
  assert.match(live, /data-balance="private"[^>]*>[\s\S]*1\.00/);
  assert.match(live, /data-pool-usdc[^>]*>[\s\S]*3\.00/);
  assert.match(live, /data-code="KEYS_MISSING"|KEYS_MISSING/);
  const published = JSON.parse(readFileSync(join(HAZE_ROOT, "deployments/fuji-v1.json"), "utf8"));
  assert.equal(published.broadcast, false);
  assert.equal(published.spend_prove, "KEYS_MISSING");
});

test("wallet address maps to grants; pool-user cannot open /admin", () => {
  const pool = createHazeSite(sessionFromAddress(FIXTURE_ACCOUNTS[0].address, { applicationId: APP_A }));
  assert.equal(pool.session.role, "pool-user");
  assert.equal(pool.decide("/admin").ok, false);
  assert.equal(pool.decide("/admin").code, "FORBIDDEN");
  assert.equal(pool.decide("/shield").ok, true);

  const admin = createHazeSite(sessionFromAddress(FIXTURE_ACCOUNTS[1].address, { applicationId: APP_A }));
  assert.equal(admin.session.role, "application-admin");
  assert.equal(admin.decide("/admin").ok, true);
  assert.equal(admin.decide("/shield").ok, false);
  assert.equal(admin.decide("/shield").code, "FORBIDDEN");
  assert.equal(admin.vaultLocked, true);
});

test("sign stays closed until connected, reviewed, and not KEYS_MISSING on spend", () => {
  assert.equal(
    canSignAction({
      path: "/shield",
      walletStatus: "disconnected",
      reviewed: true,
      role: "pool-user",
      spendProve: "KEYS_MISSING",
    }),
    false,
  );
  assert.equal(
    canSignAction({
      path: "/shield",
      walletStatus: "connected",
      reviewed: false,
      role: "pool-user",
      spendProve: "KEYS_MISSING",
    }),
    false,
  );
  assert.equal(
    canSignAction({
      path: "/swap",
      walletStatus: "connected",
      reviewed: true,
      role: "pool-user",
      spendProve: "KEYS_MISSING",
    }),
    false,
  );
  assert.equal(
    canSignAction({
      path: "/shield",
      walletStatus: "connected",
      reviewed: true,
      role: "pool-user",
      spendProve: "available",
    }),
    true,
  );
});

test("dappwright planner refuses production seeds and fuji-v1 writes", () => {
  const ok = planDappwrightBootstrap({});
  assert.equal(ok.ok, true);
  assert.equal(ok.seed, LOCAL_TEST_SEED);
  assert.equal(ok.launchMetaMask, false);
  assert.equal(ok.accounts.length, 4);
  assert.equal(planDappwrightBootstrap({ seed: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" }).ok, false);
  assert.equal(planDappwrightBootstrap({ writeFujiV1: true }).reason, "FUJI_V1_IMMUTABLE");
  assert.equal(planDappwrightBootstrap({ live: true }).reason, "SIDECAR_MISSING");
});

test("qa wallet config uses the Anvil seed and never reads PRIVATE_KEY", () => {
  const ok = validateQaWalletConfig({});
  assert.equal(ok.ok, true);
  assert.equal(ok.seed, LOCAL_TEST_SEED);
  assert.equal(ok.chainId, 43113);
  assert.equal(ok.usedPrivateKey, false);

  const withOperatorKey = validateQaWalletConfig({
    PRIVATE_KEY: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  });
  assert.equal(withOperatorKey.ok, true);
  assert.equal(withOperatorKey.seed, LOCAL_TEST_SEED);
  assert.equal(withOperatorKey.usedPrivateKey, false);

  assert.equal(
    validateQaWalletConfig({
      METAMASK_SEED_PHRASE: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    }).reason,
    "PRODUCTION_SEED_REFUSED",
  );
  const fuji = validateQaWalletConfig({ AVALANCHE_CHAIN_ID: "43113" });
  assert.equal(fuji.ok, true);
  assert.equal(fuji.chainId, 43113);
  assert.equal(fuji.symbol, "AVAX");
  assert.equal(validateQaWalletConfig({ AVALANCHE_CHAIN_ID: "43114" }).reason, "MAINNET_REFUSED");
  const anvil = validateQaWalletConfig({ AVALANCHE_CHAIN_ID: "31337" });
  assert.equal(anvil.ok, true);
  assert.equal(anvil.chainId, 31337);
});

test("spend routes stay fail-closed and live deposit is shield-only", () => {
  const reasons = failClosedReasons({
    broadcast: false,
    spendProve: "KEYS_MISSING",
  });
  assert.ok(reasons.includes("broadcast:false"));
  assert.ok(reasons.includes("KEYS_MISSING"));
  assert.equal(liveDepositAllowed({ path: "/shield", live: true, sidecarBroadcast: true }), true);
  assert.equal(liveDepositAllowed({ path: "/swap", live: true, sidecarBroadcast: true }), false);
  assert.equal(liveDepositAllowed({ path: "/shield", live: false, sidecarBroadcast: true }), false);
  assert.equal(
    liveOperatorWithdrawAllowed({
      path: "/withdraw",
      live: true,
      operatorProve: true,
      zkeyExists: true,
    }),
    true,
  );
  assert.equal(
    liveOperatorWithdrawAllowed({
      path: "/withdraw",
      live: true,
      operatorProve: false,
      zkeyExists: true,
    }),
    false,
  );
  assert.equal(
    liveOperatorWithdrawAllowed({
      path: "/withdraw",
      live: true,
      operatorProve: true,
      zkeyExists: false,
    }),
    false,
  );
  assert.equal(
    liveOperatorWithdrawAllowed({
      path: "/send",
      live: true,
      operatorProve: true,
      zkeyExists: true,
    }),
    false,
  );
  assert.equal(
    canSignAction({
      path: "/withdraw",
      walletStatus: "connected",
      reviewed: true,
      role: "pool-user",
      spendProve: "KEYS_MISSING",
      live: true,
      operatorProve: true,
      zkeyExists: true,
    }),
    true,
  );
  assert.equal(
    canSignAction({
      path: "/send",
      walletStatus: "connected",
      reviewed: true,
      role: "pool-user",
      spendProve: "KEYS_MISSING",
      live: true,
      operatorProve: true,
      zkeyExists: true,
    }),
    false,
  );
  assert.throws(
    () =>
      liveOperatorWithdrawAllowed({
        path: "/withdraw",
        live: true,
        operatorProve: true,
        zkeyExists: true,
        productionCeremonyApproved: true,
      }),
    (error) => error.code === "KEYS_MISSING",
  );
  assert.throws(
    () =>
      liveOperatorWithdrawAllowed({
        path: "/withdraw",
        live: true,
        operatorProve: true,
        zkeyExists: true,
        writeCommittedFuji: true,
      }),
    (error) => error.code === "SC-09",
  );
});

test("live shield planner builds wallet approve and typed-data without flipping fuji-v1", async () => {
  const { planLiveShieldDeposit, encodeLiveDeposit } = await import("../web/packages/ui/src/live-deposit.ts");
  const overlay = JSON.parse(readFileSync(join(HAZE_ROOT, "deployments/fuji-v1.live.json"), "utf8"));
  const denied = planLiveShieldDeposit({
    path: "/swap",
    live: true,
    sidecar: overlay,
    user: "0x1111111111111111111111111111111111111111",
    amount: 1_000_000,
    now: 1_700_000_000,
    snapshot: {
      membershipVersion: 1,
      membershipRoot: `0x${"11".repeat(32)}`,
      hazePolicyVersion: 1,
      hazeBlocklistRoot: `0x${"22".repeat(32)}`,
    },
  });
  assert.equal(denied.allowed, false);

  const plan = planLiveShieldDeposit({
    path: "/shield",
    live: true,
    sidecar: overlay,
    user: "0x1111111111111111111111111111111111111111",
    amount: 1_000_000,
    now: 1_700_000_000,
    snapshot: {
      membershipVersion: 1,
      membershipRoot: `0x${"11".repeat(32)}`,
      hazePolicyVersion: 1,
      hazeBlocklistRoot: `0x${"22".repeat(32)}`,
    },
  });
  assert.equal(plan.allowed, true);
  assert.equal(plan.chainId, 43113);
  assert.equal(plan.approve.to.toLowerCase(), overlay.usdc.toLowerCase());
  assert.match(plan.approve.data, /^0x095ea7b3/);
  assert.equal(plan.typedData.primaryType, "ApplicationAuthorization");
  assert.equal(plan.typedData.domain.chainId, 43113);
  const authFields = plan.typedData.types.ApplicationAuthorization;
  assert.equal(authFields[0].name, "applicationId");
  assert.equal(authFields[0].type, "bytes32");
  assert.ok(authFields.every((field) => /^\S+$/.test(field.name)));
  assert.ok(authFields.every((field) => field.name in plan.typedData.message));
  assert.deepEqual(plan.typedData.types.EIP712Domain, [
    { name: "name", type: "string" },
    { name: "version", type: "string" },
    { name: "chainId", type: "uint256" },
    { name: "verifyingContract", type: "address" },
  ]);
  assert.equal(plan.typedData.domain.name, "Haze Avalanche Compliant Pool");
  assert.equal(plan.typedData.domain.version, "1");

  const { snapshotFromChainReturns } = await import("../web/packages/ui/src/live-deposit.ts");
  const word = (value) => value.toString(16).padStart(64, "0");
  const decoded = snapshotFromChainReturns(
    `0x${word(32)}${word(0xa1)}${word(0)}${word(0)}${word(0)}${word(0x11)}${word(1)}`,
    `0x${word(1)}`,
    `0x${word(0x44)}`,
  );
  assert.equal(decoded.membershipRoot, `0x${word(0x11)}`);
  assert.equal(decoded.membershipVersion, 1);
  assert.equal(decoded.hazePolicyVersion, 1);
  assert.equal(decoded.hazeBlocklistRoot, `0x${word(0x44)}`);
  const encoded = encodeLiveDeposit({
    plan,
    signature: `0x${"ab".repeat(65)}`,
  });
  assert.equal(encoded.to.toLowerCase(), overlay.addresses.HazePool.toLowerCase());
  assert.match(encoded.data, /^0x/);
  assert.ok(encoded.data.length > 10);

  const published = JSON.parse(readFileSync(join(HAZE_ROOT, "deployments/fuji-v1.json"), "utf8"));
  assert.equal(published.broadcast, false);
});

test("committed fuji-v1 provenance is not flipped by the commercial app", () => {
  const published = JSON.parse(readFileSync(join(HAZE_ROOT, "deployments/fuji-v1.json"), "utf8"));
  assert.equal(published.broadcast, false);
  assert.equal(published.spend_prove, "KEYS_MISSING");
  assert.equal(existsSync(join(HAZE_ROOT, "web/apps/haze/package.json")), true);
});

test("commercial host serves both products on one origin", async () => {
  const host = await createCommercialHost({ port: 0 });
  try {
    const pool = await fetch(new URL(`/shield?address=${FIXTURE_ACCOUNTS[0].address}`, host.url));
    const poolHtml = await pool.text();
    assert.equal(pool.status, 200);
    assert.match(poolHtml, /data-origin="single"/);
    assert.match(poolHtml, /data-chrome="dex"/);
    assert.match(poolHtml, /data-card="pool"/);
    assert.match(poolHtml, /aria-label="Pool"/);
    assert.doesNotMatch(poolHtml, /haze-group-label">Compliance/);
    assert.doesNotMatch(poolHtml, /haze-inspector/);
    assert.match(poolHtml, /IBM Plex Sans/);
    assert.match(poolHtml, /data-review="public-facts"/);
    assert.match(poolHtml, /Connect wallet|data-address=/);
    assert.doesNotMatch(poolHtml, /<select name="role"/);
    assert.doesNotMatch(poolHtml, /name="ack-/);
    assert.doesNotMatch(poolHtml, /#000/);
    assert.doesNotMatch(poolHtml, /transition:\s*all/);
    assert.doesNotMatch(poolHtml, /PRIVATE_KEY/);
    assert.doesNotMatch(poolHtml, /data-code="FORBIDDEN"/);

    const swap = await fetch(new URL(`/swap?address=${FIXTURE_ACCOUNTS[0].address}`, host.url));
    const swapHtml = await swap.text();
    assert.match(swapHtml, /Public swap and shield/);
    assert.match(swapHtml, /Spend proofs unavailable/);

    const disconnected = await fetch(new URL("/swap", host.url));
    const disconnectedHtml = await disconnected.text();
    assert.match(disconnectedHtml, /Connect wallet/);
    assert.doesNotMatch(disconnectedHtml, /data-role="/);
    assert.match(disconnectedHtml, /rel="icon"/);

    const deniedOpen = await fetch(new URL("/admin", host.url));
    const deniedOpenHtml = await deniedOpen.text();
    assert.match(deniedOpenHtml, /data-code="FORBIDDEN"/);
    assert.match(deniedOpenHtml, /Connect a wallet that is granted this workspace/);
    assert.doesNotMatch(deniedOpenHtml, /not authorized for the connected wallet/);

    const denied = await fetch(new URL(`/admin?address=${FIXTURE_ACCOUNTS[0].address}`, host.url));
    const deniedHtml = await denied.text();
    assert.match(deniedHtml, /data-code="FORBIDDEN"/);
    assert.match(deniedHtml, /not authorized for the connected wallet/);

    const admin = await fetch(new URL(`/admin?address=${FIXTURE_ACCOUNTS[1].address}`, host.url));
    const adminHtml = await admin.text();
    assert.match(adminHtml, /Application administration/);
    assert.match(adminHtml, /Manifest/);
    assert.match(adminHtml, /Delegations/);
    assert.doesNotMatch(adminHtml, /data-code="FORBIDDEN"/);

    const audit = await fetch(new URL(`/audit?address=${FIXTURE_ACCOUNTS[2].address}`, host.url));
    assert.match(await audit.text(), /Sign in with Ethereum/);

    const gov = await fetch(new URL(`/governance?address=${FIXTURE_ACCOUNTS[3].address}`, host.url));
    const govHtml = await gov.text();
    assert.match(govHtml, /On-chain preview/);
    assert.match(govHtml, /TIMELOCK/);
    assert.match(govHtml, /Production ceremony closed/);

    const live = await fetch(new URL("/shield?role=pool-user&live=1", host.url));
    const liveHtml = await live.text();
    assert.match(liveHtml, /data-live="true"/);
    assert.match(liveHtml, /data-code="live-sidecar"/);
    assert.match(liveHtml, /shield-live.js/);

    const planned = await fetch(new URL("/api/live-deposit/plan", host.url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        user: "0x1111111111111111111111111111111111111111",
        amount: 1_000_000,
      }),
    });
    const plan = await planned.json();
    assert.equal(plan.allowed, true);
    assert.match(plan.approve.data, /^0x095ea7b3/);

    const closedWithdraw = await fetch(new URL("/withdraw?live=1", host.url));
    const closedHtml = await closedWithdraw.text();
    assert.doesNotMatch(closedHtml, /withdraw-live\.js/);
    assert.doesNotMatch(closedHtml, /data-code="operator-demo"/);
    const closedProve = await fetch(new URL("/api/live-withdraw/prove", host.url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ user: FIXTURE_ACCOUNTS[0].address }),
    });
    const closedBody = await closedProve.json();
    assert.equal(closedBody.allowed, false);
    assert.equal(closedBody.reason, "KEYS_MISSING");
  } finally {
    await host.close();
  }
});

test("operator withdraw hatch encodes transact and stays off the default host", async () => {
  const { encodeLiveWithdraw, planLiveOperatorWithdraw } = await import(
    "../web/packages/ui/src/live-withdraw.ts"
  );
  const overlay = JSON.parse(readFileSync(join(HAZE_ROOT, "deployments/fuji-v1.live.json"), "utf8"));
  const { buildLiveDepositWitness, buildLiveWithdrawWitness } = await import(
    "../dev/operator-circuit-witness.mjs"
  );
  const deposit = buildLiveDepositWitness({
    pool: overlay.addresses.HazePool,
    user: "0xeD37fd0d6f0f69236e7472b36796e133d20ecc32",
    applicationId: overlay.applicationId,
    poolVersion: overlay.poolVersion,
  });
  const witness = buildLiveWithdrawWitness({
    pool: overlay.addresses.HazePool,
    user: "0xeD37fd0d6f0f69236e7472b36796e133d20ecc32",
    applicationId: overlay.applicationId,
    poolVersion: overlay.poolVersion,
    note: deposit.note,
  });
  const denied = planLiveOperatorWithdraw({
    path: "/send",
    live: true,
    operatorProve: true,
    zkeyExists: true,
    sidecar: overlay,
    user: "0xeD37fd0d6f0f69236e7472b36796e133d20ecc32",
    amount: 1_000_000,
    recipient: "0xeD37fd0d6f0f69236e7472b36796e133d20ecc32",
    now: 1_700_000_000,
    witness,
  });
  assert.equal(denied.allowed, false);
  const plan = planLiveOperatorWithdraw({
    path: "/withdraw",
    live: true,
    operatorProve: true,
    zkeyExists: true,
    sidecar: overlay,
    user: "0xeD37fd0d6f0f69236e7472b36796e133d20ecc32",
    amount: 1_000_000,
    recipient: "0xeD37fd0d6f0f69236e7472b36796e133d20ecc32",
    now: 1_700_000_000,
    witness,
  });
  assert.equal(plan.allowed, true);
  assert.equal(plan.intent?.action, 3);
  assert.equal(plan.approve, undefined);
  const encoded = encodeLiveWithdraw({
    plan,
    signature: `0x${"ab".repeat(65)}`,
  });
  assert.equal(encoded.to.toLowerCase(), overlay.addresses.HazePool.toLowerCase());
  assert.match(encoded.data, /^0x/);
  const { POOL_SELECTORS } = await import("../sdk/typescript/src/bindings.ts");
  assert.equal(encoded.data.slice(0, 10), POOL_SELECTORS.transact);

  const host = await createCommercialHost({
    port: 0,
    operatorProve: true,
    zkeyPath: join(HAZE_ROOT, "package.json"),
  });
  try {
    const page = await fetch(new URL("/withdraw?live=1", host.url));
    const html = await page.text();
    assert.match(html, /withdraw-live\.js/);
    assert.match(html, /data-code="operator-demo"/);
    const script = await fetch(new URL("/withdraw-live.js", host.url));
    assert.equal(script.status, 200);
    assert.doesNotMatch(await script.text(), /\.zkey/);
  } finally {
    await host.close();
  }
});

test("DEX copy names Fuji demo when the operator hatch is open", async () => {
  const { renderHazePage } = await import("../web/packages/ui/src/html.ts");
  const { humanStatus, liveOperatorShieldAllowed } = await import("../web/packages/ui/src/site.ts");
  assert.equal(humanStatus("KEYS_MISSING"), "Spend proofs unavailable — withdrawals and private sends stay closed.");
  assert.equal(humanStatus("operator-demo"), "Fuji demo · operator keys local");
  assert.equal(
    liveOperatorShieldAllowed({
      path: "/shield",
      live: true,
      operatorProve: true,
      zkeyExists: true,
    }),
    true,
  );
  assert.equal(
    liveOperatorShieldAllowed({
      path: "/withdraw",
      live: true,
      operatorProve: true,
      zkeyExists: true,
    }),
    false,
  );
  assert.equal(
    canSignAction({
      path: "/send",
      walletStatus: "connected",
      reviewed: true,
      role: "pool-user",
      spendProve: "KEYS_MISSING",
      live: true,
      operatorProve: true,
      zkeyExists: true,
    }),
    false,
  );
  const site = createHazeSite({ role: "pool-user", applicationId: APP_A });
  const html = renderHazePage(site, "/shield", {
    live: true,
    operatorProve: true,
    zkeyExists: true,
    address: FIXTURE_ACCOUNTS[0].address,
    walletStatus: "connected",
  });
  assert.match(html, /Fuji demo · operator keys local/);
  assert.match(html, /data-code="operator-demo"/);
  assert.doesNotMatch(html, /development-digest deposit only/);
  const closed = renderHazePage(site, "/swap", {
    address: FIXTURE_ACCOUNTS[0].address,
    walletStatus: "connected",
  });
  assert.match(closed, /Spend proofs unavailable/);
  assert.doesNotMatch(closed, /Fuji demo/);
});

test("hatch live shield plans a Poseidon note; digest shield stays keccak", async () => {
  const { planLiveShieldDeposit, planLiveOperatorShield } = await import(
    "../web/packages/ui/src/live-deposit.ts"
  );
  const { planLiveCircuitTransact } = await import("../dev/operator-circuit-live.mjs");
  const overlay = JSON.parse(readFileSync(join(HAZE_ROOT, "deployments/fuji-v1.live.json"), "utf8"));
  const user = "0xeD37fd0d6f0f69236e7472b36796e133d20ecc32";
  const snapshot = {
    membershipVersion: 1,
    membershipRoot: overlay.membershipRoot,
    hazePolicyVersion: 1,
    hazeBlocklistRoot: overlay.hazeBlocklistRoot,
  };
  const digest = planLiveShieldDeposit({
    path: "/shield",
    live: true,
    sidecar: overlay,
    user,
    amount: 1_000_000,
    now: 1_700_000_000,
    snapshot,
  });
  const circuit = planLiveCircuitTransact({
    action: "deposit",
    user,
    publicAmount: 1_000_000,
  });
  assert.notEqual(digest.intent.outputCommitment0.toLowerCase(), circuit.circom.outputCommitment0.toLowerCase());
  const denied = planLiveOperatorShield({
    path: "/shield",
    live: true,
    operatorProve: false,
    zkeyExists: true,
    sidecar: overlay,
    user,
    amount: 1_000_000,
    now: 1_700_000_000,
    witness: circuit,
  });
  assert.equal(denied.allowed, false);
  const hatch = planLiveOperatorShield({
    path: "/shield",
    live: true,
    operatorProve: true,
    zkeyExists: true,
    sidecar: overlay,
    user,
    amount: 1_000_000,
    now: 1_700_000_000,
    witness: circuit,
  });
  assert.equal(hatch.allowed, true);
  assert.equal(hatch.operatorHatch, true);
  assert.equal(hatch.intent.action, 1);
  assert.equal(hatch.intent.outputCommitment0.toLowerCase(), circuit.circom.outputCommitment0.toLowerCase());
  assert.equal(hatch.approve.to.toLowerCase(), overlay.usdc.toLowerCase());
  const published = JSON.parse(readFileSync(join(HAZE_ROOT, "deployments/fuji-v1.json"), "utf8"));
  assert.equal(published.broadcast, false);
  assert.equal(published.spend_prove, "KEYS_MISSING");
});

test("operator commercial command requires a local zkey and does not flip fuji-v1", async () => {
  const { planOperatorCommercial } = await import("../dev/commercial-host.mjs");
  assert.throws(
    () => planOperatorCommercial({ zkeyExists: false }),
    (error) => error.code === "KEYS_MISSING",
  );
  assert.throws(
    () => planOperatorCommercial({ zkeyExists: true, writeCommittedFuji: true }),
    (error) => error.code === "SC-09",
  );
  assert.throws(
    () => planOperatorCommercial({ zkeyExists: true, productionCeremonyApproved: true }),
    (error) => error.code === "KEYS_MISSING",
  );
  const plan = planOperatorCommercial({ zkeyExists: true });
  assert.equal(plan.operatorProve, true);
  assert.equal(plan.env.HAZE_OPERATOR_PROVE, "1");
  const pkg = JSON.parse(readFileSync(join(HAZE_ROOT, "package.json"), "utf8"));
  assert.match(pkg.scripts["commercial:operator"], /HAZE_OPERATOR_PROVE=1/);
  const published = JSON.parse(readFileSync(join(HAZE_ROOT, "deployments/fuji-v1.json"), "utf8"));
  assert.equal(published.broadcast, false);
  assert.equal(published.spend_prove, "KEYS_MISSING");
});

test("hatch live-deposit plan does not reuse an on-chain commitment", async () => {
  const overlay = JSON.parse(readFileSync(join(HAZE_ROOT, "deployments/fuji-v1.live.json"), "utf8"));
  const host = await createCommercialHost({
    port: 0,
    operatorProve: true,
    zkeyPath: join(HAZE_ROOT, "package.json"),
  });
  try {
    const planned = await fetch(new URL("/api/live-deposit/plan", host.url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        user: "0xeD37FD0d6F0f69236E7472B36796e133D20EcC32",
        amount: 1_000_000,
      }),
    });
    const plan = await planned.json();
    assert.equal(plan.allowed, true);
    assert.equal(plan.operatorHatch, true);
    assert.notEqual(
      plan.intent.outputCommitment0.toLowerCase(),
      overlay.transactions.depositCommitment.toLowerCase(),
    );
    assert.notEqual(
      plan.intent.outputCommitment0.toLowerCase(),
      overlay.transactions.deposit1Commitment.toLowerCase(),
    );
    assert.equal(Number(plan.circuitPlan.note.leafIndex), 3);
    const script = await fetch(new URL("/shield-live.js", host.url));
    const source = await script.text();
    assert.match(source, /eth_getTransactionReceipt/);
    assert.match(source, /live-deposit\/persist/);
    assert.match(source, /blinding: plan\.circuitPlan\?\.note\?\.blinding/);
    const published = JSON.parse(readFileSync(join(HAZE_ROOT, "deployments/fuji-v1.json"), "utf8"));
    assert.equal(published.broadcast, false);
    assert.equal(published.spend_prove, "KEYS_MISSING");
  } finally {
    await host.close();
  }
});

test("hatch host persist writes a spendable note; default host stays KEYS_MISSING", async () => {
  const { mkdtempSync, readFileSync: read, rmSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { planLiveCircuitTransact } = await import("../dev/operator-circuit-live.mjs");
  const dir = mkdtempSync(join(tmpdir(), "haze-host-note-"));
  const notePath = join(dir, "fuji-poseidon-note.json");
  const closed = await createCommercialHost({ port: 0, notePath });
  try {
    const refused = await fetch(new URL("/api/live-deposit/persist", closed.url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ note: { commitment: "0x01" } }),
    });
    assert.equal(refused.headers.get("content-type")?.includes("application/json"), true);
    const body = await refused.json();
    assert.equal(body.allowed, false);
    assert.equal(body.reason, "KEYS_MISSING");
    const proveClosed = await fetch(new URL("/api/live-deposit/prove", closed.url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ user: FIXTURE_ACCOUNTS[0].address, amount: 1_000_000 }),
    });
    assert.equal(proveClosed.headers.get("content-type")?.includes("application/json"), true);
    const proveBody = await proveClosed.json();
    assert.equal(proveBody.allowed, false);
    assert.equal(proveBody.reason, "KEYS_MISSING");
  } finally {
    await closed.close();
  }

  const host = await createCommercialHost({
    port: 0,
    operatorProve: true,
    zkeyPath: join(HAZE_ROOT, "package.json"),
    notePath,
  });
  try {
    const deposit = planLiveCircuitTransact({ action: "deposit" });
    const persist = await fetch(new URL("/api/live-deposit/persist", host.url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ plan: deposit }),
    });
    const saved = await persist.json();
    assert.equal(saved.allowed, true);
    const stored = JSON.parse(read(notePath, "utf8"));
    assert.equal(stored.note.commitment, deposit.note.commitment);
    const script = await fetch(new URL("/shield-live.js", host.url));
    const source = await script.text();
    assert.match(source, /live-deposit\/prove/);
    assert.match(source, /operatorHatch/);
    assert.doesNotMatch(source, /\.zkey/);
    writeFileSync(notePath, `${JSON.stringify(stored, null, 2)}\n`);
  } finally {
    await host.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("successful live snapshot hydrates pool USDC and a persisted note hydrates private USDC", async () => {
  const {
    decodeErc20Balance,
    encodeErc20BalanceOf,
    formatUsdc,
    fetchLiveErc20Balance,
    fetchLivePoolCommitmentExists,
    fetchLivePoolNextIndex,
  } = await import(
    "../web/packages/ui/src/live-deposit.ts"
  );
  const overlay = JSON.parse(readFileSync(join(HAZE_ROOT, "deployments/fuji-v1.live.json"), "utf8"));
  assert.equal(formatUsdc(1_000_000n), "1.00");
  assert.equal(formatUsdc(0n), "0.00");
  assert.match(encodeErc20BalanceOf(overlay.addresses.HazePool), /^0x70a08231/);
  assert.equal(decodeErc20Balance(`0x${(3_000_000n).toString(16).padStart(64, "0")}`), 3_000_000n);

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => ({
    json: async () => ({ result: `0x${(3_000_000n).toString(16).padStart(64, "0")}` }),
  });
  try {
    const balance = await fetchLiveErc20Balance(overlay, overlay.addresses.HazePool);
    assert.equal(balance.raw, 3_000_000n);
    assert.equal(balance.formatted, "3.00");
  } finally {
    globalThis.fetch = originalFetch;
  }

  const { mkdtempSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { planLiveCircuitTransact } = await import("../dev/operator-circuit-live.mjs");
  const dir = mkdtempSync(join(tmpdir(), "haze-host-bal-"));
  const notePath = join(dir, "fuji-poseidon-note.json");
  const host = await createCommercialHost({
    port: 0,
    operatorProve: true,
    zkeyPath: join(HAZE_ROOT, "package.json"),
    notePath,
    publicUsdc: "15.00",
    privateUsdc: "0.00",
    poolUsdc: "0.00",
  });
  try {
    const before = await fetch(new URL("/shield?live=1", host.url));
    const beforeHtml = await before.text();
    assert.match(beforeHtml, /data-pool-usdc/);
    assert.match(beforeHtml, /data-balance="private"/);
    assert.match(beforeHtml, /0\.00 USDC/);
    assert.match(beforeHtml, /data-network[^>]*>Fuji · 43113/);

    const deposit = planLiveCircuitTransact({ action: "deposit" });
    const persist = await fetch(new URL("/api/live-deposit/persist", host.url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ plan: deposit }),
    });
    assert.equal((await persist.json()).allowed, true);

    const after = await fetch(new URL("/shield?live=1", host.url));
    const afterHtml = await after.text();
    assert.match(afterHtml, /data-balance="private"[^>]*>[\s\S]*1\.00 USDC/);
    assert.match(afterHtml, /Notes 1/);

    const client = await fetch(new URL("/client.js", host.url));
    assert.match(await client.text(), /globalThis\.hazeRefreshBalances = hydrateBalances/);
  } finally {
    await host.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("live pool planner helpers read on-chain nextIndex and commitmentExists", async () => {
  const { fetchLivePoolCommitmentExists, fetchLivePoolNextIndex } = await import(
    "../web/packages/ui/src/live-deposit.ts"
  );
  const overlay = JSON.parse(readFileSync(join(HAZE_ROOT, "deployments/fuji-v1.live.json"), "utf8"));
  const originalFetch = globalThis.fetch;
  const requests = [];
  globalThis.fetch = async (_url, options) => {
    const body = JSON.parse(options.body);
    requests.push(body);
    if (body.params[0].data === "0xfc7e9c6f") {
      return { json: async () => ({ result: "0x" + "00".repeat(31) + "03" }) };
    }
    return { json: async () => ({ result: "0x" + "00".repeat(31) + "01" }) };
  };
  try {
    assert.equal(await fetchLivePoolNextIndex(overlay), 3);
    assert.equal(await fetchLivePoolCommitmentExists(overlay, `0x${"01".repeat(32)}`), true);
    assert.equal(requests.length, 2);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("operator hatch live sync skips a committed blinding at the on-chain nextIndex", async () => {
  const { mkdtempSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const dir = mkdtempSync(join(tmpdir(), "haze-live-sync-"));
  const notePath = join(dir, "fuji-poseidon-note.json");
  const actualFetch = globalThis.fetch;
  let commitmentChecks = 0;
  globalThis.fetch = async (_url, options) => {
    const body = JSON.parse(options.body);
    if (body.params[0].data === "0xfc7e9c6f") {
      return { json: async () => ({ result: `0x${"00".repeat(31)}03` }) };
    }
    commitmentChecks += 1;
    return { json: async () => ({ result: commitmentChecks === 1 ? `0x${"00".repeat(31)}01` : `0x${"00".repeat(32)}` }) };
  };
  const host = await createCommercialHost({
    port: 0,
    operatorProve: true,
    liveChainSync: true,
    zkeyPath: join(HAZE_ROOT, "package.json"),
    notePath,
  });
  try {
    const response = await actualFetch(new URL("/api/live-deposit/plan", host.url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ user: FIXTURE_ACCOUNTS[0].address, amount: 1_000_000 }),
    });
    const plan = await response.json();
    assert.equal(plan.allowed, true, JSON.stringify(plan));
    assert.equal(Number(plan.circuitPlan.note.leafIndex), 3);
    assert.equal(Number(plan.circuitPlan.note.blinding), 3);
    assert.equal(commitmentChecks, 2);
  } finally {
    globalThis.fetch = actualFetch;
    await host.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("auditor /audit shows granted decrypted fields from the live envelope", async () => {
  const { mkdtempSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { planLiveCircuitTransact } = await import("../dev/operator-circuit-live.mjs");
  const dir = mkdtempSync(join(tmpdir(), "haze-host-audit-"));
  const notePath = join(dir, "fuji-poseidon-note.json");
  const host = await createCommercialHost({
    port: 0,
    operatorProve: true,
    zkeyPath: join(HAZE_ROOT, "package.json"),
    notePath,
  });
  try {
    const deposit = planLiveCircuitTransact({ action: "deposit" });
    const persist = await fetch(new URL("/api/live-deposit/persist", host.url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ plan: deposit }),
    });
    assert.equal((await persist.json()).allowed, true);

    const auditor = FIXTURE_ACCOUNTS[2].address;
    const page = await fetch(new URL(`/audit?address=${auditor}`, host.url));
    const html = await page.text();
    assert.match(html, /data-chrome="compliance"/);
    assert.match(html, /Assigned cases/);

    const granted = await fetch(new URL("/api/portal/export", host.url), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: `haze-address=${auditor}`,
      },
      body: JSON.stringify({
        fields: ["amount", "commitment", "user", "applicationPolicyVersion", "hazePolicyVersion"],
      }),
    });
    const grantedBody = await granted.json();
    assert.equal(granted.ok, true);
    assert.equal(grantedBody.ok, true);
    assert.equal(grantedBody.rows[0].amount, "1.00");
    assert.equal(grantedBody.rows[0].commitment, deposit.note.commitment);
    assert.equal(grantedBody.rows[0].user.toLowerCase(), String(deposit.user).toLowerCase());
    assert.equal(String(grantedBody.rows[0].applicationPolicyVersion), "1");
    assert.equal(String(grantedBody.rows[0].hazePolicyVersion), "1");
    assert.equal(grantedBody.rows[0].plaintext, undefined);

    const hydrated = await fetch(new URL(`/audit?address=${auditor}`, host.url));
    const hydratedHtml = await hydrated.text();
    assert.match(hydratedHtml, /data-audit-row/);
    assert.match(hydratedHtml, /1\.00/);
    assert.ok(hydratedHtml.includes(deposit.note.commitment.slice(0, 10)));

    const overreach = await fetch(new URL("/api/portal/export", host.url), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: `haze-address=${auditor}`,
      },
      body: JSON.stringify({ fields: ["plaintext"] }),
    });
    assert.equal(overreach.status, 403);
    const overreachBody = await overreach.json();
    assert.equal(overreachBody.code, "UNAUTHORIZED");

    assert.doesNotMatch(hydratedHtml, />secret</);
    const access = hydratedHtml.match(/Access log[\s\S]*?<\/ul>/)?.[0] ?? hydratedHtml;
    assert.doesNotMatch(access, /1\.00/);
  } finally {
    await host.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("live withdraw persists only after a successful receipt, reduces private USDC, and binds audit fields", async () => {
  const { mkdtempSync, readFileSync: read, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { planLiveCircuitTransact } = await import("../dev/operator-circuit-live.mjs");
  const dir = mkdtempSync(join(tmpdir(), "haze-host-withdraw-"));
  const notePath = join(dir, "fuji-poseidon-note.json");
  const host = await createCommercialHost({
    port: 0,
    operatorProve: true,
    zkeyPath: join(HAZE_ROOT, "package.json"),
    notePath,
  });
  try {
    const deposit = planLiveCircuitTransact({ action: "deposit" });
    const persisted = await fetch(new URL("/api/live-deposit/persist", host.url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ plan: deposit }),
    });
    assert.equal((await persisted.json()).allowed, true);

    const recipient = "0x1111111111111111111111111111111111111111";
    const withdrawPlanResponse = await fetch(new URL("/api/live-withdraw/plan", host.url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        user: "0xeD37FD0d6F0f69236E7472B36796e133D20EcC32",
        amount: 1_000_000,
        recipient,
      }),
    });
    const withdrawPlan = await withdrawPlanResponse.json();
    assert.equal(withdrawPlan.allowed, true);

    const rejected = await fetch(new URL("/api/live-withdraw/persist", host.url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ plan: withdrawPlan, receipt: { status: "0x0" } }),
    });
    assert.equal((await rejected.json()).allowed, false);
    assert.equal(JSON.parse(read(notePath, "utf8")).spent, undefined);

    const settled = await fetch(new URL("/api/live-withdraw/persist", host.url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ plan: withdrawPlan, receipt: { status: "0x1" } }),
    });
    const settledBody = await settled.json();
    assert.equal(settledBody.allowed, true);
    assert.equal(settledBody.privateUsdc, "0.00");
    assert.equal(JSON.parse(read(notePath, "utf8")).spent, true);

    const shield = await fetch(new URL("/shield?live=1", host.url));
    assert.match(await shield.text(), /data-balance="private"[^>]*>[\s\S]*0\.00 USDC/);

    const auditor = FIXTURE_ACCOUNTS[2].address;
    const granted = await fetch(new URL("/api/portal/export", host.url), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: `haze-address=${auditor}`,
      },
      body: JSON.stringify({
        fields: ["amount", "commitment", "user", "publicRecipient", "applicationPolicyVersion", "hazePolicyVersion"],
      }),
    });
    const body = await granted.json();
    assert.equal(granted.ok, true);
    assert.equal(body.rows[0].amount, "1.00");
    assert.equal(body.rows[0].commitment, deposit.note.commitment);
    assert.equal(body.rows[0].user.toLowerCase(), withdrawPlan.intent.user.toLowerCase());
    assert.equal(body.rows[0].publicRecipient.toLowerCase(), recipient);
    assert.equal(String(body.rows[0].applicationPolicyVersion), "1");
    assert.equal(String(body.rows[0].hazePolicyVersion), "1");
    assert.equal(body.rows[0].plaintext, undefined);

    const withdrawSource = await fetch(new URL("/withdraw-live.js", host.url));
    const withdrawSourceText = await withdrawSource.text();
    assert.match(withdrawSourceText, /eth_getTransactionReceipt/);
    assert.match(withdrawSourceText, /live-withdraw\/persist/);
  } finally {
    await host.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("operator overlay records mined receipts only and never writes fuji-v1", async () => {
  const { mkdtempSync, writeFileSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { recordLiveOperatorOverlay } = await import("../dev/dappwright-bootstrap.mjs");
  const dir = mkdtempSync(join(tmpdir(), "haze-overlay-"));
  const overlayPath = join(dir, "fuji-v1.live.json");
  const fujiPath = join(HAZE_ROOT, "deployments/fuji-v1.json");
  const before = JSON.parse(readFileSync(join(HAZE_ROOT, "deployments/fuji-v1.live.json"), "utf8"));
  writeFileSync(overlayPath, `${JSON.stringify(before, null, 2)}\n`);
  try {
    const reverted = recordLiveOperatorOverlay({
      overlayPath,
      shield: `0x${"11".repeat(32)}`,
      withdraw: `0x${"22".repeat(32)}`,
      host: "http://127.0.0.1:3014",
      shieldReceipt: { status: "0x0" },
      withdrawReceipt: { status: "0x1" },
    });
    assert.equal(reverted.ok, false);
    assert.equal(reverted.reason, "RECEIPT_REVERTED");
    const afterRevert = JSON.parse(readFileSync(overlayPath, "utf8"));
    assert.equal(afterRevert.transactions.nextIndex, before.transactions.nextIndex);
    assert.equal(afterRevert.transactions.websiteOperatorShield, before.transactions.websiteOperatorShield);

    const mined = recordLiveOperatorOverlay({
      overlayPath,
      shield: `0x${"33".repeat(32)}`,
      withdraw: `0x${"44".repeat(32)}`,
      host: "http://127.0.0.1:3014",
      shieldReceipt: { status: "0x1" },
      withdrawReceipt: { status: "0x1" },
    });
    assert.equal(mined.ok, true);
    const after = JSON.parse(readFileSync(overlayPath, "utf8"));
    assert.equal(after.transactions.websiteOperatorShield, `0x${"33".repeat(32)}`);
    assert.equal(after.transactions.websiteOperatorWithdraw, `0x${"44".repeat(32)}`);
    assert.equal(after.transactions.websiteOperatorHost, "http://127.0.0.1:3014");
    assert.equal(Number(after.transactions.nextIndex), 3);
    const published = JSON.parse(readFileSync(fujiPath, "utf8"));
    assert.equal(published.broadcast, false);
    assert.equal(published.spend_prove, "KEYS_MISSING");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("operator MetaMask walk planner requires hatch keys and never writes fuji-v1", async () => {
  const { planDappwrightLiveOperator } = await import("../dev/dappwright-bootstrap.mjs");
  const sidecar = { broadcast: true, chainId: 43113 };
  assert.equal(planDappwrightLiveOperator({ writeFujiV1: true, sidecar, zkeyExists: true }).reason, "FUJI_V1_IMMUTABLE");
  assert.equal(
    planDappwrightLiveOperator({ productionCeremonyApproved: true, sidecar, zkeyExists: true }).reason,
    "KEYS_MISSING",
  );
  assert.equal(planDappwrightLiveOperator({ sidecar, zkeyExists: false }).reason, "KEYS_MISSING");
  assert.equal(planDappwrightLiveOperator({ zkeyExists: true }).reason, "SIDECAR_MISSING");
  assert.equal(
    planDappwrightLiveOperator({ sidecar: { broadcast: false }, zkeyExists: true }).reason,
    "LIVE_BROADCAST_CLOSED",
  );
  const plan = planDappwrightLiveOperator({ sidecar, zkeyExists: true });
  assert.equal(plan.ok, true);
  assert.equal(plan.chainId, 43113);
  assert.equal(plan.seed, LOCAL_TEST_SEED);
  assert.deepEqual(plan.actions, ["shield", "withdraw"]);
  assert.equal(plan.script, "dappwright:live-operator");
  assert.equal(plan.commercialUrl, "http://127.0.0.1:3014");
  assert.equal(plan.launchFromNpmTest, false);
  const pkg = JSON.parse(readFileSync(join(HAZE_ROOT, "package.json"), "utf8"));
  assert.match(pkg.scripts["dappwright:live-operator"], /dappwright-live-operator-walk/);
  const published = JSON.parse(readFileSync(join(HAZE_ROOT, "deployments/fuji-v1.json"), "utf8"));
  assert.equal(published.broadcast, false);
  assert.equal(published.spend_prove, "KEYS_MISSING");
});
