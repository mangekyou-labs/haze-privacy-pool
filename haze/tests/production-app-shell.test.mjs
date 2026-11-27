import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { createHazeSite } from "../web/packages/ui/src/site.ts";
import { renderHazeFragment } from "../web/packages/ui/src/html.ts";
import {
  AUDITOR_NAV,
  USER_MORE,
  USER_NAV,
  fujiBrowserMountPaths,
  networkChrome,
  planeForPath,
  userChromeAllowsDisclosure,
} from "../web/packages/ui/src/app-shell.ts";
import {
  SESSION_STORAGE_KEY,
  canSilentResume,
  clearPersistedWalletSession,
  loadPersistedWalletSession,
  savePersistedWalletSession,
} from "../web/packages/ui/src/wallet-session.ts";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const APP_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const FIXTURE = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

function memoryStorage() {
  const map = new Map();
  return {
    getItem(key) {
      return map.has(key) ? map.get(key) : null;
    },
    setItem(key, value) {
      map.set(key, String(value));
    },
    removeItem(key) {
      map.delete(key);
    },
  };
}

test("pool-user home is Overview and nav lists the privacy-pool rail", () => {
  const site = createHazeSite({ role: "pool-user", applicationId: APP_A });
  assert.equal(site.homePath(), "/overview");
  assert.deepEqual(
    USER_NAV.map((item) => item.path),
    ["/overview", "/shield", "/swap", "/send", "/withdraw", "/history"],
  );
  assert.deepEqual(
    USER_MORE.map((item) => item.path),
    ["/emergency-exit", "/migrate"],
  );
  assert.ok(site.nav.some((item) => item.path === "/overview"));
});

test("hosted chrome is a volcanic app-shell with User | Auditor, not a DEX card", async () => {
  const site = createHazeSite({ role: "pool-user", applicationId: APP_A });
  const html = renderHazeFragment(site, "/overview", { mode: "fuji-browser" });
  assert.match(html, /data-chrome="app-shell"/);
  assert.match(html, /data-plane="user"/);
  assert.match(html, /class="haze-sidebar"/);
  assert.match(html, /class="haze-side-nav"/);
  assert.match(html, /href="\/overview"/);
  assert.match(html, /href="\/shield"/);
  assert.match(html, /href="\/swap"/);
  assert.match(html, /href="\/send"/);
  assert.match(html, /href="\/withdraw"/);
  assert.match(html, /href="\/history"/);
  assert.match(html, /data-plane-switch="user"/);
  assert.match(html, /data-plane-switch="auditor"/);
  assert.match(html, /id="haze-session-root"/);
  assert.doesNotMatch(html, /data-chrome="dex"/);
  assert.doesNotMatch(html, /class="haze-dex-tabs"/);
  assert.doesNotMatch(html, /haze-inspector/);
});

test("network chrome is Avalanche Testnet, not Fuji chain-id or KEYS_MISSING", () => {
  assert.deepEqual(networkChrome({ mode: "fuji-browser", chainId: 43113 }), {
    network: "Avalanche",
    badge: "Testnet",
  });
  assert.deepEqual(networkChrome({ live: true, chainId: 43113 }), {
    network: "Avalanche",
    badge: "Testnet",
  });
  assert.deepEqual(networkChrome({ chainId: 31337 }), {
    network: "Local",
    badge: undefined,
  });

  const site = createHazeSite({ role: "pool-user", applicationId: APP_A });
  const html = renderHazeFragment(site, "/shield", { mode: "fuji-browser" });
  assert.match(html, /data-network="avalanche"[^>]*>Avalanche/);
  assert.match(html, /data-network-badge="testnet"[^>]*>Testnet/);
  assert.doesNotMatch(html, /Fuji · 43113/);
  assert.doesNotMatch(html, /KEYS_MISSING/);
  assert.doesNotMatch(html, /broadcast:false/);
  assert.doesNotMatch(html, /operator-demo/);
  assert.doesNotMatch(html, /B002|B003/);

  const published = JSON.parse(readFileSync(join(HAZE_ROOT, "deployments/fuji-v1.json"), "utf8"));
  assert.equal(published.broadcast, false);
  assert.equal(published.spend_prove, "KEYS_MISSING");
});

test("fuji-browser mounts the live client on every pool action including swap and send", () => {
  assert.deepEqual(fujiBrowserMountPaths(), [
    "/overview",
    "/shield",
    "/swap",
    "/send",
    "/withdraw",
    "/history",
    "/emergency-exit",
    "/migrate",
  ]);
  const site = createHazeSite({ role: "pool-user", applicationId: APP_A });
  for (const path of fujiBrowserMountPaths()) {
    const html = renderHazeFragment(site, path, { mode: "fuji-browser" });
    assert.equal(html.match(/id="fuji-browser-transaction-root"/g)?.length, 1, path);
    assert.doesNotMatch(html, /<form\b/);
    assert.doesNotMatch(html, /Spend proofs unavailable/);
  }
});

test("user chrome never offers disclosure; auditor plane keeps cases", () => {
  assert.equal(userChromeAllowsDisclosure("pool-user", "/withdraw"), false);
  assert.equal(userChromeAllowsDisclosure("pool-user", "/shield"), false);
  assert.equal(userChromeAllowsDisclosure("application-auditor", "/audit"), true);
  assert.equal(planeForPath("/shield"), "user");
  assert.equal(planeForPath("/audit"), "auditor");

  const user = createHazeSite({ role: "pool-user", applicationId: APP_A });
  const withdraw = renderHazeFragment(user, "/withdraw", { mode: "fuji-browser" });
  assert.doesNotMatch(withdraw, /Disclosure:/);
  assert.doesNotMatch(withdraw, /Request wallet-scoped disclosure/);
  assert.doesNotMatch(withdraw, /data-disclosure-status/);

  const auditor = createHazeSite({ role: "application-auditor", applicationId: APP_A });
  const audit = renderHazeFragment(auditor, "/audit", { mode: "fuji-browser" });
  assert.match(audit, /data-plane="auditor"/);
  assert.match(audit, /id="haze-audit-workstation-root"/);
  assert.match(audit, /href="\/audit"/);
  assert.ok(AUDITOR_NAV.some((item) => item.label === "Cases"));
  assert.doesNotMatch(audit, /class="haze-dex-tabs"/);
  assert.doesNotMatch(audit, /Fuji · 43113/);
});

test("wallet session resumes silently when eth_accounts matches persisted signatures", () => {
  const storage = memoryStorage();
  const session = {
    address: FIXTURE,
    keyDerivationSignature: `0x${"ab".repeat(65)}`,
    vaultUnlockSignature: `0x${"cd".repeat(65)}`,
  };
  savePersistedWalletSession(session, storage);
  assert.equal(SESSION_STORAGE_KEY, "haze.wallet-session.v1");
  assert.deepEqual(loadPersistedWalletSession(storage), session);
  assert.deepEqual(
    canSilentResume({ authorizedAccounts: [FIXTURE], persisted: session }),
    { ok: true, address: FIXTURE },
  );
  assert.deepEqual(
    canSilentResume({ authorizedAccounts: [], persisted: session }),
    { ok: false, reason: "no-account" },
  );
  assert.deepEqual(
    canSilentResume({
      authorizedAccounts: ["0x70997970C51812dc3A010C7d01b50e0d17dc79C8"],
      persisted: session,
    }),
    { ok: false, reason: "mismatch" },
  );
  assert.deepEqual(
    canSilentResume({ authorizedAccounts: [FIXTURE], persisted: null }),
    { ok: false, reason: "locked" },
  );
  clearPersistedWalletSession(storage);
  assert.equal(loadPersistedWalletSession(storage), null);
});

test("shouldReusePersistedSignatures identifies matching persisted session correctly", async () => {
  const { shouldReusePersistedSignatures } = await import("../web/packages/ui/src/wallet-session.ts");
  const session = {
    address: FIXTURE,
    keyDerivationSignature: `0x${"ab".repeat(65)}`,
    vaultUnlockSignature: `0x${"cd".repeat(65)}`,
  };
  assert.equal(shouldReusePersistedSignatures({ accounts: [FIXTURE], persisted: session }), true);
  assert.equal(shouldReusePersistedSignatures({ accounts: [FIXTURE.toLowerCase()], persisted: session }), true);
  assert.equal(shouldReusePersistedSignatures({ accounts: ["0x70997970C51812dc3A010C7d01b50e0d17dc79C8"], persisted: session }), false);
  assert.equal(shouldReusePersistedSignatures({ accounts: [], persisted: session }), false);
  assert.equal(shouldReusePersistedSignatures({ accounts: [FIXTURE], persisted: null }), false);
});

test("WalletSessionProvider intercepts client navigation and reuses persisted signatures on connect", () => {
  const provider = readFileSync(
    new URL("../web/apps/haze/app/wallet-session-provider.tsx", import.meta.url),
    "utf8",
  );
  assert.match(provider, /useRouter/);
  assert.match(provider, /router\.push/);
  assert.match(provider, /a\.haze-side-link/);
  assert.match(provider, /a\.haze-brand/);
  assert.match(provider, /a\.haze-plane-link/);
  assert.match(provider, /shouldReusePersistedSignatures/);
});

test("silent resume advances vault generation even when address already painted connected", async () => {
  const session = await import("../web/packages/ui/src/wallet-session.ts");
  assert.equal(typeof session.markVaultOpened, "function");
  assert.equal(typeof session.markVaultClosed, "function");
  const initial = session.INITIAL_VAULT_HYDRATION;
  assert.equal(initial.vaultReady, false);
  assert.equal(initial.vaultGeneration, 0);

  // First paint can already be status=connected from sessionStorage. Vault open is async.
  const afterOpen = session.markVaultOpened(initial);
  assert.equal(afterOpen.vaultReady, true);
  assert.equal(afterOpen.vaultGeneration, 1);
  assert.notEqual(afterOpen.vaultGeneration, initial.vaultGeneration);

  const afterReconnect = session.markVaultOpened(afterOpen);
  assert.equal(afterReconnect.vaultReady, true);
  assert.equal(afterReconnect.vaultGeneration, 2);

  const closed = session.markVaultClosed();
  assert.equal(closed.vaultReady, false);
  assert.equal(closed.vaultGeneration, 0);
});

test("WalletSessionProvider exposes vaultReady after openVault, including silent resume", () => {
  const provider = readFileSync(
    new URL("../web/apps/haze/app/wallet-session-provider.tsx", import.meta.url),
    "utf8",
  );
  assert.match(provider, /markVaultOpened/);
  assert.match(provider, /markVaultClosed/);
  assert.match(provider, /vaultReady/);
  assert.match(provider, /vaultGeneration/);
  assert.match(provider, /data-vault-ready/);
  const silentResume = provider.indexOf("Silent resume");
  const openVaultInResume = provider.indexOf("await openVault", silentResume);
  const markOpenedInResume = provider.indexOf("markVaultOpened", openVaultInResume);
  assert.ok(
    silentResume >= 0 && openVaultInResume > silentResume && markOpenedInResume > openVaultInResume,
    "silent resume must call markVaultOpened after openVault so a connected paint still retriggers",
  );
  assert.match(provider, /vaultReady,\s*\n?\s*vaultGeneration/);
});

test("overview shows public and private balances without lab phase copy and has exactly one CTA row", () => {
  const site = createHazeSite({ role: "pool-user", applicationId: APP_A });
  const html = renderHazeFragment(site, "/overview", {
    mode: "fuji-browser",
    publicUsdc: "12.50",
    privateUsdc: "1.00",
  });
  assert.match(html, /data-card="overview"/);
  assert.match(html, /data-balance="public"/);
  assert.match(html, /data-balance="private"/);
  assert.match(html, /12\.50/);
  assert.match(html, /1\.00/);
  assert.doesNotMatch(html, /Phase idle/);
  assert.doesNotMatch(html, /Transaction:/);
  assert.doesNotMatch(html, /Review public facts/);
  // Verify exactly one Shield button and one Send button in SSR overview
  const shieldCount = (html.match(/href="\/shield"/g) ?? []).length;
  const sendCount = (html.match(/href="\/send"/g) ?? []).length;
  assert.equal(shieldCount, 2); // 1 in side-nav, 1 in overview card
  assert.equal(sendCount, 2); // 1 in side-nav, 1 in overview card
});

test("fuji-browser-client does not render duplicate overview-client actions", () => {
  const client = readFileSync(
    new URL("../web/apps/haze/app/[route]/fuji-browser-client.tsx", import.meta.url),
    "utf8",
  );
  assert.doesNotMatch(client, /data-card="overview-client"/);
  assert.doesNotMatch(client, /haze-overview-client/);
});

test("overview public and private balances format accurately from raw figures", async () => {
  const {
    formatOverviewPublicBalance,
    formatOverviewPrivateBalance,
    sumSpendableNotes,
  } = await import("../web/packages/ui/src/live-deposit.ts");

  // Disconnected state
  assert.equal(formatOverviewPublicBalance(null, false), "—");
  assert.equal(formatOverviewPublicBalance("0x0", false), "—");
  assert.equal(formatOverviewPrivateBalance(0n, false), "—");
  assert.equal(formatOverviewPrivateBalance(1000000n, false), "—");

  // Connected public USDC: hex from eth_call balanceOf
  assert.equal(formatOverviewPublicBalance("0x0000000000000000000000000000000000000000000000000000000000bebc20", true), "12.50 USDC");
  assert.equal(formatOverviewPublicBalance("0x0", true), "0.00 USDC");
  assert.equal(formatOverviewPublicBalance("0x00", true), "0.00 USDC");
  assert.equal(formatOverviewPublicBalance("0x0f4240", true), "1.00 USDC");

  // Connected private notes: sum of spendable notes
  assert.equal(formatOverviewPrivateBalance(0n, true), "0.00 USDC");
  assert.equal(formatOverviewPrivateBalance(null, true), "0.00 USDC");
  assert.equal(formatOverviewPrivateBalance(1000000n, true), "1.00 USDC");
  assert.equal(formatOverviewPrivateBalance(5500000n, true), "5.50 USDC");

  // Spendable notes calculation
  const notes = [
    { state: "confirmed", note: { value: 1000000, spendable: true } },
    { state: "confirmed", note: { value: 2500000, spendable: true } },
    { state: "pending", note: { value: 5000000, spendable: true } }, // not confirmed
    { state: "confirmed", note: { value: 3000000, spendable: false } }, // not spendable
  ];
  assert.equal(sumSpendableNotes(notes), 3500000n);
  assert.equal(sumSpendableNotes([]), 0n);
  assert.equal(sumSpendableNotes(null), 0n);
});

test("fuji-browser overview SSR ships a recent-ops table with Date Type Amount Status Receipt", () => {
  const site = createHazeSite({ role: "pool-user", applicationId: APP_A });
  const html = renderHazeFragment(site, "/overview", { mode: "fuji-browser" });
  assert.match(html, /data-recent-ops/);
  assert.match(html, /<table class="haze-ops-table"/);
  assert.match(html, /id="haze-recent-ops-body"/);
  assert.match(html, /<th[^>]*>Date<\/th>/);
  assert.match(html, /<th[^>]*>Type<\/th>/);
  assert.match(html, /<th[^>]*>Amount<\/th>/);
  assert.match(html, /<th[^>]*>Status<\/th>/);
  assert.match(html, /<th[^>]*>Receipt<\/th>/);
  assert.match(html, /Connect to see your local vault activity\./);
  assert.doesNotMatch(html, /vault operation\(s\) recorded locally/);
  assert.match(html, /id="fuji-browser-transaction-root"/);
});

test("recentOperationsFromVault maps vault notes to newest-first overview rows", async () => {
  const { recentOperationsFromVault } = await import("../web/packages/ui/src/live-deposit.ts");
  const hashA = `0x${"aa".repeat(32)}`;
  const hashB = `0x${"bb".repeat(32)}`;
  const rows = recentOperationsFromVault([
    {
      id: "old-shield",
      kind: "deposit",
      state: "confirmed",
      note: { amount: 1_000_000, value: 1_000_000, spendable: true },
      transaction: { hash: hashA, action: 1, timestamp: 1_700_000_000_000 },
    },
    {
      id: "newer-send",
      kind: "deposit",
      state: "submitted",
      note: { amount: 2_500_000, value: 2_500_000 },
      transaction: { hash: hashB, action: 2, timestamp: 1_800_000_000_000 },
    },
    {
      id: "pending-withdraw",
      kind: "withdrawal",
      state: "pending_finality",
      note: { amount: 500_000, value: 500_000 },
      transaction: {
        action: 3,
        timestamp: 1_750_000_000_000,
        finalityProvenance: { confirmationCount: 4 },
      },
    },
    {
      id: "failed-swap",
      kind: "swap",
      state: "failed",
      note: { amount: 3_000_000, value: 3_000_000 },
      transaction: { action: 4, timestamp: 1_720_000_000_000 },
    },
    {
      id: "consumed",
      kind: "deposit",
      state: "confirmed",
      note: { amount: 9_000_000, value: 9_000_000, spendable: false, consumed: true },
      transaction: { action: 1, timestamp: 1_900_000_000_000 },
    },
    {
      id: "wiped",
      kind: "transfer",
      state: "confirmed",
      note: { amount: 1, wiped: true },
      transaction: { action: 2, timestamp: 1_910_000_000_000 },
    },
    {
      id: "proving",
      kind: "deposit",
      state: "proving",
      note: { amount: 1 },
      transaction: { timestamp: 1_920_000_000_000 },
    },
  ]);

  assert.equal(rows.length, 4);
  assert.deepEqual(rows.map((row) => row.type), ["Send", "Withdraw", "Swap", "Shield"]);
  assert.equal(rows[0].id, "newer-send");
  assert.equal(rows[0].amount, "2.50");
  assert.equal(rows[0].status, "Submitted");
  assert.equal(rows[0].receipt, `${hashB.slice(0, 10)}…${hashB.slice(-4)}`);
  assert.equal(rows[0].receiptHref, `https://testnet.snowtrace.io/tx/${hashB}`);
  assert.equal(rows[1].status, "Pending finality (4/12)");
  assert.equal(rows[1].receipt, "—");
  assert.equal(rows[1].receiptHref, undefined);
  assert.equal(rows[2].type, "Swap");
  assert.equal(rows[2].status, "Failed");
  assert.equal(rows[3].type, "Shield");
  assert.equal(rows[3].status, "Finalized");
  assert.ok(!rows.some((row) => row.id === "consumed" || row.id === "wiped" || row.id === "proving"));

  const many = Array.from({ length: 12 }, (_, i) => ({
    id: `n${i}`,
    kind: "deposit",
    state: "confirmed",
    note: { amount: 1_000_000 },
    transaction: { action: 1, timestamp: 1_000 + i },
  }));
  assert.equal(recentOperationsFromVault(many).length, 8);
  assert.equal(recentOperationsFromVault(many)[0].id, "n11");
});

test("fuji-browser-client awaits Recover and hydrates the recent-ops table, not a count paragraph", () => {
  const client = readFileSync(
    new URL("../web/apps/haze/app/[route]/fuji-browser-client.tsx", import.meta.url),
    "utf8",
  );
  assert.match(client, /recovering/);
  assert.match(client, /data-recovering/);
  assert.match(client, /await recover\(/);
  assert.match(client, /haze-recent-ops-body/);
  assert.match(client, /recentOperationsFromVault/);
  assert.doesNotMatch(client, /section:last-of-type p/);
  assert.doesNotMatch(client, /vault operation\$\{activeOps\.length === 1 \? "" : "s"\} recorded locally/);
});

test("Next layout wraps routes in a wallet session provider", () => {
  const layout = readFileSync(new URL("../web/apps/haze/app/layout.tsx", import.meta.url), "utf8");
  assert.match(layout, /WalletSessionProvider/);
  const page = readFileSync(new URL("../web/apps/haze/app/page.tsx", import.meta.url), "utf8");
  assert.match(page, /\/overview/);
  const routePage = readFileSync(
    new URL("../web/apps/haze/app/[route]/page.tsx", import.meta.url),
    "utf8",
  );
  assert.match(routePage, /overview/);
  const provider = readFileSync(
    new URL("../web/apps/haze/app/wallet-session-provider.tsx", import.meta.url),
    "utf8",
  );
  assert.match(provider, /createPortal/);
  assert.match(provider, /haze-session-root/);
  assert.match(provider, /data-action="connect"/);
  assert.match(provider, /data-action="disconnect"/);
  assert.match(provider, /data-address/);
  const client = readFileSync(
    new URL("../web/apps/haze/app/[route]/fuji-browser-client.tsx", import.meta.url),
    "utf8",
  );
  assert.doesNotMatch(client, /Request wallet-scoped disclosure/);
  assert.doesNotMatch(client, /Disclosure: \{/);
  assert.match(client, /useWalletSession/);
  assert.doesNotMatch(client, /\{sessionControl\}/);
  assert.doesNotMatch(client, /"Connect wallet"/);
});

test("theme tokens stay volcanic and include app-shell layout", () => {
  const theme = readFileSync(join(HAZE_ROOT, "web/packages/ui/src/theme.css"), "utf8");
  assert.match(theme, /--haze-bg:\s*#16130f/);
  assert.match(theme, /IBM Plex Sans/);
  assert.match(theme, /\.haze-sidebar/);
  assert.match(theme, /\.haze-role-switch/);
  assert.match(theme, /\.haze-preview/);
  assert.doesNotMatch(theme, /Inter|#000|#18181b|violet/);
});

test("theme action card spacing and input hit-targets meet production density standards", () => {
  const theme = readFileSync(join(HAZE_ROOT, "web/packages/ui/src/theme.css"), "utf8");
  // .haze-preview bottom spacing >= 24px
  assert.match(theme, /\.haze-preview\s*\{[^}]*margin:\s*0\s+0\s+(?:2[4-9]|[3-9][0-9])px/);
  // .haze-field input min-height >= 44px
  assert.match(theme, /\.haze-field input[^{]*\{[^}]*min-height:\s*(?:4[4-9]|[5-9][0-9])px/);
  // .haze-amount-field input min-height >= 44px
  assert.match(theme, /\.haze-amount-field input\.haze-amount\s*\{[^}]*min-height:\s*(?:4[4-9]|[5-9][0-9])px/);
});

test("fuji-browser-client enables inputs when session is connected and maintains single preview and confirm", () => {
  const client = readFileSync(
    new URL("../web/apps/haze/app/[route]/fuji-browser-client.tsx", import.meta.url),
    "utf8",
  );
  // Gate disabled on connection status, not solely raw wallet string
  assert.match(client, /disabled=\{!isConnected\}/);
  // Exactly one preview button and one confirm button
  const previewToggles = (client.match(/className="haze-button haze-preview-toggle"/g) ?? []).length;
  const confirms = (client.match(/className="haze-button haze-confirm"/g) ?? []).length;
  assert.equal(previewToggles, 1);
  assert.equal(confirms, 1);
});

test("theme includes action card row tokens and badge styles", () => {
  const theme = readFileSync(join(HAZE_ROOT, "web/packages/ui/src/theme.css"), "utf8");
  assert.match(theme, /\.haze-action-rows/);
  assert.match(theme, /\.haze-row/);
  assert.match(theme, /\.haze-row-label/);
  assert.match(theme, /\.haze-row-value/);
  assert.match(theme, /\.haze-badge/);
});

test("SSR pool routes contain single mount point and zero SSR forms", () => {
  const site = createHazeSite({ role: "pool-user", applicationId: APP_A });
  for (const route of ["/shield", "/swap", "/send", "/withdraw"]) {
    const html = renderHazeFragment(site, route, { mode: "fuji-browser" });
    assert.equal(html.match(/id="fuji-browser-transaction-root"/g)?.length, 1);
    assert.equal(html.includes('<form class="haze-form"'), false);
    assert.equal(html.includes("Review public facts first"), false);
  }
});


test("connected pool-user is authorized for /overview and sees no FORBIDDEN banner", () => {
  const site = createHazeSite({ role: "pool-user", applicationId: APP_A });
  assert.equal(site.decide("/overview").ok, true);
  const html = renderHazeFragment(site, "/overview", {
    mode: "fuji-browser",
    address: "0xab251237210f6c2f7fad53be182e8bfde2f628e0",
  });
  assert.doesNotMatch(html, /data-code="FORBIDDEN"/);
  assert.doesNotMatch(html, /not authorized for the connected wallet/);
});
