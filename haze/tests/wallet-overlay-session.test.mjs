import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

test("D10.3: wallet-session.ts saves, loads, clears, and determines silent resume", async () => {
  const {
    savePersistedWalletSession,
    loadPersistedWalletSession,
    clearPersistedWalletSession,
    canSilentResume,
    SESSION_STORAGE_KEY,
  } = await import("../web/packages/ui/src/wallet-session.ts");

  const mockStorage = {
    data: {},
    getItem(key) {
      return this.data[key] ?? null;
    },
    setItem(key, val) {
      this.data[key] = String(val);
    },
    removeItem(key) {
      delete this.data[key];
    },
  };

  const sample = {
    address: "0x1111111111111111111111111111111111111111",
    keyDerivationSignature: "0x" + "aa".repeat(65),
    vaultUnlockSignature: "0x" + "bb".repeat(65),
    providerRdns: "io.metamask",
  };

  savePersistedWalletSession(sample, mockStorage);
  assert.equal(typeof mockStorage.data[SESSION_STORAGE_KEY], "string");
  const loaded = loadPersistedWalletSession(mockStorage);
  assert.deepEqual(loaded, sample);

  const resumeOk = canSilentResume({
    authorizedAccounts: [sample.address],
    persisted: loaded,
  });
  assert.equal(resumeOk.ok, true);
  assert.equal(resumeOk.address, sample.address);

  const resumeMismatch = canSilentResume({
    authorizedAccounts: ["0x2222222222222222222222222222222222222222"],
    persisted: loaded,
  });
  assert.equal(resumeMismatch.ok, false);
  assert.equal(resumeMismatch.reason, "mismatch");

  clearPersistedWalletSession(mockStorage);
  assert.equal(loadPersistedWalletSession(mockStorage), null);
});

test("D10.3: WalletSessionProvider and FujiBrowserClient exist and are integrated in Next app", () => {
  assert.equal(
    existsSync(join(HAZE_ROOT, "web/apps/haze/app/wallet-session-provider.tsx")),
    true,
    "wallet-session-provider.tsx must exist in app dir",
  );
  assert.equal(
    existsSync(join(HAZE_ROOT, "web/apps/haze/app/[route]/fuji-browser-client.tsx")),
    true,
    "fuji-browser-client.tsx must exist in route dir",
  );

  const layout = readFileSync(join(HAZE_ROOT, "web/apps/haze/app/layout.tsx"), "utf8");
  assert.match(
    layout,
    /<WalletSessionProvider>/,
    "RootLayout must wrap children in WalletSessionProvider",
  );

  const page = readFileSync(join(HAZE_ROOT, "web/apps/haze/app/[route]/page.tsx"), "utf8");
  assert.match(
    page,
    /<FujiBrowserClient/,
    "RoutePage must include FujiBrowserClient component",
  );
});

test("D10.3: EIP-6963 wallet discovery is fail-closed on missing wallet and wrong chain", () => {
  const providerCode = readFileSync(
    join(HAZE_ROOT, "web/apps/haze/app/wallet-session-provider.tsx"),
    "utf8",
  );
  // EIP-6963 discovery lives in the shared UI package; the session provider calls it.
  const discoveryCode = readFileSync(join(HAZE_ROOT, "web/packages/ui/src/wallet-provider.ts"), "utf8");
  assert.match(discoveryCode, /eip6963:announceProvider/, "Must listen for eip6963 announceProvider");
  assert.match(discoveryCode, /eip6963:requestProvider/, "Must request eip6963 providers");
  assert.match(discoveryCode, /throw new Error\("WALLET_UNAVAILABLE"\)/, "Must fail closed when no wallet is injected");
  assert.match(providerCode, /injectedProvider\(/, "Session provider must use EIP-6963 discovery");
  assert.match(providerCode, /eth_requestAccounts/, "Connect must request accounts from the wallet");
  assert.match(providerCode, /CHAIN_HEX = "0xa869"/, "Connect must pin the Fuji chain id");
  assert.match(providerCode, /throw new Error\(`FUJI_REQUIRED/, "Connect must fail closed off Fuji");
});

test("D8.4: Consumer fragment wraps SSR wallet controls in #haze-session-root", async () => {
  const { renderHazeFragment } = await import("../web/packages/ui/src/html.ts");
  const { createHazeSite } = await import("../web/packages/ui/src/site.ts");
  const site = createHazeSite({ role: "pool-user", applicationId: "0x" + "aa".repeat(32) });
  const fragment = renderHazeFragment(site, "/shield", {});
  assert.match(
    fragment,
    /<span id="haze-session-root">[\s\S]*?data-action="connect"[\s\S]*?<\/span>/,
    "Consumer fragment must include #haze-session-root wrapping the SSR connect button",
  );
});

test("D8.4: wallet-session-provider portals session control to #haze-session-root and fuji-browser-client does not render sessionControl", () => {
  const providerCode = readFileSync(
    join(HAZE_ROOT, "web/apps/haze/app/wallet-session-provider.tsx"),
    "utf8",
  );
  assert.match(
    providerCode,
    /getElementById\("haze-session-root"\)/,
    "WalletSessionProvider must locate #haze-session-root element",
  );
  assert.match(
    providerCode,
    /createPortal\s*\(\s*sessionControl,\s*portalTarget\s*\)/,
    "WalletSessionProvider must portal sessionControl into portalTarget",
  );
  assert.match(
    providerCode,
    /data-session-status/,
    "Portal control must have data-session-status attribute",
  );

  const clientCode = readFileSync(
    join(HAZE_ROOT, "web/apps/haze/app/[route]/fuji-browser-client.tsx"),
    "utf8",
  );
  assert.doesNotMatch(
    clientCode,
    /\{sessionControl\}/,
    "fuji-browser-client must not render sessionControl",
  );
});
