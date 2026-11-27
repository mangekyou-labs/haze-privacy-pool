import assert from "node:assert/strict";
import test from "node:test";
import { createInjectedProviderResolver } from "../web/packages/ui/src/wallet-provider.ts";

function fakeWindow({ ethereum, announce = [] } = {}) {
  const listeners = new Map();
  return {
    ethereum,
    addEventListener(type, listener) {
      listeners.set(type, [...(listeners.get(type) ?? []), listener]);
    },
    dispatchEvent(event) {
      if (event.type === "eip6963:requestProvider") {
        for (const detail of announce) {
          for (const listener of listeners.get("eip6963:announceProvider") ?? []) listener({ type: "eip6963:announceProvider", detail });
        }
      }
      return true;
    },
    lateAnnounce(detail) {
      for (const listener of listeners.get("eip6963:announceProvider") ?? []) listener({ type: "eip6963:announceProvider", detail });
    },
  };
}

const provider = (name) => ({ name, request: async () => name });
const announced = (rdns, p) => ({ info: { rdns, name: rdns, uuid: rdns, icon: "" }, provider: p });

test("prefers MetaMask announced via EIP-6963 over a hijacked window.ethereum", () => {
  const metamask = provider("metamask");
  const phantom = provider("phantom");
  const win = fakeWindow({
    ethereum: phantom,
    announce: [announced("com.avax.core", provider("core")), announced("app.phantom", phantom), announced("io.metamask", metamask)],
  });
  assert.equal(createInjectedProviderResolver(win)(), metamask);
});

test("falls back to window.ethereum when MetaMask does not announce", () => {
  const legacy = provider("legacy");
  const win = fakeWindow({ ethereum: legacy, announce: [announced("app.backpack", provider("backpack"))] });
  assert.equal(createInjectedProviderResolver(win)(), legacy);
});

test("uses the first announced wallet when there is no window.ethereum", () => {
  const core = provider("core");
  const win = fakeWindow({ announce: [announced("com.avax.core", core)] });
  assert.equal(createInjectedProviderResolver(win)(), core);
});

test("picks up a MetaMask announcement that arrives after the first lookup", () => {
  const legacy = provider("legacy");
  const metamask = provider("metamask");
  const win = fakeWindow({ ethereum: legacy });
  const resolve = createInjectedProviderResolver(win);
  assert.equal(resolve(), legacy);
  win.lateAnnounce(announced("io.metamask", metamask));
  assert.equal(resolve(), metamask);
});

test("throws WALLET_UNAVAILABLE when nothing is injected", () => {
  assert.throws(() => createInjectedProviderResolver(fakeWindow())(), /WALLET_UNAVAILABLE/);
  assert.throws(() => createInjectedProviderResolver(undefined)(), /WALLET_UNAVAILABLE/);
});
