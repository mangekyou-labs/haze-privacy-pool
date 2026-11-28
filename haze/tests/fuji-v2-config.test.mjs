import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => readFileSync(join(ROOT, p), "utf8");
const live = JSON.parse(read("deployments/fuji-v2.live.json"));

const V1_ADDRESSES = [
  "0x00BEB0A5D709d0F093952fD374Dbbf3d0d21d550",
  "0x919b338f189B1e564Af34A26fC002138f308f7dE",
  "0xdb386aeAd1C0b859903702454a7ECDfC306800F6",
  "0x3c40abEEAF252f3F37F59C8D72E7624D466f8ec9",
  "0xcCB53D8430E5c5555c66d56D2747660f97826f9E",
  "0x7147832d44094DD2a8A28470b9CD8C02e402162b",
];
const FIXTURE_AUDIT_KEY = "0x2a082bd0a097bda77158deadbecf043d15e5d09845bf8cfcd2d294d0b0a4ed04";
const V2_AUDIT_PUBLIC_KEY = "0x1b9b5de7274e874632960720219be873afa5fd0249347e3900763d8a774c2546";

const SOURCES = [
  "web/apps/haze/app/wallet-session-provider.tsx",
  "web/apps/haze/app/[route]/fuji-browser-client.tsx",
  "web/apps/haze/app/api/v1/pool/membership-root/route.ts",
  "web/apps/haze/app/api/v1/pool/quote/route.ts",
  "web/apps/haze/app/api/v1/pool/authorize/route.ts",
  "web/apps/haze/app/api/compliance/_lib.ts",
  "web/apps/haze/next.config.ts",
  "sdk/typescript/src/render-disclosure.ts",
  "sdk/typescript/src/compliance-service.ts",
];

test("v2 defaults match the live Fuji v2 deployment", async () => {
  const cfg = await import(join(ROOT, "sdk/typescript/src/fuji-v2-defaults.ts"));
  assert.equal(cfg.FUJI_V2.pool, live.addresses.HazePoolPoseidon);
  assert.equal(cfg.FUJI_V2.router, live.addresses.SwapAndShieldRouter);
  assert.equal(cfg.FUJI_V2.applicationRegistry, live.addresses.ApplicationRegistry);
  assert.equal(cfg.FUJI_V2.policyRegistry, live.addresses.PolicyRegistry);
  assert.equal(cfg.FUJI_V2.usdc, live.usdc);
  assert.equal(cfg.FUJI_V2.emergencyExit, "", "v2 has no approved exit");
  assert.equal(cfg.FUJI_V2.migrationPool, "", "no v1->v2 migration target");
  assert.equal(cfg.FUJI_V2.disclosureOrigin, "https://haze-fuji-disclosure-uegs.onrender.com");
  assert.equal(cfg.FUJI_V2.auditPublicKey, V2_AUDIT_PUBLIC_KEY);
});

test("render-disclosure defaults are the live service and the real audit key", async () => {
  const rd = await import(join(ROOT, "sdk/typescript/src/render-disclosure.ts"));
  assert.equal(rd.DEFAULT_HAZE_DISCLOSURE_ORIGIN, "https://haze-fuji-disclosure-uegs.onrender.com");
  assert.equal(rd.DEFAULT_HAZE_AUDIT_PUBLIC_KEY, V2_AUDIT_PUBLIC_KEY);
});

test("no app source hard-codes v1 addresses, the fixture key, or the suspended origin", () => {
  for (const file of SOURCES) {
    const src = read(file);
    for (const addr of V1_ADDRESSES) assert.ok(!src.includes(addr), `${file} still has v1 ${addr}`);
    assert.ok(!src.includes(FIXTURE_AUDIT_KEY), `${file} still has the fixture audit key`);
    assert.ok(!src.includes("haze-fuji-disclosure.onrender.com"), `${file} still points at the suspended origin`);
  }
});

test("browser spend fails closed instead of using a digest proof (v2 is Groth16-only)", () => {
  const src = read("web/apps/haze/app/[route]/fuji-browser-client.tsx");
  assert.ok(!src.includes("deriveDevelopmentSpendProof"), "digest-proof fallback must be removed");
});
