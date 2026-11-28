import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const ROOT = join(import.meta.dirname, "..");
const manifestPath = join(
  ROOT,
  "web/apps/haze/public/proving/fuji-development/haze-spend-v1/manifest.json",
);

test("published Fuji proving manifest pins the verified immutable spend artifacts", () => {
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));

  assert.deepEqual(
    {
      circuitId: manifest.circuitId,
      profile: manifest.profile,
      notForProduction: manifest.notForProduction,
    },
    {
      circuitId: "haze-spend-v1",
      profile: "fuji-development",
      notForProduction: true,
    },
  );
  const BLOB = "https://ofslwgiidw6jaaky.public.blob.vercel-storage.com/fuji-development/haze-spend-v1";
  const WASM_SHA = "0fc940afbd43a8c16b34e2fd7947c4016963cdf120c7ae34d1188666069b5b57";
  const ZKEY_SHA = "374bb2394da985ab824ce61a95b3b3409b71355139f0a6b16fb8e0bff8e508d5";
  // Artifact URLs are content-addressed: the file name carries its sha256, so a
  // changed artifact needs a new URL and a new pin here.
  assert.deepEqual(manifest.wasm, {
    url: `${BLOB}/spend-${WASM_SHA}.wasm`,
    byteSize: 2611219,
    sha256: `0x${WASM_SHA}`,
  });
  assert.deepEqual(manifest.zkey, {
    url: `${BLOB}/spend-${ZKEY_SHA}.zkey`,
    byteSize: 280397584,
    sha256: `0x${ZKEY_SHA}`,
  });
});
