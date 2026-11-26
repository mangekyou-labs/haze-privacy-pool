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
  assert.deepEqual(manifest.wasm, {
    url: "/proving/fuji-development/haze-spend-v1/spend.wasm",
    byteSize: 2611219,
    sha256: "0x0fc940afbd43a8c16b34e2fd7947c4016963cdf120c7ae34d1188666069b5b57",
  });
  assert.deepEqual(manifest.zkey, {
    urls: [
      "/proving/fuji-development/haze-spend-v1/spend.zkey.part0",
      "/proving/fuji-development/haze-spend-v1/spend.zkey.part1",
      "/proving/fuji-development/haze-spend-v1/spend.zkey.part2",
    ],
    byteSize: 280397584,
    sha256: "0x374bb2394da985ab824ce61a95b3b3409b71355139f0a6b16fb8e0bff8e508d5",
  });
});
