import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const ROOT = dirname(fileURLToPath(import.meta.url));
const runnerPath = join(ROOT, "../dev/dappwright-next-spend-walk.mjs");

test("dappwright-next-spend-walk exists and pins safety & spend constraints", () => {
  assert.ok(existsSync(runnerPath), "dappwright-next-spend-walk.mjs must exist");
  const runner = readFileSync(runnerPath, "utf8");

  // Next origin allowlist
  assert.match(runner, /HAZE_NEXT_ORIGIN/);
  assert.match(runner, /PRODUCTION_URL|127\.0\.0\.1:3010/);

  // Fuji chain
  assert.match(runner, /43113/);
  assert.match(runner, /0xa869/);

  // Headed MetaMask
  assert.match(runner, /headless:\s*false/);
  assert.match(runner, /@tenkeylabs\/dappwright/);

  // Safety: does not rewrite fuji-v1.json
  assert.doesNotMatch(runner, /fuji-v1\.json/);
});

test("dappwright-next-spend-walk exercises header connect, Shield 1 USDC, and Send to haze1", () => {
  const runner = readFileSync(runnerPath, "utf8");

  // Connect via #haze-session-root
  assert.match(runner, /#haze-session-root|data-action="connect"|haze-session-connect/);
  assert.match(runner, /CONNECT_FAILED|session\.address/);
  // Shield route and preview
  assert.match(runner, /\/shield/);
  assert.match(runner, /preview|data-action="preview"/i);
  assert.match(runner, /haze-confirm|Shield 1/);

  // Send route and recipient
  assert.match(runner, /\/send/);
  assert.match(runner, /haze1/);

  // Swap handling: named INSUFFICIENT_PILOT error if PILOT balance is 0
  assert.match(runner, /INSUFFICIENT_PILOT|pilot/i);

  // Evidence output
  assert.match(runner, /dappwright-next-spend-walk\.json/);
});
