import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const ROOT = dirname(fileURLToPath(import.meta.url));
const runnerPath = join(ROOT, "../dev/dappwright-next-session-walk.mjs");

test("dappwright-next-session-walk exists and pins safety & seed constraints", () => {
  assert.ok(existsSync(runnerPath), "dappwright-next-session-walk.mjs must exist");
  const runner = readFileSync(runnerPath, "utf8");

  assert.match(runner, /LOCAL_TEST_SEED/);
  assert.doesNotMatch(runner, /process\.env\.PRIVATE_KEY/);
  assert.doesNotMatch(runner, /loadPrivateKey/);
  assert.match(runner, /HAZE_NEXT_ORIGIN/);
  assert.match(runner, /HAZE_NEXT_ORIGIN|127\.0\.0\.1:3010/);
  assert.match(runner, /headless:\s*false/);
  assert.match(runner, /@tenkeylabs\/dappwright/);
});

test("dappwright-next-session-walk enforces Fuji chain and returns home before switchNetwork", () => {
  const runner = readFileSync(runnerPath, "utf8");
  assert.match(runner, /43113/);
  assert.match(runner, /0xa869/);

  const home = runner.indexOf('getByTestId("account-options-menu-button")');
  const network = runner.indexOf("switchNetwork");
  assert.ok(home >= 0 && network > home, "Must return to account home before switchNetwork");
});

test("dappwright-next-session-walk verifies header connect, session persistence across full rail, account switch, forbidden admin, and zero broadcast", () => {
  const runner = readFileSync(runnerPath, "utf8");

  // Header Connect
  assert.match(runner, /#haze-session-root|data-action="connect"|haze-session-connect/);
  assert.match(runner, /confirmAny|confirmVisibleWalletAction/);

  // Persistence across all user rail tabs without re-prompt
  assert.match(runner, /\/overview/);
  assert.match(runner, /\/shield/);
  assert.match(runner, /\/swap/);
  assert.match(runner, /\/send/);
  assert.match(runner, /\/withdraw/);
  assert.match(runner, /\/history/);

  // Signature count guard: assert no second signature after initial connect
  assert.match(runner, /signatureCount|signaturesRequested|noExtraSignatures|no_extra_signatures/i);

  // Account switch with mismatch
  assert.match(runner, /account|Account 2|ANVIL_ADMIN_PK|selectAccount|importPK/);

  // Pool user /admin forbidden without query param
  assert.match(runner, /\/admin/);
  assert.match(runner, /FORBIDDEN/);
  assert.doesNotMatch(runner, /\?role=/);

  // No user disclosure CTA
  assert.doesNotMatch(runner, /Request wallet-scoped disclosure/);

  // Zero broadcast enforcement
  assert.match(runner, /eth_sendTransaction/);
  assert.match(runner, /BROADCAST_FORBIDDEN|NO_BROADCAST|broadcast.*failed|throw.*sendTransaction/i);
});
