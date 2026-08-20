import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { assembleStack, bootstrapStack, teardownStack, verifyStack } from "../dev/stack.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const APP_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const APP_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

test("one command assembles local and CI stacks without production vendors", () => {
  for (const profile of ["local", "ci"]) {
    const stack = assembleStack(profile);
    assert.equal(stack.profile, profile);
    assert.equal(stack.notForProduction, true);
    assert.equal(stack.evm, "anvil-mock");
    assert.ok(stack.contracts.includes("HazePool"));
    assert.ok(stack.services.includes("haze-gatekeeper"));
    assert.ok(stack.services.includes("haze-indexer"));
    assert.ok(stack.database.migrations.includes("0001_init.sql"));
    assert.ok(stack.mocks.includes("MockUsdc"));
    assert.ok(stack.mocks.includes("malicious-adapter"));
    assert.ok(stack.frontends.includes("privacy-pool-dex"));
    assert.ok(stack.frontends.includes("compliance-portal"));
    assert.equal(stack.applications.length, 2);
    assert.ok(stack.actors.includes("adversary"));
    const blob = JSON.stringify(stack);
    assert.doesNotMatch(blob, /alchemy|infura|quicknode|auth0|okta|aws-sdk|vercel/i);
    assert.doesNotMatch(blob, /mainnet\.infura|api\.g\.alchemy/i);
  }
});

test("two registered applications stay isolated in fixtures", () => {
  const stack = assembleStack("local");
  const ids = stack.applications.map((app) => app.applicationId).sort();
  assert.deepEqual(ids, [APP_A, APP_B].sort());
  assert.notEqual(stack.applications[0].kmsKeyRef, stack.applications[1].kmsKeyRef);
  assert.notEqual(stack.applications[0].gatekeeperSigner, stack.applications[1].gatekeeperSigner);
  assert.equal(
    stack.applications.every((app) => app.users.eligible && app.users.ineligible && app.auditor),
    true,
  );
});

test("published fixture hashes are stable and reject production circuit labels", () => {
  const report = verifyStack();
  assert.match(report.fixtureHash, /^0x[0-9a-f]{64}$/);
  assert.equal(report.fixtureHash, assembleStack("local").hash);
  assert.equal(report.circuitProfile, "development");
  assert.equal(report.notForProduction, true);
  const published = JSON.parse(readFileSync(join(HAZE_ROOT, "dev/fixtures/stack-manifest.json"), "utf8"));
  assert.equal(published.fixtureHash, report.fixtureHash);
  assert.equal(published.profile, "development");
  assert.equal(published.not_for_production, true);
});

test("bootstrap and teardown are repeatable on a clean directory", () => {
  const root = mkdtempSync(join(tmpdir(), "haze-stack-"));
  try {
    const first = bootstrapStack({ root, profile: "ci" });
    assert.equal(existsSync(join(root, "ready.json")), true);
    assert.equal(first.applications.length, 2);
    const again = bootstrapStack({ root, profile: "ci" });
    assert.equal(again.hash, first.hash);
    teardownStack(root);
    assert.equal(existsSync(join(root, "ready.json")), false);
    teardownStack(root);
    assert.equal(existsSync(root), true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("npm stack script and CLI verify the published hashes", () => {
  const pkg = JSON.parse(readFileSync(join(HAZE_ROOT, "package.json"), "utf8"));
  assert.equal(pkg.scripts.stack, "node dev/stack.mjs");
  const output = execFileSync(process.execPath, ["dev/stack.mjs", "verify"], {
    cwd: HAZE_ROOT,
    encoding: "utf8",
  });
  assert.match(output, /stack-verify ok/);
  assert.match(output, /0x[0-9a-f]{64}/);
});
