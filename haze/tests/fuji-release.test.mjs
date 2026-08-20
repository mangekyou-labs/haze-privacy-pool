import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { assembleFujiRelease, verifyFujiRelease } from "../dev/fuji-release.mjs";
import { FUJI_COMPATIBILITY } from "../sdk/typescript/src/versions.ts";
import { assembleStack } from "../dev/stack.mjs";
import { SCENARIO_IDS } from "../dev/e2e.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const USDC_FUJI = "0x5425890298aed601595a70AB815c96711a31Bc65";

const CONTRACTS = [
  "HazePool",
  "HazeSpendVerifier",
  "SwapAndShieldRouter",
  "EmergencyExit",
  "HazeAccess",
  "ApplicationRegistry",
  "PolicyRegistry",
  "VersionRegistry",
];

test("Fuji release pins chain, USDC, compatibility, and development ceremony artifacts", () => {
  const release = assembleFujiRelease();
  assert.equal(release.notForProduction, true);
  assert.equal(release.network, "fuji");
  assert.equal(release.chainId, 43113);
  assert.equal(release.usdc.toLowerCase(), USDC_FUJI.toLowerCase());
  assert.equal(release.broadcast, false);
  assert.equal(release.liveRpc, "operator-owned");
  assert.equal(release.compatibility.chainId, FUJI_COMPATIBILITY.chainId);
  assert.equal(release.compatibility.circuitArtifactHash, FUJI_COMPATIBILITY.circuitArtifactHash);
  assert.equal(release.compatibility.protocolVersionTag, FUJI_COMPATIBILITY.protocolVersionTag);
  assert.equal(release.ceremony.profile, "development");
  assert.equal(release.ceremony.notForProduction, true);
  assert.equal(release.ceremony.spendProve, "KEYS_MISSING");
  assert.equal(release.immutable, true);
  assert.deepEqual(release.contracts, CONTRACTS);
  assert.ok(release.services.includes("haze-gatekeeper"));
  assert.ok(release.frontends.includes("privacy-pool-dex"));
  assert.ok(release.frontends.includes("compliance-portal"));
  assert.match(release.policyRoots.protocolVersionTag, /^0x[0-9a-f]{64}$/);
  assert.equal(existsSync(join(HAZE_ROOT, release.provenancePath)), true);
  assert.doesNotMatch(JSON.stringify(release), /alchemy|infura|quicknode|auth0|okta|aws-sdk|vercel/i);
});

test("Fuji release records smoke, E2E, gas, and Fuji-configured runbook rehearsal", () => {
  const release = assembleFujiRelease();
  const stack = assembleStack("ci");
  assert.equal(release.smoke.stackHash, stack.hash);
  assert.equal(release.smoke.compatibility, "pass");
  assert.deepEqual(release.e2e.scenarios, SCENARIO_IDS);
  assert.equal(release.e2e.count, 13);
  assert.equal(release.gas.fujiRequiredBeforeMainnet, true);
  assert.equal(release.gas.network, "local-foundry");
  assert.ok(release.gas.actions.includes("deposit"));
  assert.ok(release.gas.actions.includes("withdraw"));
  assert.equal(release.observability, "dashboards-alerts");
  assert.equal(release.rehearsal.fuji, "pass-fuji-configured");
  assert.equal(release.coverage.includes("SC-01"), true);
  assert.equal(release.coverage.includes("SC-06"), true);
  assert.equal(release.coverage.includes("SC-07"), true);
  assert.match(release.verdict, /^pass/);
});

test("published Fuji release fixture hashes match verifyFujiRelease", () => {
  const verified = verifyFujiRelease();
  const assembled = assembleFujiRelease();
  assert.match(verified.fixtureHash, /^0x[0-9a-f]{64}$/);
  assert.equal(verified.fixtureHash, assembled.hash);
  const published = JSON.parse(readFileSync(join(HAZE_ROOT, "dev/fixtures/fuji-release.json"), "utf8"));
  assert.equal(published.fixtureHash, verified.fixtureHash);
  assert.equal(published.not_for_production, true);
  assert.equal(published.network, "fuji");
  assert.equal(published.chainId, 43113);
  assert.equal(published.broadcast, false);
  assert.equal(published.verdict, assembled.verdict);
  const provenance = JSON.parse(readFileSync(join(HAZE_ROOT, "deployments/fuji-v1.json"), "utf8"));
  assert.equal(provenance.not_for_production, true);
  assert.equal(provenance.chainId, 43113);
  assert.equal(provenance.broadcast, false);
});

test("npm fuji-release script verifies the published package", () => {
  const pkg = JSON.parse(readFileSync(join(HAZE_ROOT, "package.json"), "utf8"));
  assert.equal(pkg.scripts["fuji-release"], "node --experimental-strip-types dev/fuji-release.mjs");
  const output = execFileSync(process.execPath, ["--experimental-strip-types", "dev/fuji-release.mjs", "verify"], {
    cwd: HAZE_ROOT,
    encoding: "utf8",
  });
  assert.match(output, /fuji-release-verify ok/);
  assert.match(output, /0x[0-9a-f]{64}/);
});
