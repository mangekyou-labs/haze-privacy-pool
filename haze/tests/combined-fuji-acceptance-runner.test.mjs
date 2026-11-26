import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const combinedRunner = readFileSync(
  new URL("../dev/combined-fuji-acceptance.mjs", import.meta.url),
  "utf8",
);
const cliWalkScript = readFileSync(
  new URL("../dev/playwright-cli-audit-walk.mjs", import.meta.url),
  "utf8",
);

import { parseAndValidateVercelDeployment, getRequiredEnvironmentConfig } from "../dev/combined-fuji-acceptance.mjs";

test("Combined runner uses exact production origin and exact environment wallet without stale deployment defaults", () => {
  assert.match(combinedRunner, /PRODUCTION_URL/);
  assert.match(combinedRunner, /0xeD37FD0d6F0f69236E7472B36796e133D20EcC32/i);
  assert.match(combinedRunner, /assertProductionOrigin/);
  assert.doesNotMatch(combinedRunner, /process\.env\.VERCEL_DEPLOYMENT_ID\s*\|\|\s*["']dpl_/);
  assert.match(combinedRunner, /43113/);
});

test("parseAndValidateVercelDeployment recognizes actual meta.gitCommitSha and verifies against candidateGitSha", () => {
  const deployment = {
    readyState: "READY",
    meta: {
      gitCommitSha: "901c4b5bc11a765d012c4e9280e0539c5375c185",
      gitCommitRef: "feature-haze-avalanche-compliant-pool",
    },
  };
  const result = parseAndValidateVercelDeployment(deployment, "901c4b5bc11a765d012c4e9280e0539c5375c185");
  assert.equal(result.ready, true);
  assert.equal(result.clean, true);
  assert.equal(result.dirty, false);
  assert.equal(result.sourceShaVerified, true);
  assert.equal(result.sourceSha, "901c4b5bc11a765d012c4e9280e0539c5375c185");
});

test("parseAndValidateVercelDeployment rejects dirty deployments", () => {
  const dirtyDeployment1 = {
    readyState: "READY",
    meta: {
      gitCommitSha: "901c4b5bc11a765d012c4e9280e0539c5375c185",
      gitDirty: "1",
    },
  };
  assert.throws(
    () => parseAndValidateVercelDeployment(dirtyDeployment1, "901c4b5bc11a765d012c4e9280e0539c5375c185"),
    /DIRTY_DEPLOYMENT_REJECTED/,
  );

  const dirtyDeployment2 = {
    readyState: "READY",
    meta: {
      gitCommitSha: "901c4b5bc11a765d012c4e9280e0539c5375c185",
      gitDirty: true,
    },
  };
  assert.throws(
    () => parseAndValidateVercelDeployment(dirtyDeployment2, "901c4b5bc11a765d012c4e9280e0539c5375c185"),
    /DIRTY_DEPLOYMENT_REJECTED/,
  );
});

test("parseAndValidateVercelDeployment rejects missing, mismatched, or unready deployments", () => {
  const unready = {
    readyState: "BUILDING",
    meta: { gitCommitSha: "901c4b5bc11a765d012c4e9280e0539c5375c185" },
  };
  assert.throws(
    () => parseAndValidateVercelDeployment(unready, "901c4b5bc11a765d012c4e9280e0539c5375c185"),
    /VERCEL_DEPLOYMENT_NOT_READY/,
  );

  const mismatch = {
    readyState: "READY",
    meta: { gitCommitSha: "4143e60c3eec93ba25e7aa8432f2455084d5f39e" },
  };
  assert.throws(
    () => parseAndValidateVercelDeployment(mismatch, "901c4b5bc11a765d012c4e9280e0539c5375c185"),
    /VERCEL_SOURCE_SHA_MISMATCH/,
  );

  const missingSha = {
    readyState: "READY",
    meta: {},
  };
  assert.throws(
    () => parseAndValidateVercelDeployment(missingSha, "901c4b5bc11a765d012c4e9280e0539c5375c185"),
    /VERCEL_SOURCE_SHA_MISSING/,
  );
});

test("getRequiredEnvironmentConfig requires explicit candidate SHA and deployment ID", () => {
  assert.throws(
    () => getRequiredEnvironmentConfig({}, {}),
    /VERCEL_DEPLOYMENT_ID_REQUIRED/,
  );
  assert.throws(
    () => getRequiredEnvironmentConfig({ VERCEL_DEPLOYMENT_ID: "dpl_test" }, {}),
    /CANDIDATE_GIT_SHA_REQUIRED/,
  );
  const config = getRequiredEnvironmentConfig(
    { VERCEL_DEPLOYMENT_ID: "dpl_12345", CANDIDATE_GIT_SHA: "901c4b5bc11a765d012c4e9280e0539c5375c185" },
    {},
  );
  assert.equal(config.vercelDeploymentId, "dpl_12345");
  assert.equal(config.candidateGitSha, "901c4b5bc11a765d012c4e9280e0539c5375c185");
});

test("Preflight independently proves deployment source, readiness, contracts, funds, and allowance", () => {
  assert.match(combinedRunner, /api\.vercel\.com\/v13\/deployments/);
  assert.match(combinedRunner, /sourceShaVerified/);
  assert.match(combinedRunner, /eth_getCode/);
  assert.match(combinedRunner, /eth_getBalance/);
  assert.match(combinedRunner, /70a08231/);
  assert.match(combinedRunner, /dd62ed3e/);
  assert.match(combinedRunner, /readyz/);
  assert.match(combinedRunner, /AbortSignal\.timeout/);
});

test("Combined runner performs fresh deposit, reload recovery, withdrawal, and SIWE in Dappwright", () => {
  assert.match(combinedRunner, /@tenkeylabs\/dappwright/);
  assert.match(combinedRunner, /openRoute\("\/shield"\)/);
  assert.match(combinedRunner, /#haze-session-root|data-action="connect"|getByRole\("button",\s*\{\s*name:\s*"Connect",\s*exact:\s*true\s*\}\)/);
  assert.doesNotMatch(combinedRunner, /txRegion\(\)\.getByRole\("button",\s*\{\s*name:\s*"Connect wallet"/);
  assert.match(combinedRunner, /data-action="preview"|getByRole\("button",\s*\{\s*name:\s*"Preview"\s*\}\)/);
  assert.match(combinedRunner, /getByRole\("button",\s*\{\s*name:\s*\/Shield.*USDC\/|Shield 1\.0 USDC/);
  assert.doesNotMatch(combinedRunner, /getByRole\("button",\s*\{\s*name:\s*"Deposit 1 USDC"\s*\}\)/);
  assert.match(combinedRunner, /reloadAfterDeposit/);
  assert.match(combinedRunner, /openRoute\("\/withdraw"\)/);
  assert.match(combinedRunner, /confirmVisibleWalletAction/);
  assert.match(combinedRunner, /connect-siwe/);
  assert.match(combinedRunner, /audit-session\.json/);
});

test("Combined runner enforces rejection of previously recorded transaction hashes", () => {
  assert.match(combinedRunner, /HISTORICAL_TRANSACTION_HASHES/);
  assert.match(combinedRunner, /rejectHistoricalHash/);
});

test("Combined runner delegates audit walkthrough to mandatory named playwright-cli session", () => {
  assert.match(combinedRunner, /haze-d8-fuji-live/);
  assert.match(combinedRunner, /runPlaywrightCliAuditWalk/);
  assert.match(cliWalkScript, /playwright-cli/);
  assert.match(cliWalkScript, /-s=haze-d8-fuji-live/);
  assert.match(cliWalkScript, /tracing-start/);
  assert.match(cliWalkScript, /tracing-stop/);
  assert.match(cliWalkScript, /snapshot/);
  assert.match(cliWalkScript, /state-load/);
});

test("Named CLI walk verifies case, checks, disclosure, export, tamper, mobile, and logout", () => {
  assert.match(cliWalkScript, /verify-case/);
  assert.match(cliWalkScript, /export-case/);
  assert.match(cliWalkScript, /verifyEs256Jws/);
  assert.match(cliWalkScript, /390/);
  assert.match(cliWalkScript, /844/);
  assert.match(cliWalkScript, /logout/);
  assert.match(cliWalkScript, /WITHHELD/);
});

test("Combined runner executes evidence verifier on final manifest", () => {
  assert.match(combinedRunner, /verifyCombinedEvidenceManifest/);
  assert.match(combinedRunner, /fresh-combined-fuji-acceptance\.json/);
});
