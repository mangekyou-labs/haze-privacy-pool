/**
 * Fuji MVP Acceptance Run Journaler.
 * Append-only run directory with schema haze-fuji-mvp-acceptance-v2.
 * Writes manifest at run start, preflight, broadcast, mining, event validation, and finality.
 * Crash after broadcast is guaranteed to preserve the transaction hash.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { PRODUCTION_URL } from "./production-origin.mjs";

const ROOT = dirname(fileURLToPath(import.meta.url));
const RUNS_DIR = join(ROOT, "../output/playwright/runs");

export function createAcceptanceJournal(options = {}) {
  const timestamp = options.timestamp || new Date().toISOString().replace(/[:.]/g, "-");
  const runId = options.runId || `run-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
  const runDirName = `${timestamp}-${runId}`;
  const runDir = join(RUNS_DIR, runDirName);
  mkdirSync(runDir, { recursive: true });

  const manifestPath = join(runDir, "manifest.json");
  const latestPath = join(RUNS_DIR, "latest.json");
  const topLatestPath = join(ROOT, "../output/playwright/latest.json");

  const manifest = {
    schema: "haze-fuji-mvp-acceptance-v2",
    runId,
    timestamp: new Date().toISOString(),
    origin: options.origin || PRODUCTION_URL,
    chainId: 43113,
    pool: options.pool || "0x00BEB0A5D709d0F093952fD374Dbbf3d0d21d550",
    poolVersion: options.poolVersion || "0x000000000000000000000000000000000000000000000000000000000000b002",
    applicationId: options.applicationId || "0x0000000000000000000000000000000000000000000000000000000000000a11",
    status: "IN_PROGRESS",
    candidateGitSha: options.candidateGitSha || process.env.CANDIDATE_GIT_SHA || process.env.GIT_SHA || "unknown",
    vercelDeploymentId: options.vercelDeploymentId || process.env.VERCEL_DEPLOYMENT_ID,
    deployment: options.deployment || {
      sourceSha: options.candidateGitSha || process.env.CANDIDATE_GIT_SHA || "unknown",
      clean: false,
      ready: false,
      sourceShaVerified: false,
    },
    namedCliSession: options.namedCliSession || `haze-fuji-mvp-${runId}`,
    tools: {
      dappwright: false,
      playwrightCli: false,
    },
    accounts: {
      accountA: { address: options.accountA || "" },
      accountB: { address: options.accountB || "" },
    },
    operations: {},
    attempts: [],
    screenshots: {},
  };

  function bigIntReplacer(key, value) {
    if (typeof value === "bigint") {
      return value.toString();
    }
    return value;
  }

  function persist() {
    writeFileSync(manifestPath, `${JSON.stringify(manifest, bigIntReplacer, 2)}\n`);
    const pointer = {
      latestRunId: runId,
      runDir: runDirName,
      manifestPath: `runs/${runDirName}/manifest.json`,
      timestamp: manifest.timestamp,
      status: manifest.status,
    };
    writeFileSync(latestPath, `${JSON.stringify(pointer, bigIntReplacer, 2)}\n`);
    try {
      writeFileSync(topLatestPath, `${JSON.stringify(pointer, bigIntReplacer, 2)}\n`);
    } catch {}
  }

  // Initial persist at run start
  persist();

  return {
    setPoolVersion(version) {
      manifest.poolVersion = version;
      persist();
    },

    setDeploymentValidation(validation) {
      manifest.deployment = {
        ...manifest.deployment,
        ...validation,
      };
      persist();
    },

    markToolExecuted(toolName) {
      if (toolName in manifest.tools) {
        manifest.tools[toolName] = true;
        persist();
      }
    },

    runId,
    runDir,
    manifestPath,
    getManifest: () => manifest,

    setAccounts(accounts) {
      if (accounts.accountA) manifest.accounts.accountA = { ...manifest.accounts.accountA, ...accounts.accountA };
      if (accounts.accountB) manifest.accounts.accountB = { ...manifest.accounts.accountB, ...accounts.accountB };
      persist();
    },

    recordAttempt(record) {
      manifest.attempts.push({
        id: `att-${manifest.attempts.length + 1}`,
        timestamp: Date.now(),
        ...record,
      });
      persist();
    },

    recordPreflight(actionName, details = {}) {
      const action = actionName === "shield" ? 1 : actionName === "send" ? 2 : actionName === "withdraw" ? 3 : 4;
      manifest.operations[actionName] = {
        action,
        wallet: details.wallet || "",
        phase: "preflight",
        transactionHash: "",
        confirmationCount: 0,
        ...details,
      };
      this.recordAttempt({
        action,
        wallet: details.wallet || "",
        expectedPool: manifest.pool,
        expectedApplicationId: manifest.applicationId,
        phase: "preflight",
      });
      persist();
    },

    recordBroadcast(actionName, txHash, details = {}) {
      const action = actionName === "shield" ? 1 : actionName === "send" ? 2 : actionName === "withdraw" ? 3 : 4;
      manifest.operations[actionName] = {
        ...manifest.operations[actionName],
        action,
        transactionHash: txHash,
        phase: "broadcast",
        ...details,
      };
      this.recordAttempt({
        action,
        wallet: details.wallet || manifest.operations[actionName]?.wallet || "",
        expectedPool: manifest.pool,
        expectedApplicationId: manifest.applicationId,
        phase: "broadcast",
        transactionHash: txHash,
      });
      persist();
    },

    recordMined(actionName, receipt, details = {}) {
      manifest.operations[actionName] = {
        ...manifest.operations[actionName],
        receipt,
        blockNumber: receipt.blockNumber ? Number(receipt.blockNumber) : undefined,
        blockHash: receipt.blockHash,
        phase: "mined",
        ...details,
      };
      this.recordAttempt({
        action: manifest.operations[actionName]?.action,
        wallet: manifest.operations[actionName]?.wallet || "",
        expectedPool: manifest.pool,
        expectedApplicationId: manifest.applicationId,
        phase: "mined",
        transactionHash: manifest.operations[actionName]?.transactionHash,
        receiptStatus: receipt.status ? Number(receipt.status) : 1,
        blockNumber: receipt.blockNumber ? Number(receipt.blockNumber) : undefined,
      });
      persist();
    },

    recordEventValidated(actionName, decodedEvent, details = {}) {
      manifest.operations[actionName] = {
        ...manifest.operations[actionName],
        decodedEvent,
        phase: "event_validated",
        ...details,
      };
      persist();
    },

    recordFinality(actionName, confirmations, provenance = {}) {
      manifest.operations[actionName] = {
        ...manifest.operations[actionName],
        confirmationCount: confirmations,
        phase: "finalized",
        verifiedAtBlock: provenance.verifiedAtBlock,
        canonicalBlockHash: provenance.canonicalBlockHash,
      };
      persist();
    },

    recordFailure(actionName, stage, error) {
      if (actionName && manifest.operations[actionName]) {
        manifest.operations[actionName].phase = "failed";
        manifest.operations[actionName].failureReason = error instanceof Error ? error.message : String(error);
        manifest.operations[actionName].failureStage = stage;
      }
      this.recordAttempt({
        action: manifest.operations[actionName]?.action,
        wallet: manifest.operations[actionName]?.wallet || "",
        expectedPool: manifest.pool,
        expectedApplicationId: manifest.applicationId,
        phase: "failed",
        failureStage: stage,
        error: error instanceof Error ? error.message : String(error),
      });
      persist();
    },

    recordAuditorCase(details) {
      manifest.auditorCase = {
        caseId: details.caseId,
        withdrawalHash: details.withdrawalHash,
        disclosedActionReference: details.disclosedActionReference,
        verifiedJws: details.verifiedJws ?? true,
        exportHash: details.exportHash,
      };
      persist();
    },

    recordFaucet(details) {
      manifest.faucet = {
        enabled: true,
        mintHash: details.mintHash,
        venueLiquidityUsdc: details.venueLiquidityUsdc,
      };
      persist();
    },

    recordHistoryReconciliation(details) {
      manifest.historyReconciliation = {
        recoveredOnReload: details.recoveredOnReload ?? true,
        spendableNoteCount: details.spendableNoteCount ?? 1,
      };
      persist();
    },

    recordScreenshot(name, relativePath) {
      manifest.screenshots[name] = relativePath;
      persist();
    },

    finalize(status = "PASS") {
      manifest.status = status;
      persist();
      return manifest;
    },
  };
}
