/**
 * Independent Evidence Verifier for Combined Fresh Fuji Production Acceptance.
 * Validates cryptographic authenticity, on-chain evidence, finality,
 * named CLI execution, isolation checks, access logs, and artifact completeness.
 */
import assert from "node:assert/strict";
import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { PRODUCTION_URL } from "./production-origin.mjs";

const ROOT = dirname(fileURLToPath(import.meta.url));

export const HISTORICAL_TRANSACTION_HASHES = new Set([
  // Historical D7 runs
  "0x11a283fe82297674f37d94b015132f3098a440b21b880eb643f07d1a986bcc80",
  "0x12d668b859aedd1e179f84e466e46cd1586d7446c95ebbd0b2f0b666307626f2",
  "0xb9184be1be1a3e4713cd015200d95edcb30aebeb567b1e73672a375607ec2e69",
  "0x8218e5a4f14434e0007d421a8e82ba0914429a0cab43d7dba263d1ed232c8a03",
  // Historical fuji-v1 deployment & test hashes
  "0xe8d353fab0f60c34d44ec91df2988a820189bc3483d722c7a17c1081c5ecca2a",
  "0xf83220015bdca26a7d801f84558590159007ffe59d613a85c90d7c29a5293036",
  "0xc6e4a0ca56dc2629f2c2699da89319fcadf576472d845a881e4165c495a18904",
  "0x39e4142f873fab281ea38cd5c2b5a7e37af9b28faad32a4dc66463683c9ec427",
  "0x66ff71a2f1641d633afef9c3aceabf329300743a75cf54950771f5c82cd77760",
  "0x9d251910b6876151855d9b585777040d8be9604eda97f74e2f6749b68c25d5e1",
  "0x15a9f9c3f2223476203d95fa2acdeaf0a8d7c078aa17c4b523cc9b98700b1b4b",
  "0xb97e014e858dea1264924e3f7b53dbaecdf4b0a340a933e3f5347d565cf3f850",
  "0x2adf385f6fecd230a822fae3a87dbc113f6433b889e97cbeed76527b1b20047d",
  "0x1148377b763523300bf1e3971339e12a85fa8728612491702dca88027b65f6d2",
  "0xbeaf038584910bd73be36dee94164117878e44488c7bd6702d66153858a5432c",
  "0xdbfbeb63cfda4bbd03abf2d55303b758dc950fd33b24733af135611ab81a151e",
  "0x1789ea0044500a4603ca7a3cdd388c4ffa00d005340bc0478a97e9112f223926",
  "0x26f14a8c5d7f981c8543b136b8a6870a9759e3db5b8399ba10b9c4f18fdc3c4a",
  "0x20264e5bec8324e22f6b85978a6f0f39d2f760e1d59511ffc962fd2eb6625205",
  "0x909a43cc2fff0b7ea0c0cd34596a1dd1892a81b7e4dc51ce7dbb7c375ce11f48",
  "0xb79595a2b8dc85a4139af88d6e76e0d006e2c544f98d2302828a4f34e8bac2f1",
  "0xc29172ca342747e1075ecb24f745555bb8892788c385750c0cec9709798138a2",
  "0x6b92122b6354afd31aeccc6d72dd6acf2413a60ceaf85e47e57020a6d1e404f9",
  "0x317706310ca6b248e7121e10961ebd3b8180abc7b1923c7b57a538a334005244",
  "0xf0bb033bc0bc3c690a0cdb020d827411b9616fad6977e373898c2943ca291f66",
  "0xd0658888c554b3710cafc525b996791de0b62534862548882a9bf0ac0780445c",
  "0xaef57f88064785eac91aac33f99e360f8a1bbb8e277cf85116be054779635a8a",
  "0x2cd6cdefc084dbd716a7809378d7f29a5fa05961b823309a6188c7cb7f89fe9c",
  "0x6c6d5ef40f3df4ed4a0507c58462b186fc7fc5f70512874f06126a7013c016f5",
  "0x935dd929fde37bf1f1477bf667b22096c1112c7a3eab97481be2caa74441f931",
  // Historical D8 fresh-combined acceptance run (deposit, withdrawal, disclosed action_reference)
  "0xb842657c79d72cb740f578a5c4f95ae1b1d7c7be3434e0672e7da3bf9576ea09",
  "0x4578237da261536c68801dfbd7c321695a1dd4b31165999d6ae92d696c0b79e6",
  "0xc2b907b4a1fa13da1a042a0d4e67ebf0765e73aeeacacbd218668102baf962f8",
]);

export function assertProductionOrigin(value) {
  const url = new URL(value);
  if (url.protocol !== "https:" || url.origin !== PRODUCTION_URL || (url.pathname !== "/" && url.pathname !== "/audit" && url.pathname !== "/shield") || url.search || url.hash) {
    throw new Error(`INVALID_PRODUCTION_ORIGIN: Expected ${PRODUCTION_URL}, received ${value}`);
  }
  return url.origin;
}

export function verifyCombinedEvidenceManifest(manifest, options = {}) {
  if (!manifest || typeof manifest !== "object") {
    throw new Error("INVALID_MANIFEST_OBJECT");
  }
  if (manifest.schema === "haze-fuji-mvp-acceptance-v2") {
    return verifyFujiMvpV2Manifest(manifest, options);
  }

  const errors = [];

  // 1. Schema & Status
  if (manifest.schema !== "haze-combined-fuji-acceptance-v1") {
    errors.push(`INVALID_SCHEMA: ${manifest.schema}`);
  }
  if (manifest.status !== "PASS") {
    errors.push(`INVALID_STATUS: ${manifest.status}`);
  }
  try {
    assertProductionOrigin(manifest.origin);
  } catch (err) {
    throw new Error(err.message);
  }

  if (!manifest.vercelDeploymentId || !manifest.vercelDeploymentId.startsWith("dpl_")) {
    errors.push(`INVALID_VERCEL_DEPLOYMENT_ID: ${manifest.vercelDeploymentId}`);
  }
  if (!manifest.candidateGitSha || !/^[0-9a-f]{7,40}$/i.test(manifest.candidateGitSha)) {
    errors.push(`INVALID_CANDIDATE_GIT_SHA: ${manifest.candidateGitSha}`);
  }
  if (manifest.deployment?.ready !== true || manifest.deployment?.sourceShaVerified !== true) {
    throw new Error("DEPLOYMENT_SOURCE_UNVERIFIED: Ready deployment must be independently bound to candidateGitSha");
  }
  if (manifest.deployment?.dirty === true || manifest.deployment?.clean === false) {
    throw new Error("DIRTY_DEPLOYMENT_REJECTED: Manifest deployment metadata indicates dirty source state");
  }
  if (!manifest.deployment?.sourceSha) {
    throw new Error("DEPLOYMENT_SOURCE_SHA_MISMATCH: Missing deployment source SHA in manifest");
  }
  const normalizedCandidate = manifest.candidateGitSha.toLowerCase();
  const normalizedSource = manifest.deployment.sourceSha.toLowerCase();
  if (!normalizedCandidate.startsWith(normalizedSource) && !normalizedSource.startsWith(normalizedCandidate)) {
    throw new Error(`DEPLOYMENT_SOURCE_SHA_MISMATCH: Candidate SHA ${manifest.candidateGitSha} does not match deployment source SHA ${manifest.deployment.sourceSha}`);
  }

  // 3. Chain & Named CLI Session
  if (manifest.chainId !== 43113) {
    throw new Error(`INVALID_CHAIN_ID: ${manifest.chainId}`);
  }
  if (!manifest.namedCliSession || typeof manifest.namedCliSession !== "string") {
    throw new Error("MISSING_NAMED_CLI_SESSION: Evidence must include a named playwright-cli session");
  }
  if (!manifest.tools || !manifest.tools.playwrightCli) {
    throw new Error("PLAYWRIGHT_CLI_REQUIRED: Named CLI session must be executed via playwright-cli tool");
  }

  // 4. Fresh On-Chain Transactions (Reject Historical)
  if (!manifest.deposit || !manifest.deposit.hash) {
    errors.push("MISSING_DEPOSIT_EVIDENCE");
  } else {
    const depHash = manifest.deposit.hash.toLowerCase();
    if (HISTORICAL_TRANSACTION_HASHES.has(depHash)) {
      throw new Error(`REUSED_HISTORICAL_TRANSACTION_HASH: Deposit hash ${depHash} is a known historical transaction`);
    }
    if (manifest.deposit.status !== 1) {
      throw new Error(`TRANSACTION_REVERTED: Deposit transaction status is ${manifest.deposit.status}`);
    }
    if (manifest.deposit.recoveredAfterReload !== true) {
      throw new Error("DEPOSIT_NOTE_RECOVERY_REQUIRED: Deposit note must be recovered after page reload");
    }
    verifyTransactionEvidence(manifest.deposit, "Deposit");
  }

  if (!manifest.withdrawal || !manifest.withdrawal.hash) {
    errors.push("MISSING_WITHDRAWAL_EVIDENCE");
  } else {
    const withHash = manifest.withdrawal.hash.toLowerCase();
    if (HISTORICAL_TRANSACTION_HASHES.has(withHash)) {
      throw new Error(`REUSED_HISTORICAL_TRANSACTION_HASH: Withdrawal hash ${withHash} is a known historical transaction`);
    }
    if (manifest.withdrawal.status !== 1) {
      throw new Error(`TRANSACTION_REVERTED: Withdrawal transaction status is ${manifest.withdrawal.status}`);
    }
    if (typeof manifest.withdrawal.confirmations !== "number" || manifest.withdrawal.confirmations < 12) {
      throw new Error(`INSUFFICIENT_FINALITY: Required >= 12 confirmations, observed ${manifest.withdrawal.confirmations}`);
    }
    verifyTransactionEvidence(manifest.withdrawal, "Withdrawal");
  }

  // 5. Auditor Identity & On-Chain Nonce Isolation
  if (!manifest.auditor || !manifest.auditor.address) {
    errors.push("MISSING_AUDITOR_EVIDENCE");
  } else {
    if (manifest.auditor.txCountBefore !== manifest.auditor.txCountAfter) {
      throw new Error(`AUDITOR_TX_COUNT_CHANGED: Before ${manifest.auditor.txCountBefore} !== After ${manifest.auditor.txCountAfter}`);
    }
  }

  // 6. Case & Disclosure Scoping (Exact 5 granted, 0 denied/PII)
  if (!manifest.caseId) {
    errors.push("MISSING_CASE_ID");
  }

  if (!manifest.disclosure) {
    errors.push("MISSING_DISCLOSURE_EVIDENCE");
  } else {
    const granted = manifest.disclosure.grantedFields || [];
    const expectedGranted = ["tx_hash", "amount", "asset", "timestamp", "policy_version"];
    if (granted.length !== expectedGranted.length || granted.some((field) => !expectedGranted.includes(field))) {
      throw new Error(`EXCESS_DISCLOSURE_FIELD: Expected exactly ${expectedGranted.join(",")}`);
    }
    for (const field of expectedGranted) {
      if (!granted.includes(field)) {
        errors.push(`MISSING_GRANTED_FIELD: ${field}`);
      }
    }

    const fields = manifest.disclosure.fields || {};
    if (fields.user !== undefined || fields.counterparty !== undefined || manifest.disclosure.user !== undefined) {
      throw new Error("DENIED_FIELD_EXPOSED: Denied PII field 'user' or 'counterparty' was exposed in disclosure");
    }
    const excessField = Object.keys(fields).find((field) => !expectedGranted.includes(field));
    if (excessField) throw new Error(`EXCESS_DISCLOSURE_FIELD: ${excessField}`);

    if ((manifest.disclosure.passedChecksCount ?? 0) < 6) {
      errors.push(`INSUFFICIENT_PASSED_CHECKS: Required 6, observed ${manifest.disclosure.passedChecksCount}`);
    }
    if (manifest.disclosure.caseId !== manifest.caseId) {
      throw new Error(`CASE_ID_MISMATCH: ${manifest.disclosure.caseId} !== ${manifest.caseId}`);
    }
    if (manifest.disclosure.transactionHash?.toLowerCase() !== manifest.withdrawal?.hash?.toLowerCase()) {
      throw new Error("CASE_TRANSACTION_MISMATCH: Disclosure is not bound to the fresh withdrawal");
    }
    if (fields.tx_hash?.toLowerCase() !== manifest.withdrawal?.hash?.toLowerCase()) {
      throw new Error("DISCLOSED_TRANSACTION_MISMATCH: Disclosed tx_hash is not the fresh withdrawal");
    }
  }

  // 7. Cryptographic Export Verification & Tamper Detection
  if (!manifest.exportVerification || manifest.exportVerification.verified !== true) {
    throw new Error("EXPORT_SIGNATURE_INVALID: Detached JWS signature could not be verified against JWKS");
  }
  if (manifest.exportVerification.tamperDetected !== true) {
    throw new Error("TAMPER_DETECTION_REQUIRED: Tamper mutation test must successfully detect altered fields");
  }

  // 8. Access Logs
  if (!manifest.accessLog || typeof manifest.accessLog.entryCount !== "number" || manifest.accessLog.entryCount < 2) {
    throw new Error(`ACCESS_LOGS_REQUIRED: Access log must record at least 2 entries, observed ${manifest.accessLog?.entryCount}`);
  }

  // 9. Mobile & Negative Security
  if (!manifest.mobileView || manifest.mobileView.noHorizontalOverflow !== true) {
    errors.push("MOBILE_OVERFLOW_DETECTED: Mobile viewport has horizontal scroll overflow");
  }
  if (!manifest.negativeSecurity || manifest.negativeSecurity.unauthenticatedRejected401 !== true) {
    errors.push("NEGATIVE_SECURITY_FAILED: Unauthenticated requests did not fail closed");
  }

  // 10. Required Artifacts Completeness
  if (!manifest.artifacts || !manifest.artifacts.screenshots) {
    throw new Error("INCOMPLETE_ARTIFACTS: Missing screenshots manifest");
  }

  const requiredScreenshots = ["depositRecovery", "withdrawal", "login", "disclosure", "export", "mobile"];
  for (const s of requiredScreenshots) {
    if (!manifest.artifacts.screenshots[s]) {
      throw new Error(`INCOMPLETE_ARTIFACTS: Missing screenshot artifact '${s}'`);
    }
  }

  for (const artifact of ["trace", "consoleLog", "networkLog"]) {
    if (!manifest.artifacts[artifact]) {
      throw new Error(`INCOMPLETE_ARTIFACTS: Missing ${artifact} artifact`);
    }
  }

  const requiredTimestamps = ["startedAt", "depositCompletedAt", "withdrawalCompletedAt", "finalityReachedAt", "cliWalkCompletedAt", "finishedAt"];
  if (!manifest.timestamps || requiredTimestamps.some((key) => !manifest.timestamps[key] || Number.isNaN(Date.parse(manifest.timestamps[key])))) {
    throw new Error("INCOMPLETE_TIMESTAMPS: All acceptance stages require ISO timestamps");
  }

  if (!options.skipFileExistence) {
    const outputDir = join(ROOT, "../output/playwright");
    for (const [key, filename] of Object.entries(manifest.artifacts.screenshots)) {
      const fullPath = join(outputDir, filename);
      if (!existsSync(fullPath) || statSync(fullPath).size === 0) {
        errors.push(`ARTIFACT_FILE_MISSING: Screenshot ${key} (${fullPath}) does not exist or is empty`);
      }
    }
    for (const artifact of ["trace", "consoleLog", "networkLog"]) {
      const fullPath = join(outputDir, manifest.artifacts[artifact]);
      if (!existsSync(fullPath) || statSync(fullPath).size === 0) {
        errors.push(`ARTIFACT_FILE_MISSING: ${artifact} (${fullPath}) does not exist or is empty`);
      }
    }
  }

  if (errors.length > 0) {
    throw new Error(`EVIDENCE_VERIFICATION_FAILED:\n${errors.join("\n")}`);
  }

  return { valid: true, errors: [] };
}

export function verifyFujiMvpV2Manifest(manifest, options = {}) {
  const errors = [];

  // 1. Schema & Status
  if (manifest.schema !== "haze-fuji-mvp-acceptance-v2") {
    errors.push(`INVALID_SCHEMA: ${manifest.schema}`);
  }
  if (manifest.status !== "PASS") {
    errors.push(`INVALID_STATUS: ${manifest.status}`);
  }

  // 2. Production Origin & Deployment Identifiers
  try {
    assertProductionOrigin(manifest.origin);
  } catch (err) {
    throw new Error(err.message);
  }

  if (!manifest.candidateGitSha || !/^[0-9a-f]{7,40}$/i.test(manifest.candidateGitSha)) {
    errors.push(`INVALID_CANDIDATE_GIT_SHA: ${manifest.candidateGitSha}`);
  }

  if (manifest.deployment) {
    if (manifest.deployment.ready !== true || manifest.deployment.sourceShaVerified !== true) {
      throw new Error("DEPLOYMENT_SOURCE_UNVERIFIED: Ready deployment must be independently bound to candidateGitSha");
    }
    if (manifest.deployment.dirty === true || manifest.deployment.clean === false) {
      throw new Error("DIRTY_DEPLOYMENT_REJECTED: Manifest deployment metadata indicates dirty source state");
    }
    if (manifest.deployment.sourceSha) {
      const normalizedCandidate = manifest.candidateGitSha.toLowerCase();
      const normalizedSource = manifest.deployment.sourceSha.toLowerCase();
      if (!normalizedCandidate.startsWith(normalizedSource) && !normalizedSource.startsWith(normalizedCandidate)) {
        throw new Error(`DEPLOYMENT_SOURCE_SHA_MISMATCH: Candidate SHA ${manifest.candidateGitSha} does not match deployment source SHA ${manifest.deployment.sourceSha}`);
      }
    }
  }

  // 3. Chain & Named CLI Session
  if (manifest.chainId !== 43113) {
    throw new Error(`INVALID_CHAIN_ID: ${manifest.chainId}`);
  }
  if (!manifest.namedCliSession || typeof manifest.namedCliSession !== "string") {
    throw new Error("MISSING_NAMED_CLI_SESSION: Evidence must include a named playwright-cli session");
  }
  if (!manifest.tools || !manifest.tools.playwrightCli) {
    throw new Error("PLAYWRIGHT_CLI_REQUIRED: Named CLI session must be executed via playwright-cli tool");
  }

  // 4. Accounts verification
  if (!options.shieldOnly) {
    const accA = manifest.accounts?.accountA?.address;
    const accB = manifest.accounts?.accountB?.address;
    if (!accA || !/^0x[0-9a-f]{40}$/i.test(accA)) {
      errors.push("MISSING_OR_INVALID_ACCOUNT_A");
    }
    if (!accB || !/^0x[0-9a-f]{40}$/i.test(accB)) {
      errors.push("MISSING_OR_INVALID_ACCOUNT_B");
    }
    if (accA && accB && accA.toLowerCase() === accB.toLowerCase()) {
      throw new Error("ACCOUNTS_NOT_DISTINCT: Acceptance journey requires two distinct accounts (A and B)");
    }
  }

  // 5. Operations verification (Shield, Send, Withdraw, Swap)
  if (!manifest.operations || Object.keys(manifest.operations).length === 0) {
    throw new Error("MISSING_OPERATIONS_EVIDENCE");
  }

  const shield = manifest.operations?.shield;
  if (!shield) {
    errors.push("MISSING_SHIELD_EVIDENCE");
  } else {
    if (!shield.transactionHash || !/^0x[0-9a-f]{64}$/i.test(shield.transactionHash)) {
      errors.push("INVALID_SHIELD_TRANSACTION_HASH");
    } else if (HISTORICAL_TRANSACTION_HASHES.has(shield.transactionHash.toLowerCase())) {
      throw new Error(`REUSED_HISTORICAL_TRANSACTION_HASH: Shield hash ${shield.transactionHash} is a known historical transaction`);
    }
    if (shield.phase !== "finalized") {
      errors.push(`SHIELD_NOT_FINALIZED: current phase is ${shield.phase}`);
    }
    if (typeof shield.confirmationCount !== "number" || shield.confirmationCount < 12) {
      throw new Error(`INSUFFICIENT_FINALITY: Shield required >= 12 confirmations, observed ${shield.confirmationCount}`);
    }
    if (shield.action !== 1) {
      errors.push(`SHIELD_ACTION_MISMATCH: expected action 1, observed ${shield.action}`);
    }
    if (shield.receipt && Number(shield.receipt.status) !== 1) {
      throw new Error(`TRANSACTION_REVERTED: Shield transaction receipt status is ${shield.receipt.status}`);
    }
  }

  if (!options.shieldOnly) {
    const send = manifest.operations?.send;
    if (!send) {
      errors.push("MISSING_SEND_EVIDENCE: Complete MVP acceptance requires Send operation");
    } else {
      if (!send.transactionHash || !/^0x[0-9a-f]{64}$/i.test(send.transactionHash)) {
        errors.push("INVALID_SEND_TRANSACTION_HASH");
      } else if (HISTORICAL_TRANSACTION_HASHES.has(send.transactionHash.toLowerCase())) {
        throw new Error(`REUSED_HISTORICAL_TRANSACTION_HASH: Send hash ${send.transactionHash} is a known historical transaction`);
      }
      if (send.phase !== "finalized") {
        errors.push(`SEND_NOT_FINALIZED: current phase is ${send.phase}`);
      }
      if (typeof send.confirmationCount !== "number" || send.confirmationCount < 12) {
        throw new Error(`INSUFFICIENT_FINALITY: Send required >= 12 confirmations, observed ${send.confirmationCount}`);
      }
      if (send.action !== 2) {
        errors.push(`SEND_ACTION_MISMATCH: expected action 2, observed ${send.action}`);
      }
    }

    const withdraw = manifest.operations?.withdraw;
    if (!withdraw) {
      errors.push("MISSING_WITHDRAW_EVIDENCE: Complete MVP acceptance requires Withdraw operation");
    } else {
      if (!withdraw.transactionHash || !/^0x[0-9a-f]{64}$/i.test(withdraw.transactionHash)) {
        errors.push("INVALID_WITHDRAW_TRANSACTION_HASH");
      } else if (HISTORICAL_TRANSACTION_HASHES.has(withdraw.transactionHash.toLowerCase())) {
        throw new Error(`REUSED_HISTORICAL_TRANSACTION_HASH: Withdraw hash ${withdraw.transactionHash} is a known historical transaction`);
      }
      if (withdraw.phase !== "finalized") {
        errors.push(`WITHDRAW_NOT_FINALIZED: current phase is ${withdraw.phase}`);
      }
      if (typeof withdraw.confirmationCount !== "number" || withdraw.confirmationCount < 12) {
        throw new Error(`INSUFFICIENT_FINALITY: Withdraw required >= 12 confirmations, observed ${withdraw.confirmationCount}`);
      }
      if (withdraw.action !== 3) {
        errors.push(`WITHDRAW_ACTION_MISMATCH: expected action 3, observed ${withdraw.action}`);
      }
    }

    const swap = manifest.operations?.swap;
    if (!swap) {
      errors.push("MISSING_SWAP_EVIDENCE: Complete MVP acceptance requires Swap operation");
    } else {
      if (!swap.transactionHash || !/^0x[0-9a-f]{64}$/i.test(swap.transactionHash)) {
        errors.push("INVALID_SWAP_TRANSACTION_HASH");
      } else if (HISTORICAL_TRANSACTION_HASHES.has(swap.transactionHash.toLowerCase())) {
        throw new Error(`REUSED_HISTORICAL_TRANSACTION_HASH: Swap hash ${swap.transactionHash} is a known historical transaction`);
      }
      if (swap.phase !== "finalized") {
        errors.push(`SWAP_NOT_FINALIZED: current phase is ${swap.phase}`);
      }
      if (typeof swap.confirmationCount !== "number" || swap.confirmationCount < 12) {
        throw new Error(`INSUFFICIENT_FINALITY: Swap required >= 12 confirmations, observed ${swap.confirmationCount}`);
      }
      if (swap.action !== 4) {
        errors.push(`SWAP_ACTION_MISMATCH: expected action 4, observed ${swap.action}`);
      }
    }

    // 6. Auditor case verification
    if (!manifest.auditorCase) {
      errors.push("MISSING_AUDITOR_CASE: Complete MVP acceptance requires verified auditor case");
    } else {
      if (!manifest.auditorCase.caseId) {
        errors.push("MISSING_CASE_ID");
      }
      if (manifest.auditorCase.verifiedJws !== true) {
        throw new Error("AUDITOR_CASE_JWS_UNVERIFIED: Disclosed export signature must be verified");
      }
      if (withdraw && manifest.auditorCase.withdrawalHash.toLowerCase() !== withdraw.transactionHash.toLowerCase()) {
        throw new Error("AUDITOR_CASE_WITHDRAWAL_MISMATCH: Auditor case does not match withdrawal hash");
      }
    }
  }

  if (errors.length > 0) {
    throw new Error(`EVIDENCE_VERIFICATION_FAILED:\n${errors.join("\n")}`);
  }

  return { valid: true, errors: [] };
}

function verifyTransactionEvidence(transaction, label) {
  if (!transaction.receipt || transaction.receipt.status !== 1) {
    throw new Error(`FAILED_RECEIPT_EVIDENCE: ${label}`);
  }
  if (transaction.receipt.transactionHash?.toLowerCase() !== transaction.hash.toLowerCase()) {
    throw new Error(`RECEIPT_HASH_MISMATCH: ${label}`);
  }
  if (!transaction.event || transaction.event.name !== "PrivateTransaction") {
    throw new Error(`MISSING_EXPECTED_EVENT: ${label}`);
  }
  if (transaction.event.transactionHash?.toLowerCase() !== transaction.hash.toLowerCase()) {
    throw new Error(`EVENT_HASH_MISMATCH: ${label}`);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const filePath = process.argv[2] || join(ROOT, "../output/playwright/fresh-combined-fuji-acceptance.json");
  if (!existsSync(filePath)) {
    console.error(`Evidence file not found: ${filePath}`);
    process.exit(1);
  }
  try {
    const raw = readFileSync(filePath, "utf8");
    const manifest = JSON.parse(raw);
    verifyCombinedEvidenceManifest(manifest);
    console.log(`[PASS] Evidence manifest verified successfully: ${filePath}`);
    process.exit(0);
  } catch (err) {
    console.error(`[FAIL] Evidence verification failed:`, err.message);
    process.exit(1);
  }
}
