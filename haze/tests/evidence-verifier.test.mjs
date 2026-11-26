import assert from "node:assert/strict";
import test from "node:test";
import {
  verifyCombinedEvidenceManifest,
  HISTORICAL_TRANSACTION_HASHES,
} from "../dev/evidence-verifier.mjs";
import { PRODUCTION_URL } from "../dev/production-origin.mjs";

function createValidFixture() {
  return {
    schema: "haze-combined-fuji-acceptance-v1",
    status: "PASS",
    origin: PRODUCTION_URL,
    vercelDeploymentId: "dpl_5k49FKLRHpVpb6sQXDt3SEE6bYMA",
    candidateGitSha: "901c4b5bc11a765d012c4e9280e0539c5375c185",
    deployment: {
      ready: true,
      sourceShaVerified: true,
      clean: true,
      dirty: false,
      sourceSha: "901c4b5bc11a765d012c4e9280e0539c5375c185",
    },
    network: "Avalanche Fuji",
    chainId: 43113,
    namedCliSession: "haze-d8-fuji-live",
    tools: {
      node: process.version,
      playwrightCli: "0.1.18",
      dappwright: "2.13.12",
      playwrightCore: "1.62.1",
    },
    deposit: {
      hash: "0xaa11111111111111111111111111111111111111111111111111111111111111",
      status: 1,
      blockNumber: 57900001,
      destination: "0x00beb0a5d709d0f093952fd374dbbf3d0d21d550",
      commitment: "0x1111111111111111111111111111111111111111111111111111111111111111",
      recoveredAfterReload: true,
      receipt: { transactionHash: "0xaa11111111111111111111111111111111111111111111111111111111111111", status: 1 },
      event: { name: "PrivateTransaction", transactionHash: "0xaa11111111111111111111111111111111111111111111111111111111111111" },
    },
    withdrawal: {
      hash: "0xbb22222222222222222222222222222222222222222222222222222222222222",
      status: 1,
      blockNumber: 57900015,
      destination: "0x00beb0a5d709d0f093952fd374dbbf3d0d21d550",
      nullifier: "0x2222222222222222222222222222222222222222222222222222222222222222",
      confirmations: 25,
      receipt: { transactionHash: "0xbb22222222222222222222222222222222222222222222222222222222222222", status: 1 },
      event: { name: "PrivateTransaction", transactionHash: "0xbb22222222222222222222222222222222222222222222222222222222222222" },
    },
    caseId: "fuji-withdrawal-bb222222",
    auditor: {
      address: "0xed37fd0d6f0f69236e7472b36796e133d20ecc32",
      txCountBefore: "0x150",
      txCountAfter: "0x150",
    },
    disclosure: {
      grantedFields: ["tx_hash", "amount", "asset", "timestamp", "policy_version"],
      deniedFields: ["user", "counterparty"],
      fields: {
        tx_hash: "0xbb22222222222222222222222222222222222222222222222222222222222222",
        amount: "1.000000 USDC",
        asset: "0x5425890298aed601595a70AB815c96711a31Bc65",
        timestamp: "2026-08-24T04:25:00.000Z",
        policy_version: "1",
      },
      caseId: "fuji-withdrawal-bb222222",
      transactionHash: "0xbb22222222222222222222222222222222222222222222222222222222222222",
      checksCount: 6,
      passedChecksCount: 6,
    },
    exportVerification: {
      verified: true,
      signingKeyId: "fuji-compliance-signer-v1",
      tamperDetected: true,
    },
    accessLog: {
      entryCount: 3,
      operations: ["auth", "query", "export"],
    },
    mobileView: {
      viewport: { width: 390, height: 844 },
      noHorizontalOverflow: true,
    },
    negativeSecurity: {
      unauthenticatedRejected401: true,
      adminForbidden: true,
      governanceForbidden: true,
      logoutRevokedSession: true,
    },
    artifacts: {
      screenshots: {
        depositRecovery: "dapp-fuji-fresh-deposit-recovery.png",
        withdrawal: "dapp-fuji-fresh-withdrawal.png",
        login: "fresh-audit-login.png",
        disclosure: "fresh-audit-disclosure.png",
        export: "fresh-audit-export.png",
        mobile: "fresh-audit-mobile.png",
      },
      trace: "fresh-audit-trace.zip",
      consoleLog: "fresh-audit-console.log",
      networkLog: "fresh-audit-network.log",
    },
    timestamps: {
      startedAt: "2026-08-24T04:20:00.000Z",
      depositCompletedAt: "2026-08-24T04:21:00.000Z",
      withdrawalCompletedAt: "2026-08-24T04:22:00.000Z",
      finalityReachedAt: "2026-08-24T04:24:00.000Z",
      cliWalkCompletedAt: "2026-08-24T04:26:00.000Z",
      finishedAt: "2026-08-24T04:26:30.000Z",
    },
  };
}

test("Evidence verifier accepts a fully valid fresh manifest", () => {
  const manifest = createValidFixture();
  const result = verifyCombinedEvidenceManifest(manifest, { skipFileExistence: true });
  assert.equal(result.valid, true);
  assert.equal(result.errors.length, 0);
});

test("Evidence verifier denylists stale D8 fresh-combined hashes", () => {
  const staleD8Hashes = [
    "0xb842657c79d72cb740f578a5c4f95ae1b1d7c7be3434e0672e7da3bf9576ea09",
    "0x4578237da261536c68801dfbd7c321695a1dd4b31165999d6ae92d696c0b79e6",
    "0xc2b907b4a1fa13da1a042a0d4e67ebf0765e73aeeacacbd218668102baf962f8",
  ];
  for (const hash of staleD8Hashes) {
    assert.equal(HISTORICAL_TRANSACTION_HASHES.has(hash), true, `expected ${hash} in denylist`);
  }
});

test("Evidence verifier rejects missing or null named CLI session", () => {
  const manifest = createValidFixture();
  manifest.namedCliSession = null;
  assert.throws(
    () => verifyCombinedEvidenceManifest(manifest, { skipFileExistence: true }),
    /MISSING_NAMED_CLI_SESSION/,
  );

  delete manifest.namedCliSession;
  assert.throws(
    () => verifyCombinedEvidenceManifest(manifest, { skipFileExistence: true }),
    /MISSING_NAMED_CLI_SESSION/,
  );
});

test("Evidence verifier rejects direct-API-only evidence without playwright-cli tool", () => {
  const manifest = createValidFixture();
  delete manifest.tools.playwrightCli;
  assert.throws(
    () => verifyCombinedEvidenceManifest(manifest, { skipFileExistence: true }),
    /PLAYWRIGHT_CLI_REQUIRED/,
  );
});

test("Evidence verifier rejects reused historical transaction hashes", () => {
  for (const historicalHash of HISTORICAL_TRANSACTION_HASHES) {
    const manifestDep = createValidFixture();
    manifestDep.deposit.hash = historicalHash;
    assert.throws(
      () => verifyCombinedEvidenceManifest(manifestDep, { skipFileExistence: true }),
      /REUSED_HISTORICAL_TRANSACTION_HASH/,
    );

    const manifestWith = createValidFixture();
    manifestWith.withdrawal.hash = historicalHash;
    assert.throws(
      () => verifyCombinedEvidenceManifest(manifestWith, { skipFileExistence: true }),
      /REUSED_HISTORICAL_TRANSACTION_HASH/,
    );
  }
});

test("Evidence verifier rejects preview, localhost, or invalid production origins", () => {
  const invalidOrigins = [
    "http://localhost:3000",
    "http://127.0.0.1:3013",
    "https://haze-preview-pr12.vercel.app",
    "https://example.com",
  ];
  for (const origin of invalidOrigins) {
    const manifest = createValidFixture();
    manifest.origin = origin;
    assert.throws(
      () => verifyCombinedEvidenceManifest(manifest, { skipFileExistence: true }),
      /INVALID_PRODUCTION_ORIGIN/,
    );
  }
});

test("Evidence verifier rejects incorrect chain ID", () => {
  const manifest = createValidFixture();
  manifest.chainId = 43114;
  assert.throws(
    () => verifyCombinedEvidenceManifest(manifest, { skipFileExistence: true }),
    /INVALID_CHAIN_ID/,
  );
});

test("Evidence verifier rejects reverted or unconfirmed receipts", () => {
  const manifestDep = createValidFixture();
  manifestDep.deposit.status = 0;
  assert.throws(
    () => verifyCombinedEvidenceManifest(manifestDep, { skipFileExistence: true }),
    /TRANSACTION_REVERTED/,
  );

  const manifestWith = createValidFixture();
  manifestWith.withdrawal.status = 0;
  assert.throws(
    () => verifyCombinedEvidenceManifest(manifestWith, { skipFileExistence: true }),
    /TRANSACTION_REVERTED/,
  );
});

test("Evidence verifier rejects missing events and receipt/hash mismatches", () => {
  const missingEvent = createValidFixture();
  delete missingEvent.deposit.event;
  assert.throws(() => verifyCombinedEvidenceManifest(missingEvent, { skipFileExistence: true }), /MISSING_EXPECTED_EVENT/);

  const receiptMismatch = createValidFixture();
  receiptMismatch.withdrawal.receipt.transactionHash = receiptMismatch.deposit.hash;
  assert.throws(() => verifyCombinedEvidenceManifest(receiptMismatch, { skipFileExistence: true }), /RECEIPT_HASH_MISMATCH/);
});

test("Evidence verifier binds the dynamically ingested case and disclosure to the fresh withdrawal", () => {
  const wrongCase = createValidFixture();
  wrongCase.disclosure.caseId = "fuji-withdrawal-other";
  assert.throws(() => verifyCombinedEvidenceManifest(wrongCase, { skipFileExistence: true }), /CASE_ID_MISMATCH/);

  const wrongTransaction = createValidFixture();
  wrongTransaction.disclosure.transactionHash = wrongTransaction.deposit.hash;
  assert.throws(() => verifyCombinedEvidenceManifest(wrongTransaction, { skipFileExistence: true }), /CASE_TRANSACTION_MISMATCH/);

  const wrongDisclosedTransaction = createValidFixture();
  wrongDisclosedTransaction.disclosure.fields.tx_hash = wrongDisclosedTransaction.deposit.hash;
  assert.throws(
    () => verifyCombinedEvidenceManifest(wrongDisclosedTransaction, { skipFileExistence: true }),
    /DISCLOSED_TRANSACTION_MISMATCH/,
  );
});

test("Evidence verifier rejects insufficient finality (< 12 confirmations)", () => {
  const manifest = createValidFixture();
  manifest.withdrawal.confirmations = 11;
  assert.throws(
    () => verifyCombinedEvidenceManifest(manifest, { skipFileExistence: true }),
    /INSUFFICIENT_FINALITY/,
  );
});

test("Evidence verifier rejects unrecovered deposit note", () => {
  const manifest = createValidFixture();
  manifest.deposit.recoveredAfterReload = false;
  assert.throws(
    () => verifyCombinedEvidenceManifest(manifest, { skipFileExistence: true }),
    /DEPOSIT_NOTE_RECOVERY_REQUIRED/,
  );
});

test("Evidence verifier rejects excess or PII fields in disclosed record", () => {
  const manifestUser = createValidFixture();
  manifestUser.disclosure.fields.user = "0xed37fd0d6f0f69236e7472b36796e133d20ecc32";
  assert.throws(
    () => verifyCombinedEvidenceManifest(manifestUser, { skipFileExistence: true }),
    /DENIED_FIELD_EXPOSED/,
  );

  const manifestCounterparty = createValidFixture();
  manifestCounterparty.disclosure.fields.counterparty = "0x0000000000000000000000000000000000000000";
  assert.throws(
    () => verifyCombinedEvidenceManifest(manifestCounterparty, { skipFileExistence: true }),
    /DENIED_FIELD_EXPOSED/,
  );

  const manifestExtra = createValidFixture();
  manifestExtra.disclosure.grantedFields.push("memo");
  manifestExtra.disclosure.fields.memo = "excess";
  assert.throws(() => verifyCombinedEvidenceManifest(manifestExtra, { skipFileExistence: true }), /EXCESS_DISCLOSURE_FIELD/);
});

test("Evidence verifier rejects unverified or tampered export signature", () => {
  const manifest = createValidFixture();
  manifest.exportVerification.verified = false;
  assert.throws(
    () => verifyCombinedEvidenceManifest(manifest, { skipFileExistence: true }),
    /EXPORT_SIGNATURE_INVALID/,
  );

  const manifestTamper = createValidFixture();
  manifestTamper.exportVerification.tamperDetected = false;
  assert.throws(
    () => verifyCombinedEvidenceManifest(manifestTamper, { skipFileExistence: true }),
    /TAMPER_DETECTION_REQUIRED/,
  );
});

test("Evidence verifier rejects missing access logs", () => {
  const manifest = createValidFixture();
  manifest.accessLog.entryCount = 0;
  assert.throws(
    () => verifyCombinedEvidenceManifest(manifest, { skipFileExistence: true }),
    /ACCESS_LOGS_REQUIRED/,
  );
});

test("Evidence verifier rejects altered auditor on-chain nonce", () => {
  const manifest = createValidFixture();
  manifest.auditor.txCountBefore = "0x150";
  manifest.auditor.txCountAfter = "0x151";
  assert.throws(
    () => verifyCombinedEvidenceManifest(manifest, { skipFileExistence: true }),
    /AUDITOR_TX_COUNT_CHANGED/,
  );
});

test("Evidence verifier rejects missing required artifact fields", () => {
  const manifest = createValidFixture();
  delete manifest.artifacts.screenshots.mobile;
  assert.throws(
    () => verifyCombinedEvidenceManifest(manifest, { skipFileExistence: true }),
    /INCOMPLETE_ARTIFACTS/,
  );

  for (const key of ["trace", "consoleLog", "networkLog"]) {
    const incomplete = createValidFixture();
    delete incomplete.artifacts[key];
    assert.throws(() => verifyCombinedEvidenceManifest(incomplete, { skipFileExistence: true }), /INCOMPLETE_ARTIFACTS/);
  }

  const missingTimestamp = createValidFixture();
  delete missingTimestamp.timestamps.cliWalkCompletedAt;
  assert.throws(() => verifyCombinedEvidenceManifest(missingTimestamp, { skipFileExistence: true }), /INCOMPLETE_TIMESTAMPS/);
});

test("Evidence verifier requires independently proven deployment source identity and clean state", () => {
  const manifestUnverified = createValidFixture();
  manifestUnverified.deployment.sourceShaVerified = false;
  assert.throws(() => verifyCombinedEvidenceManifest(manifestUnverified, { skipFileExistence: true }), /DEPLOYMENT_SOURCE_UNVERIFIED/);

  const manifestUnready = createValidFixture();
  manifestUnready.deployment.ready = false;
  assert.throws(() => verifyCombinedEvidenceManifest(manifestUnready, { skipFileExistence: true }), /DEPLOYMENT_SOURCE_UNVERIFIED/);

  const manifestDirty = createValidFixture();
  manifestDirty.deployment.dirty = true;
  assert.throws(() => verifyCombinedEvidenceManifest(manifestDirty, { skipFileExistence: true }), /DIRTY_DEPLOYMENT_REJECTED/);

  const manifestNotClean = createValidFixture();
  manifestNotClean.deployment.clean = false;
  assert.throws(() => verifyCombinedEvidenceManifest(manifestNotClean, { skipFileExistence: true }), /DIRTY_DEPLOYMENT_REJECTED/);

  const manifestMissingSha = createValidFixture();
  delete manifestMissingSha.deployment.sourceSha;
  assert.throws(() => verifyCombinedEvidenceManifest(manifestMissingSha, { skipFileExistence: true }), /DEPLOYMENT_SOURCE_SHA_MISMATCH/);

  const manifestShaMismatch = createValidFixture();
  manifestShaMismatch.deployment.sourceSha = "4143e60c3eec93ba25e7aa8432f2455084d5f39e";
  assert.throws(() => verifyCombinedEvidenceManifest(manifestShaMismatch, { skipFileExistence: true }), /DEPLOYMENT_SOURCE_SHA_MISMATCH/);
});
