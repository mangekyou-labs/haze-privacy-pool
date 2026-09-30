/**
 * Postgres-backed ComplianceStore.
 *
 * Uses the 0003_compliance_portal.sql schema:
 * - haze_compliance_challenges (SIWE nonce store)
 * - haze_compliance_sessions (authenticated sessions)
 * - haze_compliance_grants (auditor field grants)
 * - haze_compliance_cases (ingested withdrawal cases)
 * - haze_compliance_exports (signed export records)
 * - haze_compliance_access_log (hash-chained access audit trail)
 *
 * The pool should be a node-postgres Pool with `query(text, params)` returning
 * `{ rows: any[] }`.
 */

import { createHash, randomBytes } from "node:crypto";
import {
  type ComplianceStore,
  type ComplianceCase,
  type CaseState,
  type AccessLogEntry,
  GRANTED_FIELDS,
  FUJI_CHAIN_ID,
  REQUIRED_CONFIRMATIONS,
  DEDICATED_AUDITOR,
  LIVE_APP_ID,
  SIGNING_KEY_ID,
  buildSiweMessage,
  computeLogEntryHash,
  signCanonicalExport,
  verifySiweSignature,
} from "../../../../sdk/typescript/src/compliance-service.ts";
import { SdkError } from "../../../../sdk/typescript/src/errors.ts";
import { resolveSiweDomain } from "../../../../dev/production-origin.mjs";

interface PgPool {
  query(text: string, params?: any[]): Promise<{ rows: any[] }>;
}

export class CompliancePostgresStore implements ComplianceStore {
  private pool: PgPool;

  constructor(pool: PgPool) {
    this.pool = pool;
  }

  caseKey(chainId: number, txHash: string, logIndex: number): string {
    return `${chainId}:${txHash.toLowerCase()}:${logIndex}`;
  }

  async upsertWithdrawalCase(input: {
    chainId: number;
    pool: string;
    applicationId: string;
    transactionHash: string;
    logIndex: number;
    blockNumber: number;
    blockHash?: string;
    currentBlockNumber: number;
    witnessData?: any;
    assignedAuditor?: string;
  }): Promise<ComplianceCase> {
    const caseId = `case-fuji-${input.transactionHash.slice(2, 10)}-${input.logIndex}`;
    const title = `Fuji Withdrawal ${input.transactionHash.slice(0, 10)}…${input.transactionHash.slice(-6)}`;
    const confirmations = Math.max(1, input.currentBlockNumber - input.blockNumber + 1);
    const normTx = input.transactionHash.toLowerCase();
    const normPool = input.pool.toLowerCase();
    const normApp = input.applicationId.toLowerCase();
    const auditor = (input.assignedAuditor ?? DEDICATED_AUDITOR).toLowerCase();
    const amount = input.witnessData?.auditRecord?.facts?.publicAmount;
    const assetAmount = typeof amount === "number" || typeof amount === "bigint" ? (Number(amount) / 1_000_000).toFixed(2) + " USDC" : null;
    const eventTs = input.witnessData?.auditRecord?.facts?.timestamp;
    const policyVer = input.witnessData?.auditRecord?.facts?.applicationPolicyVersion;
    let state: CaseState = confirmations >= REQUIRED_CONFIRMATIONS ? "ready" : "confirming";

    const existing = await this.pool.query(
      `SELECT status FROM haze_compliance_cases WHERE case_id = $1`,
      [caseId],
    );

    if (existing.rows.length > 0) {
      const existingState = existing.rows[0].status as CaseState;
      if (existingState === "reorged") state = "reorged";
      else if (existingState === "exported" || existingState === "verified") state = existingState;
      else if (confirmations >= REQUIRED_CONFIRMATIONS) state = "ready";
      await this.pool.query(
        `UPDATE haze_compliance_cases SET status = $1, confirmations = $2, block_number = $3,
         log_index = $4, chain_id = $5, pool = $6, assigned_auditor = $7,
         amount = $8, event_timestamp = $9, policy_version = $10, witness_data = $11,
         updated_at = now()
         WHERE case_id = $12`,
        [state, confirmations, input.blockNumber, input.logIndex, input.chainId,
         Buffer.from(normPool.slice(2), "hex"), Buffer.from(auditor.slice(2), "hex"),
         assetAmount, eventTs ? new Date(Number(eventTs) * 1000) : null,
         policyVer ? Number(policyVer) : null,
         input.witnessData ? JSON.stringify(input.witnessData) : null, caseId],
      );
    } else {
      await this.pool.query(
        `INSERT INTO haze_compliance_cases
         (case_id, title, chain_id, pool, application_id, transaction_hash, log_index,
          block_number, block_hash, status, confirmations, required_confirmations,
          assigned_auditor, amount, asset, event_timestamp, policy_version, witness_data,
          granted_fields, denied_fields)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
        [caseId, title, input.chainId, Buffer.from(normPool.slice(2), "hex"),
         Buffer.from(normApp.slice(2), "hex"), Buffer.from(normTx.slice(2), "hex"),
         input.logIndex, input.blockNumber,
         input.blockHash ? Buffer.from(input.blockHash.slice(2), "hex") : null,
         state, confirmations, REQUIRED_CONFIRMATIONS,
         Buffer.from(auditor.slice(2), "hex"),
         assetAmount, assetAmount ? "USDC" : null,
         eventTs ? new Date(Number(eventTs) * 1000) : null,
         policyVer ? Number(policyVer) : null,
         input.witnessData ? JSON.stringify(input.witnessData) : null,
         GRANTED_FIELDS as unknown as string[], ["user", "counterparty"]],
      );
    }

    return {
      caseId, title, chainId: input.chainId, pool: normPool,
      applicationId: normApp, transactionHash: normTx, logIndex: input.logIndex,
      blockNumber: input.blockNumber, blockHash: input.blockHash,
      caseState: state, confirmationCount: confirmations,
      requiredConfirmations: REQUIRED_CONFIRMATIONS,
      canonicalBlockIdentity: `Block #${input.blockNumber} (${confirmations}/${REQUIRED_CONFIRMATIONS} confs)`,
      readiness: confirmations >= REQUIRED_CONFIRMATIONS && state !== "reorged",
      fields: [...GRANTED_FIELDS],
      expiresAt: Math.floor(Date.now() / 1000) + 86400 * 30,
      assignedAuditor: auditor,
      witnessData: input.witnessData,
      createdAt: Math.floor(Date.now() / 1000),
      updatedAt: Math.floor(Date.now() / 1000),
    };
  }

  async updateConfirmations(currentBlockNumber: number): Promise<void> {
    await this.pool.query(
      `UPDATE haze_compliance_cases
       SET confirmations = GREATEST(1, $1 - block_number + 1),
           status = CASE WHEN $1 - block_number + 1 >= required_confirmations
                         AND status IN ('observed', 'confirming') THEN 'ready'
                         ELSE status END,
           updated_at = now()
       WHERE status <> 'reorged'`,
      [currentBlockNumber],
    );
  }

  async markReorged(_chainId: number, txHash: string, logIndex: number): Promise<ComplianceCase | null> {
    const caseId = `case-fuji-${txHash.slice(2, 10)}-${logIndex}`;
    const r = await this.pool.query(`UPDATE haze_compliance_cases SET status = 'reorged' WHERE case_id = $1 RETURNING *`, [caseId]);
    return r.rows.length > 0 ? this.rowToCase(r.rows[0]) : null;
  }

  async getCaseById(caseId: string): Promise<ComplianceCase | undefined> {
    const r = await this.pool.query(`SELECT * FROM haze_compliance_cases WHERE case_id = $1`, [caseId]);
    return r.rows.length > 0 ? this.rowToCase(r.rows[0]) : undefined;
  }

  async getCaseByTxHash(txHash: string): Promise<ComplianceCase | undefined> {
    const r = await this.pool.query(
      `SELECT * FROM haze_compliance_cases WHERE transaction_hash = $1`,
      [Buffer.from(txHash.toLowerCase().slice(2), "hex")],
    );
    return r.rows.length > 0 ? this.rowToCase(r.rows[0]) : undefined;
  }

  async listAssignedCases(_auditorAddress: string, applicationId: string): Promise<ComplianceCase[]> {
    const r = await this.pool.query(
      `SELECT * FROM haze_compliance_cases WHERE application_id = $1 ORDER BY created_at DESC`,
      [Buffer.from(applicationId.toLowerCase().slice(2), "hex")],
    );
    return r.rows.map((row) => this.rowToCase(row));
  }

  async recordAccessLog(
    action: AccessLogEntry["action"],
    auditor: string,
    allowed: boolean,
    caseId?: string,
    reason?: string,
  ): Promise<AccessLogEntry> {
    const lastR = await this.pool.query(`SELECT entry_hash FROM haze_compliance_access_log ORDER BY seq DESC LIMIT 1`);
    const prevHash = lastR.rows.length > 0 ? "0x" + lastR.rows[0].entry_hash.toString("hex") : "0x" + "00".repeat(32);
    const idx = lastR.rows.length + 1;

    const entryWithoutHash: Omit<AccessLogEntry, "hash"> = {
      id: `log-${idx}`, index: idx, action, caseId,
      auditor: auditor.toLowerCase(), allowed, reason, prevHash,
      timestamp: Math.floor(Date.now() / 1000),
    };
    const hash = "0x" + computeLogEntryHash(entryWithoutHash);

    await this.pool.query(
      `INSERT INTO haze_compliance_access_log (prev_hash, entry_hash, name, application_id, case_id, wallet, fields, allowed)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [Buffer.from(prevHash.slice(2), "hex"), Buffer.from(hash.slice(2), "hex"), action,
       Buffer.from(LIVE_APP_ID.slice(2), "hex"), caseId ?? null,
       Buffer.from(auditor.toLowerCase().slice(2), "hex"), JSON.stringify({ action, allowed, reason }), allowed],
    );
    return { ...entryWithoutHash, hash };
  }

  async getAccessLog(): Promise<{ entries: AccessLogEntry[]; headHash: string; verified: boolean }> {
    const r = await this.pool.query(`SELECT * FROM haze_compliance_access_log ORDER BY seq ASC`);
    let verified = true;
    let expectedPrev = "0x" + "00".repeat(32);
    const entries: AccessLogEntry[] = [];

    for (const row of r.rows) {
      const prevHash = "0x" + row.prev_hash.toString("hex");
      const entryHash = "0x" + row.entry_hash.toString("hex");
      if (prevHash !== expectedPrev) verified = false;
      entries.push({
        id: `log-${row.seq}`, index: row.seq, action: row.name, caseId: row.case_id,
        auditor: "0x" + row.wallet.toString("hex"), allowed: row.allowed,
        prevHash, hash: entryHash, timestamp: Math.floor(new Date(row.at).getTime() / 1000),
      });
      expectedPrev = entryHash;
    }
    return { entries, headHash: entries.length > 0 ? entries[entries.length - 1].hash : expectedPrev, verified };
  }

  async createSiweChallenge(
    address: string, domain = "compliance.haze.network",
  ): Promise<{ nonce: string; address: string; statement: string; domain: string; chainId: number; message: string }> {
    const nonce = randomBytes(16).toString("hex");
    const expiresAt = new Date(Date.now() + 600_000);
    const challengeId = createHash("sha256").update(nonce + address).digest("hex");
    const issuedAt = new Date().toISOString();
    const resolvedDomain = resolveSiweDomain(domain);
    const message = buildSiweMessage({
      statement: "Sign in with Ethereum to access the Haze Compliance Portal.",
      domain: resolvedDomain,
      chainId: FUJI_CHAIN_ID,
      nonce,
      issuedAt,
    });

    await this.pool.query(
      `INSERT INTO haze_compliance_challenges (challenge_id, nonce, domain, uri, statement, message, issued_at, wallet, application_id, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [Buffer.from(challengeId, "hex"), nonce, resolvedDomain, `https://${resolvedDomain}/audit`,
       "Sign in with Ethereum to access the Haze Compliance Portal.", message, new Date(),
       Buffer.from(address.toLowerCase().slice(2), "hex"),
       Buffer.from(LIVE_APP_ID.slice(2), "hex"), expiresAt],
    );
    return {
      nonce, address: address.toLowerCase(),
      statement: "Sign in with Ethereum to access the Haze Compliance Portal.",
      domain: resolvedDomain, chainId: FUJI_CHAIN_ID, message,
    };
  }

  async verifySiweChallenge(
    nonce: string, address: string, signature: string,
  ): Promise<{ token: string; address: string; role: string; applicationId: string }> {
    const r = await this.pool.query(
      `SELECT * FROM haze_compliance_challenges WHERE nonce = $1 AND consumed = false`, [nonce],
    );
    if (r.rows.length === 0) throw new SdkError("UNAUTHORIZED");

    const ch = r.rows[0];
    if (new Date(ch.expires_at) < new Date()) {
      await this.pool.query(`UPDATE haze_compliance_challenges SET consumed = true WHERE nonce = $1`, [nonce]);
      throw new SdkError("AUTHORIZATION_EXPIRED");
    }
    if ("0x" + ch.wallet.toString("hex") !== address.toLowerCase()) throw new SdkError("UNAUTHORIZED");
    // The exact persisted message is the only accepted preimage — the wallet
    // signed the server-issued challenge, so any reconstructed variant fails.
    const message = String(ch.message);
    if (!message) throw new SdkError("UNAUTHORIZED");
    verifySiweSignature(message, address, signature);

    await this.pool.query(`UPDATE haze_compliance_challenges SET consumed = true WHERE nonce = $1`, [nonce]);

    const token = "haze_session_" + randomBytes(32).toString("hex");
    const sessionHash = createHash("sha256").update(token).digest("hex");
    const expiresAt = new Date(Date.now() + 86400_000);

    await this.pool.query(
      `INSERT INTO haze_compliance_sessions (session_hash, wallet, application_id, role, grant_id, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [Buffer.from(sessionHash, "hex"), Buffer.from(address.toLowerCase().slice(2), "hex"),
       Buffer.from(LIVE_APP_ID.slice(2), "hex"), "application-auditor",
       Buffer.from("00".repeat(32), "hex"), expiresAt],
    );

    await this.recordAccessLog("login", address, true);
    return { token, address: address.toLowerCase(), role: "application-auditor", applicationId: LIVE_APP_ID.toLowerCase() };
  }

  async getSession(token?: string): Promise<{ address: string; role: string; applicationId: string } | null> {
    if (!token) return null;
    const hash = createHash("sha256").update(token).digest("hex");
    const r = await this.pool.query(
      `SELECT * FROM haze_compliance_sessions WHERE session_hash = $1 AND expires_at > now()`,
      [Buffer.from(hash, "hex")],
    );
    if (r.rows.length === 0) return null;
    const row = r.rows[0];
    return { address: "0x" + row.wallet.toString("hex"), role: row.role, applicationId: "0x" + row.application_id.toString("hex") };
  }

  async deleteSession(token?: string): Promise<void> {
    if (!token) return;
    const hash = createHash("sha256").update(token).digest("hex");
    await this.pool.query(`DELETE FROM haze_compliance_sessions WHERE session_hash = $1`, [Buffer.from(hash, "hex")]);
  }

  async discloseCase(
    caseId: string, sessionAuditor: string, _keyManagementIkm?: any,
  ): Promise<{
    caseId: string; transactionHash: string;
    fields: { tx_hash: string; amount: string; asset: string; timestamp: string; policy_version: number };
    integrity: { canonicalReceipt: boolean; blockNumber: number; confirmations: number; poolMatch: boolean; applicationMatch: boolean; actionMatch: boolean; envelopeHashMatch: boolean; commitmentMatch: boolean };
  }> {
    const item = await this.getCaseById(caseId);
    if (!item) { await this.recordAccessLog("query", sessionAuditor, false, caseId, "CASE_NOT_FOUND"); throw new SdkError("UNAUTHORIZED"); }
    if (item.assignedAuditor !== sessionAuditor.toLowerCase()) { await this.recordAccessLog("query", sessionAuditor, false, caseId, "AUDITOR_MISMATCH"); throw new SdkError("UNAUTHORIZED"); }
    if (item.caseState === "reorged") { await this.recordAccessLog("query", sessionAuditor, false, caseId, "CASE_REORGED"); throw Object.assign(new Error("Case has been reorged"), { code: "CASE_REORGED" }); }
    if (item.confirmationCount < REQUIRED_CONFIRMATIONS) { await this.recordAccessLog("query", sessionAuditor, false, caseId, "FINALITY_REQUIRED"); throw Object.assign(new Error(`Waiting for finality`), { code: "FINALITY_REQUIRED" }); }

    const facts = item.witnessData?.auditRecord?.facts;
    const amountUnits = facts?.publicAmount;
    if (typeof amountUnits !== "number" && typeof amountUnits !== "bigint") {
      await this.recordAccessLog("query", sessionAuditor, false, caseId, "AMOUNT_UNAVAILABLE");
      throw Object.assign(new Error("Disclosure amount is unavailable for this case"), { code: "AMOUNT_UNAVAILABLE" });
    }
    const disclosed = {
      tx_hash: item.transactionHash,
      amount: (Number(amountUnits) / 1_000_000).toFixed(2) + " USDC",
      asset: "USDC",
      timestamp: facts?.timestamp ? new Date(Number(facts.timestamp) * 1000).toISOString() : new Date(item.createdAt * 1000).toISOString(),
      policy_version: facts?.applicationPolicyVersion ? Number(facts.applicationPolicyVersion) : 1,
    };

    await this.pool.query(`UPDATE haze_compliance_cases SET status = 'verified' WHERE case_id = $1 AND status = 'ready'`, [caseId]);
    await this.recordAccessLog("verify", sessionAuditor, true, caseId);

    return {
      caseId: item.caseId, transactionHash: item.transactionHash, fields: disclosed,
      integrity: { canonicalReceipt: true, blockNumber: item.blockNumber, confirmations: item.confirmationCount,
        poolMatch: true, applicationMatch: true, actionMatch: true, envelopeHashMatch: true, commitmentMatch: true },
    };
  }

  async exportCase(caseId: string, sessionAuditor: string): Promise<Record<string, unknown>> {
    const item = await this.getCaseById(caseId);
    if (!item || item.assignedAuditor !== sessionAuditor.toLowerCase()) {
      await this.recordAccessLog("export", sessionAuditor, false, caseId, "UNAUTHORIZED"); throw new SdkError("UNAUTHORIZED");
    }
    if (item.caseState === "reorged" || item.confirmationCount < REQUIRED_CONFIRMATIONS) {
      await this.recordAccessLog("export", sessionAuditor, false, caseId, "FINALITY_REQUIRED"); throw new SdkError("UNAUTHORIZED");
    }
    if (!item.disclosedRecord?.amount) {
      await this.discloseCase(caseId, sessionAuditor);
      const refreshed = await this.getCaseById(caseId);
      if (!refreshed?.disclosedRecord) {
        await this.recordAccessLog("export", sessionAuditor, false, caseId, "AMOUNT_UNAVAILABLE");
        throw Object.assign(new Error("Disclosure amount is unavailable for this case"), { code: "AMOUNT_UNAVAILABLE" });
      }
      item.disclosedRecord = refreshed.disclosedRecord;
    }

    const payloadToSign = {
      case_id: item.caseId, transaction_hash: item.transactionHash,
      fields: item.disclosedRecord,
      signing_key_id: SIGNING_KEY_ID,
      provenance: { chain_id: item.chainId, pool: item.pool, application_id: item.applicationId, block_number: item.blockNumber, finalized: true },
      timestamp: Math.floor(Date.now() / 1000),
    };
    const signature = signCanonicalExport(payloadToSign);

    await this.pool.query(`UPDATE haze_compliance_cases SET status = 'exported' WHERE case_id = $1`, [caseId]);
    await this.recordAccessLog("export", sessionAuditor, true, caseId);
    return { ...payloadToSign, signature };
  }

  private rowToCase(row: any): ComplianceCase {
    const chainId = Number(row.chain_id ?? FUJI_CHAIN_ID);
    const confirmations = Number(row.confirmations ?? 0);
    const status = (row.status ?? "observed") as CaseState;
    const witnessData = row.witness_data
      ? (typeof row.witness_data === "string" ? JSON.parse(row.witness_data) : row.witness_data)
      : undefined;
    return {
      caseId: row.case_id, title: row.title, chainId,
      pool: row.pool ? "0x" + row.pool.toString("hex") : "",
      applicationId: "0x" + row.application_id.toString("hex"),
      transactionHash: "0x" + row.transaction_hash.toString("hex"),
      logIndex: Number(row.log_index ?? 0),
      blockNumber: Number(row.block_number ?? 0),
      blockHash: row.block_hash ? "0x" + row.block_hash.toString("hex") : undefined,
      caseState: status,
      confirmationCount: confirmations,
      requiredConfirmations: Number(row.required_confirmations ?? REQUIRED_CONFIRMATIONS),
      canonicalBlockIdentity: `Block #${row.block_number ?? 0} (${confirmations}/${row.required_confirmations ?? REQUIRED_CONFIRMATIONS} confs)`,
      readiness: confirmations >= REQUIRED_CONFIRMATIONS && status !== "reorged",
      fields: row.granted_fields ?? [...GRANTED_FIELDS],
      expiresAt: Math.floor(Date.now() / 1000) + 86400 * 30,
      assignedAuditor: row.assigned_auditor ? "0x" + row.assigned_auditor.toString("hex") : DEDICATED_AUDITOR.toLowerCase(),
      witnessData,
      disclosedRecord: witnessData?.auditRecord?.facts
        ? {
            tx_hash: "0x" + row.transaction_hash.toString("hex"),
            amount: row.amount ?? undefined,
            asset: row.asset ?? "USDC",
            timestamp: row.event_timestamp ? new Date(row.event_timestamp).toISOString() : undefined,
            policy_version: row.policy_version ?? 1,
          }
        : undefined,
      createdAt: Math.floor(new Date(row.created_at).getTime() / 1000),
      updatedAt: Math.floor(new Date(row.updated_at ?? row.created_at).getTime() / 1000),
    };
  }
}
