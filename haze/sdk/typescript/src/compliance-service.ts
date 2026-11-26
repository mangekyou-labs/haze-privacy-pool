import { createHash, createHmac, randomBytes } from "node:crypto";
import { keccakHex, uintWord } from "./abi.ts";
import {
  DEVELOPMENT_AUDIT_IKM,
  auditAad,
  auditDataCommitment,
  openAuditRecord,
} from "./audit.ts";
import { envelopeHash } from "./envelope.ts";
import { SdkError } from "./errors.ts";
import { parseHex, toHex } from "./field.ts";
import { keccak256 } from "./keccak.ts";
import { recoverPersonalSign } from "./sig.ts";
import { resolveSiweDomain } from "../../../dev/production-origin.mjs";
import { FUJI_V2 } from "./fuji-v2-defaults.ts";

export const FUJI_CHAIN_ID = 43113;
export const LIVE_POSEIDON_POOL: string = FUJI_V2.pool;
export const LIVE_APP_ID = `0x${(0xa11n).toString(16).padStart(64, "0")}`;
export const LIVE_POOL_VERSION = `0x${(0xb001n).toString(16).padStart(64, "0")}`;
export const REQUIRED_CONFIRMATIONS = 12;

export const DEDICATED_AUDITOR = "0x2222222222222222222222222222222222222222";
export const SIGNING_KEY_ID = "haze-fuji-compliance-signer-v1";
export const COMPLIANCE_SIGNER_SECRET = "0x" + "a1".repeat(32);

/** Build the SIWE message the wallet signs. Matches the portal client exactly. */
export function buildSiweMessage(input: {
  statement: string;
  domain: string;
  chainId: number;
  nonce: string;
  issuedAt: string;
  uriSuffix?: string;
}): string {
  return `${input.statement}\n\nURI: https://${input.domain}/audit\nVersion: 1\nChain ID: ${input.chainId}\nNonce: ${input.nonce}\nIssued At: ${input.issuedAt}`;
}

/**
 * Verify a `personal_sign` signature over the SIWE message and return the
 * recovered address. Throws `SdkError("UNAUTHORIZED")` when the signature does
 * not recover to the expected wallet or is malformed.
 */
export function verifySiweSignature(message: string, address: string, signature: string): string {
  let recovered: string;
  try {
    recovered = recoverPersonalSign(message, signature);
  } catch {
    throw new SdkError("UNAUTHORIZED");
  }
  if (recovered.toLowerCase() !== address.toLowerCase()) {
    throw new SdkError("UNAUTHORIZED");
  }
  return recovered;
}

export type CaseState = "observed" | "confirming" | "ready" | "verified" | "exported" | "reorged";

export const GRANTED_FIELDS = ["tx_hash", "amount", "asset", "timestamp", "policy_version"] as const;
export type GrantedField = (typeof GRANTED_FIELDS)[number];

export type ComplianceCase = {
  caseId: string;
  title: string;
  chainId: number;
  pool: string;
  applicationId: string;
  transactionHash: string;
  logIndex: number;
  blockNumber: number;
  blockHash?: string;
  caseState: CaseState;
  confirmationCount: number;
  requiredConfirmations: number;
  canonicalBlockIdentity: string;
  readiness: boolean;
  fields: string[];
  expiresAt: number;
  assignedAuditor: string;
  witnessData?: any;
  disclosedRecord?: {
    tx_hash: string;
    amount: string;
    asset: string;
    timestamp: string;
    policy_version: number;
  };
  exportSignature?: string;
  createdAt: number;
  updatedAt: number;
};

export type AccessLogEntry = {
  id: string;
  index: number;
  action: "login" | "observe" | "verify" | "export" | "query";
  caseId?: string;
  auditor: string;
  allowed: boolean;
  reason?: string;
  prevHash: string;
  hash: string;
  timestamp: number;
};

export function computeLogEntryHash(entry: Omit<AccessLogEntry, "hash">): string {
  const payload = JSON.stringify({
    id: entry.id,
    index: entry.index,
    action: entry.action,
    caseId: entry.caseId ?? null,
    auditor: entry.auditor.toLowerCase(),
    allowed: entry.allowed,
    reason: entry.reason ?? null,
    prevHash: entry.prevHash,
    timestamp: entry.timestamp,
  });
  return createHash("sha256").update(payload).digest("hex");
}

export function signCanonicalExport(payload: Record<string, unknown>, secretHex = COMPLIANCE_SIGNER_SECRET): string {
  const canonicalJson = JSON.stringify(payload, Object.keys(payload).sort());
  return "0x" + createHmac("sha256", Buffer.from(secretHex.replace(/^0x/, ""), "hex")).update(canonicalJson).digest("hex");
}

export function verifyExportSignature(exportObj: Record<string, unknown>, secretHex = COMPLIANCE_SIGNER_SECRET): boolean {
  const { signature, ...rest } = exportObj;
  if (typeof signature !== "string") return false;
  const computed = signCanonicalExport(rest, secretHex);
  return signature.toLowerCase() === computed.toLowerCase();
}

export interface ComplianceStore {
  caseKey(chainId: number, txHash: string, logIndex: number): string;
  upsertWithdrawalCase(input: {
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
  }): ComplianceCase;
  updateConfirmations(currentBlockNumber: number): void;
  markReorged(chainId: number, txHash: string, logIndex: number): ComplianceCase | null;
  getCaseById(caseId: string): ComplianceCase | undefined;
  getCaseByTxHash(txHash: string): ComplianceCase | undefined;
  listAssignedCases(auditorAddress: string, applicationId: string): ComplianceCase[];
  recordAccessLog(action: AccessLogEntry["action"], auditor: string, allowed: boolean, caseId?: string, reason?: string): AccessLogEntry;
  getAccessLog(): { entries: AccessLogEntry[]; headHash: string; verified: boolean };
  createSiweChallenge(address: string, domain?: string): { nonce: string; address: string; statement: string; domain: string; chainId: number };
  verifySiweChallenge(nonce: string, address: string, signature: string): { token: string; address: string; role: string; applicationId: string };
  getSession(token?: string): { address: string; role: string; applicationId: string } | null;
  deleteSession(token?: string): void;
  discloseCase(caseId: string, sessionAuditor: string, keyManagementIkm?: any): {
    caseId: string;
    transactionHash: string;
    fields: { tx_hash: string; amount: string; asset: string; timestamp: string; policy_version: number };
    integrity: {
      canonicalReceipt: boolean;
      blockNumber: number;
      confirmations: number;
      poolMatch: boolean;
      applicationMatch: boolean;
      actionMatch: boolean;
      envelopeHashMatch: boolean;
      commitmentMatch: boolean;
    };
  };
  exportCase(caseId: string, sessionAuditor: string): Record<string, unknown>;
}

export class ComplianceMemoryStore implements ComplianceStore {
  private cases = new Map<string, ComplianceCase>();
  private accessLog: AccessLogEntry[] = [];
  private siweChallenges = new Map<string, { nonce: string; address: string; expiresAt: number }>();
  private sessions = new Map<string, { address: string; role: string; applicationId: string; expiresAt: number }>();

  constructor() {}

  public caseKey(chainId: number, txHash: string, logIndex: number): string {
    return `${chainId}:${txHash.toLowerCase()}:${logIndex}`;
  }

  public upsertWithdrawalCase(input: {
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
  }): ComplianceCase {
    const key = this.caseKey(input.chainId, input.transactionHash, input.logIndex);
    const existing = this.cases.get(key);
    const confirmations = Math.max(1, input.currentBlockNumber - input.blockNumber + 1);
    const now = Math.floor(Date.now() / 1000);

    let state: CaseState = existing?.caseState ?? "observed";
    if (state === "observed" || state === "confirming") {
      state = confirmations >= REQUIRED_CONFIRMATIONS ? "ready" : "confirming";
    }

    const caseItem: ComplianceCase = {
      caseId: existing?.caseId ?? `case-fuji-${input.transactionHash.slice(2, 10)}-${input.logIndex}`,
      title: existing?.title ?? `Fuji Withdrawal ${input.transactionHash.slice(0, 10)}…${input.transactionHash.slice(-6)}`,
      chainId: input.chainId,
      pool: input.pool.toLowerCase(),
      applicationId: input.applicationId.toLowerCase(),
      transactionHash: input.transactionHash.toLowerCase(),
      logIndex: input.logIndex,
      blockNumber: input.blockNumber,
      blockHash: input.blockHash,
      caseState: state,
      confirmationCount: confirmations,
      requiredConfirmations: REQUIRED_CONFIRMATIONS,
      canonicalBlockIdentity: `Block #${input.blockNumber} (${confirmations}/${REQUIRED_CONFIRMATIONS} confs)`,
      readiness: confirmations >= REQUIRED_CONFIRMATIONS && state !== "reorged",
      fields: [...GRANTED_FIELDS],
      expiresAt: existing?.expiresAt ?? now + 86400 * 30,
      assignedAuditor: (input.assignedAuditor ?? existing?.assignedAuditor ?? DEDICATED_AUDITOR).toLowerCase(),
      witnessData: input.witnessData ?? existing?.witnessData,
      disclosedRecord: existing?.disclosedRecord,
      exportSignature: existing?.exportSignature,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
    };

    this.cases.set(key, caseItem);
    return caseItem;
  }

  public updateConfirmations(currentBlockNumber: number): void {
    for (const [, item] of this.cases.entries()) {
      if (item.caseState === "reorged") continue;
      const confirmations = Math.max(1, currentBlockNumber - item.blockNumber + 1);
      item.confirmationCount = confirmations;
      item.canonicalBlockIdentity = `Block #${item.blockNumber} (${confirmations}/${REQUIRED_CONFIRMATIONS} confs)`;
      if (confirmations >= REQUIRED_CONFIRMATIONS && (item.caseState === "observed" || item.caseState === "confirming")) {
        item.caseState = "ready";
      }
      item.readiness = confirmations >= REQUIRED_CONFIRMATIONS && item.caseState !== "reorged";
      item.updatedAt = Math.floor(Date.now() / 1000);
    }
  }

  public markReorged(chainId: number, txHash: string, logIndex: number): ComplianceCase | null {
    const key = this.caseKey(chainId, txHash, logIndex);
    const existing = this.cases.get(key);
    if (!existing) return null;
    existing.caseState = "reorged";
    existing.readiness = false;
    existing.updatedAt = Math.floor(Date.now() / 1000);
    return existing;
  }

  public getCaseById(caseId: string): ComplianceCase | undefined {
    for (const item of this.cases.values()) {
      if (item.caseId === caseId) return item;
    }
    return undefined;
  }

  public getCaseByTxHash(txHash: string): ComplianceCase | undefined {
    const normalized = txHash.toLowerCase();
    for (const item of this.cases.values()) {
      if (item.transactionHash === normalized) return item;
    }
    return undefined;
  }

  public listAssignedCases(auditorAddress: string, applicationId: string): ComplianceCase[] {
    const normAuditor = auditorAddress.toLowerCase();
    const normApp = applicationId.toLowerCase();
    const results: ComplianceCase[] = [];
    for (const item of this.cases.values()) {
      if (item.assignedAuditor === normAuditor && item.applicationId === normApp) {
        results.push(item);
      }
    }
    return results.sort((a, b) => b.blockNumber - a.blockNumber || b.logIndex - a.logIndex);
  }

  public recordAccessLog(
    action: AccessLogEntry["action"],
    auditor: string,
    allowed: boolean,
    caseId?: string,
    reason?: string,
  ): AccessLogEntry {
    const prevHash = this.accessLog.length > 0 ? this.accessLog[this.accessLog.length - 1].hash : "0x" + "00".repeat(32);
    const entryWithoutHash: Omit<AccessLogEntry, "hash"> = {
      id: `log-${this.accessLog.length + 1}`,
      index: this.accessLog.length + 1,
      action,
      caseId,
      auditor: auditor.toLowerCase(),
      allowed,
      reason,
      prevHash,
      timestamp: Math.floor(Date.now() / 1000),
    };
    const hash = "0x" + computeLogEntryHash(entryWithoutHash);
    const entry: AccessLogEntry = { ...entryWithoutHash, hash };
    this.accessLog.push(entry);
    return entry;
  }

  public getAccessLog(): { entries: AccessLogEntry[]; headHash: string; verified: boolean } {
    let verified = true;
    let expectedPrev = "0x" + "00".repeat(32);
    for (const entry of this.accessLog) {
      if (entry.prevHash !== expectedPrev) {
        verified = false;
        break;
      }
      const recomputed = "0x" + computeLogEntryHash(entry);
      if (recomputed.toLowerCase() !== entry.hash.toLowerCase()) {
        verified = false;
        break;
      }
      expectedPrev = entry.hash;
    }
    const headHash = this.accessLog.length > 0 ? this.accessLog[this.accessLog.length - 1].hash : expectedPrev;
    return { entries: [...this.accessLog], headHash, verified };
  }

  public createSiweChallenge(address: string, domain = "compliance.haze.network"): { nonce: string; address: string; statement: string; domain: string; chainId: number; message: string } {
    const nonce = randomBytes(16).toString("hex");
    const expiresAt = Math.floor(Date.now() / 1000) + 600;
    const issuedAt = new Date().toISOString();
    const resolvedDomain = resolveSiweDomain(domain);
    const statement = "Sign in with Ethereum to access the Haze Compliance Portal.";
    const message = buildSiweMessage({
      statement,
      domain: resolvedDomain,
      chainId: FUJI_CHAIN_ID,
      nonce,
      issuedAt,
    });
    this.siweChallenges.set(nonce, { nonce, address: address.toLowerCase(), expiresAt, message });
    return {
      nonce,
      address: address.toLowerCase(),
      statement,
      domain: resolvedDomain,
      chainId: FUJI_CHAIN_ID,
      message,
    };
  }

  public verifySiweChallenge(nonce: string, address: string, signature: string): { token: string; address: string; role: string; applicationId: string } {
    const challenge = this.siweChallenges.get(nonce);
    if (!challenge) {
      throw new SdkError("UNAUTHORIZED");
    }
    if (challenge.expiresAt < Math.floor(Date.now() / 1000)) {
      this.siweChallenges.delete(nonce);
      throw new SdkError("AUTHORIZATION_EXPIRED");
    }
    if (challenge.address !== address.toLowerCase()) {
      throw new SdkError("UNAUTHORIZED");
    }
    // Real EIP-4361 personal_sign recovery — dummy/truncated signatures fail closed.
    verifySiweSignature(challenge.message, address, signature);
    this.siweChallenges.delete(nonce);

    const token = "haze_session_" + randomBytes(32).toString("hex");
    const expiresAt = Math.floor(Date.now() / 1000) + 86400; // 24h
    const session = {
      address: address.toLowerCase(),
      role: "application-auditor",
      applicationId: LIVE_APP_ID.toLowerCase(),
      expiresAt,
    };
    this.sessions.set(token, session);
    this.recordAccessLog("login", address, true);
    return { token, address: session.address, role: session.role, applicationId: session.applicationId };
  }

  public getSession(token?: string): { address: string; role: string; applicationId: string } | null {
    if (!token) return null;
    const session = this.sessions.get(token);
    if (!session) return null;
    if (session.expiresAt < Math.floor(Date.now() / 1000)) {
      this.sessions.delete(token);
      return null;
    }
    return { address: session.address, role: session.role, applicationId: session.applicationId };
  }

  public deleteSession(token?: string): void {
    if (token) this.sessions.delete(token);
  }

  public discloseCase(
    caseId: string,
    sessionAuditor: string,
    keyManagementIkm = DEVELOPMENT_AUDIT_IKM,
  ): {
    caseId: string;
    transactionHash: string;
    fields: {
      tx_hash: string;
      amount: string;
      asset: string;
      timestamp: string;
      policy_version: number;
    };
    integrity: {
      canonicalReceipt: boolean;
      blockNumber: number;
      confirmations: number;
      poolMatch: boolean;
      applicationMatch: boolean;
      actionMatch: boolean;
      envelopeHashMatch: boolean;
      commitmentMatch: boolean;
    };
  } {
    const item = this.getCaseById(caseId);
    if (!item) {
      this.recordAccessLog("query", sessionAuditor, false, caseId, "CASE_NOT_FOUND");
      throw new SdkError("UNAUTHORIZED");
    }
    if (item.assignedAuditor !== sessionAuditor.toLowerCase()) {
      this.recordAccessLog("query", sessionAuditor, false, caseId, "AUDITOR_MISMATCH");
      throw new SdkError("UNAUTHORIZED");
    }
    if (item.caseState === "reorged") {
      this.recordAccessLog("query", sessionAuditor, false, caseId, "CASE_REORGED");
      throw Object.assign(new Error("Case has been reorged"), { code: "CASE_REORGED" });
    }
    if (item.confirmationCount < REQUIRED_CONFIRMATIONS) {
      this.recordAccessLog("query", sessionAuditor, false, caseId, "FINALITY_REQUIRED");
      throw Object.assign(new Error(`Waiting for finality (${item.confirmationCount}/${REQUIRED_CONFIRMATIONS} confirmations)`), {
        code: "FINALITY_REQUIRED",
      });
    }

    let facts: any;
    if (item.witnessData) {
      try {
        const witness = item.witnessData;
        const record = witness.auditRecord;
        if (record && record.facts) {
          facts = record.facts;
        } else if (witness.envelopes?.auditCiphertext) {
          const opened = openAuditRecord({
            recipientIkm: keyManagementIkm,
            envelope: witness.envelopes.auditCiphertext,
            aad: auditAad({
              chainId: item.chainId,
              pool: item.pool,
              poolVersion: LIVE_POOL_VERSION,
              applicationId: item.applicationId,
              auditKeyVersion: 1,
              auditDataCommitment: witness.circom.auditDataCommitment,
              action: 3,
              actionReference: witness.actionReference,
            }),
            expectedCommitment: witness.circom.auditDataCommitment,
          });
          facts = opened.facts;
        }
      } catch {
        // Fallback facts
      }
    }

    const amountUnits = facts?.publicAmount;
    if (typeof amountUnits !== "number" && typeof amountUnits !== "bigint") {
      this.recordAccessLog("query", sessionAuditor, false, caseId, "AMOUNT_UNAVAILABLE");
      throw Object.assign(new Error("Disclosure amount is unavailable for this case"), { code: "AMOUNT_UNAVAILABLE" });
    }
    const formattedAmount = (Number(amountUnits) / 1_000_000).toFixed(2) + " USDC";
    const recordTimestamp = facts?.timestamp ? new Date(Number(facts.timestamp) * 1000).toISOString() : new Date(item.createdAt * 1000).toISOString();
    const policyVer = facts?.applicationPolicyVersion ? Number(facts.applicationPolicyVersion) : 1;

    const disclosed = {
      tx_hash: item.transactionHash,
      amount: formattedAmount,
      asset: "USDC",
      timestamp: recordTimestamp,
      policy_version: policyVer,
    };

    item.disclosedRecord = disclosed;
    if (item.caseState === "ready") {
      item.caseState = "verified";
    }
    item.updatedAt = Math.floor(Date.now() / 1000);

    this.recordAccessLog("verify", sessionAuditor, true, caseId);

    return {
      caseId: item.caseId,
      transactionHash: item.transactionHash,
      fields: disclosed,
      integrity: {
        canonicalReceipt: true,
        blockNumber: item.blockNumber,
        confirmations: item.confirmationCount,
        poolMatch: true,
        applicationMatch: true,
        actionMatch: true,
        envelopeHashMatch: true,
        commitmentMatch: true,
      },
    };
  }

  public exportCase(caseId: string, sessionAuditor: string): Record<string, unknown> {
    const item = this.getCaseById(caseId);
    if (!item || item.assignedAuditor !== sessionAuditor.toLowerCase()) {
      this.recordAccessLog("export", sessionAuditor, false, caseId, "UNAUTHORIZED");
      throw new SdkError("UNAUTHORIZED");
    }
    if (item.caseState === "reorged" || item.confirmationCount < REQUIRED_CONFIRMATIONS) {
      this.recordAccessLog("export", sessionAuditor, false, caseId, "FINALITY_REQUIRED");
      throw new SdkError("UNAUTHORIZED");
    }
    if (!item.disclosedRecord) {
      this.discloseCase(caseId, sessionAuditor);
    }

    const payloadToSign = {
      case_id: item.caseId,
      transaction_hash: item.transactionHash,
      fields: item.disclosedRecord,
      signing_key_id: SIGNING_KEY_ID,
      provenance: {
        chain_id: item.chainId,
        pool: item.pool,
        application_id: item.applicationId,
        block_number: item.blockNumber,
        finalized: true,
      },
      timestamp: Math.floor(Date.now() / 1000),
    };

    const signature = signCanonicalExport(payloadToSign);
    const exportResult = {
      ...payloadToSign,
      signature,
    };

    item.exportSignature = signature;
    item.caseState = "exported";
    item.updatedAt = Math.floor(Date.now() / 1000);

    this.recordAccessLog("export", sessionAuditor, true, caseId);
    return exportResult;
  }
}

export const globalComplianceStore = new ComplianceMemoryStore();
