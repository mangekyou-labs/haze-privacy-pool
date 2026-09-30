import { keccakHex } from "../sdk/typescript/src/abi.ts";
import {
  DEVELOPMENT_AUDIT_IKM,
  auditAad,
  openAuditRecord,
} from "../sdk/typescript/src/audit.ts";
import { envelopeHash, parseEnvelope } from "../sdk/typescript/src/envelope.ts";
import { parseHex, toHex } from "../sdk/typescript/src/field.ts";

const PRIVATE_TRANSACTION_SIGNATURE =
  "PrivateTransaction(bytes32,uint8,address,uint64,uint64,uint256,uint256,uint256,uint256,uint256,uint64,address,bytes32,bytes32,uint256,bytes32,bytes,bytes,bytes)";
export const PRIVATE_TRANSACTION_TOPIC = keccakHex(Buffer.from(PRIVATE_TRANSACTION_SIGNATURE));

const ALLOWED_FIELDS = new Set(["tx_hash", "user", "counterparty", "amount", "asset", "policy_version"]);

function coded(code, message = code) {
  throw Object.assign(new Error(message), { code });
}

function equal(a, b) {
  return String(a).toLowerCase() === String(b).toLowerCase();
}

function bytes32(value, label) {
  try {
    const bytes = parseHex(value);
    if (bytes.length !== 32) coded("ENCODING_INVALID", `${label} is not bytes32`);
    return toHex(bytes);
  } catch (error) {
    if (error?.code) throw error;
    coded("ENCODING_INVALID", `${label} is not hex`);
  }
}

function statusIsSuccess(status) {
  return status === 1 || status === "0x1" || status === "0X1" || status === "1";
}

function word(data, index) {
  if (typeof data !== "string" || !/^0x[0-9a-fA-F]*$/.test(data)) coded("EVENT_MISSING", "event data is invalid");
  const body = data.slice(2);
  if (body.length % 64 !== 0 || body.length < 16 * 64) coded("EVENT_MISSING", "PrivateTransaction data is truncated");
  const start = index * 64;
  return `0x${body.slice(start, start + 64)}`;
}

function addressWord(value) {
  return `0x${value.slice(-40)}`;
}

function quantityWord(value) {
  try {
    return BigInt(value);
  } catch {
    coded("EVENT_MISSING", "event quantity is invalid");
  }
}

function planParts(plan) {
  const circuit = plan?.circuitPlan ?? plan?.artifact ?? plan;
  const intent = plan?.intent ?? circuit?.intent;
  if (!intent || !circuit) coded("ENCODING_INVALID", "withdraw plan is incomplete");
  const authorization = plan?.authorization ?? circuit?.authorization;
  const actionReference = authorization?.nonce ?? circuit?.actionReference ?? circuit?.auditRecord?.facts?.actionReference;
  const auditCiphertext = plan?.auditCiphertext ?? circuit?.envelopes?.auditCiphertext ?? circuit?.auditCiphertext;
  const auditHash = intent.auditCiphertextHash ?? circuit?.envelopes?.auditCiphertextHash ?? circuit?.auditCiphertextHash;
  const auditCommitment = intent.auditDataCommitment ?? circuit?.circom?.auditDataCommitment ?? circuit?.auditDataCommitment;
  if (!actionReference || !auditCiphertext || !auditHash || !auditCommitment) {
    coded("ENCODING_INVALID", "withdraw plan does not carry the audit binding");
  }
  return {
    circuit,
    intent,
    actionReference: bytes32(actionReference, "action reference"),
    auditCiphertext,
    auditHash: bytes32(auditHash, "audit envelope hash"),
    auditCommitment: bytes32(auditCommitment, "audit commitment"),
  };
}

function validateRequestedFields(fields) {
  if (!Array.isArray(fields) || fields.length === 0 || fields.some((field) => typeof field !== "string" || !ALLOWED_FIELDS.has(field))) {
    coded("UNAUTHORIZED", "requested audit fields are not authorized");
  }
  return [...new Set(fields)];
}

function validateEvent(receipt, pool, applicationId, intent, auditHash, auditCommitment, auditCiphertext, txHash) {
  if (!Array.isArray(receipt?.logs)) coded("EVENT_MISSING", "withdrawal receipt has no logs");
  if (txHash && receipt.transactionHash && !equal(txHash, receipt.transactionHash)) {
    coded("COMMITMENT_MISMATCH", "receipt transaction hash does not match the requested transaction");
  }
  const log = receipt.logs.find((candidate) => {
    return candidate && candidate.removed !== true && Array.isArray(candidate.topics) &&
      equal(candidate.topics[0], PRIVATE_TRANSACTION_TOPIC);
  });
  if (!log) coded("EVENT_MISSING", "successful withdrawal has no PrivateTransaction event");
  if (!equal(log.address, pool)) coded("APPLICATION_MISMATCH", "PrivateTransaction came from another pool");
  if (log.topics.length < 4) coded("EVENT_MISSING", "PrivateTransaction topics are incomplete");
  if (!equal(log.topics[1], applicationId)) coded("APPLICATION_MISMATCH", "PrivateTransaction application differs");
  if (quantityWord(log.topics[2]) !== 3n) coded("COMMITMENT_MISMATCH", "receipt event is not a withdrawal");
  if (!equal(addressWord(log.topics[3]), intent.user)) coded("COMMITMENT_MISMATCH", "withdrawal user differs");

  const applicationPolicyVersion = quantityWord(word(log.data, 0));
  const hazePolicyVersion = quantityWord(word(log.data, 1));
  const noteTreeRoot = bytes32(word(log.data, 2), "note tree root");
  const inputNullifier0 = bytes32(word(log.data, 3), "input nullifier 0");
  const inputNullifier1 = bytes32(word(log.data, 4), "input nullifier 1");
  const outputCommitment0 = bytes32(word(log.data, 5), "output commitment 0");
  const outputCommitment1 = bytes32(word(log.data, 6), "output commitment 1");
  const publicAmount = quantityWord(word(log.data, 7));
  const publicRecipient = addressWord(word(log.data, 8));
  const recipientCiphertextHash0 = bytes32(word(log.data, 9), "recipient hash 0");
  const recipientCiphertextHash1 = bytes32(word(log.data, 10), "recipient hash 1");
  const eventAuditCommitment = bytes32(word(log.data, 11), "audit commitment");
  const eventAuditHash = bytes32(word(log.data, 12), "audit envelope hash");
  let actualHash;
  try {
    actualHash = envelopeHash(parseEnvelope(auditCiphertext));
  } catch {
    coded("COMMITMENT_MISMATCH", "audit envelope is not a valid canonical envelope");
  }
  if (!equal(actualHash, auditHash) || !equal(actualHash, eventAuditHash)) coded("COMMITMENT_MISMATCH", "audit envelope hash differs");
  if (!equal(eventAuditCommitment, auditCommitment)) coded("COMMITMENT_MISMATCH", "audit commitment differs");
  if (applicationPolicyVersion !== BigInt(intent.applicationPolicyVersion) || hazePolicyVersion !== BigInt(intent.hazePolicyVersion)) coded("COMMITMENT_MISMATCH", "policy versions differ");
  if (noteTreeRoot !== bytes32(intent.noteTreeRoot ?? "0x" + "00".repeat(32), "note tree root")) coded("COMMITMENT_MISMATCH", "note tree root differs");
  if (inputNullifier0 !== bytes32(intent.inputNullifier0 ?? "0x" + "00".repeat(32), "input nullifier 0") || inputNullifier1 !== bytes32(intent.inputNullifier1 ?? "0x" + "00".repeat(32), "input nullifier 1")) coded("COMMITMENT_MISMATCH", "input nullifiers differ");
  if (outputCommitment0 !== bytes32(intent.outputCommitment0 ?? "0x" + "00".repeat(32), "output commitment 0") || outputCommitment1 !== bytes32(intent.outputCommitment1 ?? "0x" + "00".repeat(32), "output commitment 1")) coded("COMMITMENT_MISMATCH", "output commitments differ");
  if (publicAmount !== BigInt(intent.publicAmount) || !equal(publicRecipient, intent.publicRecipient)) coded("COMMITMENT_MISMATCH", "public withdrawal facts differ");
  if (!equal(recipientCiphertextHash0, intent.recipientCiphertextHash0 ?? "0x" + "00".repeat(32)) || !equal(recipientCiphertextHash1, intent.recipientCiphertextHash1 ?? "0x" + "00".repeat(32))) coded("COMMITMENT_MISMATCH", "recipient envelope hashes differ");
  return log;
}

function assertRecordBindings(record, parts, pool, applicationId, usdc, chainId) {
  const facts = record.facts;
  if (facts.chainId !== Number(chainId) || !equal(facts.poolAddress, pool) || !equal(facts.applicationId, applicationId)) coded("APPLICATION_MISMATCH", "audit record is bound to another chain, application, or pool");
  if (!equal(facts.poolVersion, parts.intent.poolVersion)) coded("POOL_VERSION_MISMATCH", "audit record pool version differs");
  if (facts.action !== 3 || !equal(facts.authorizedUser, parts.intent.user) || !equal(facts.actionReference, parts.actionReference)) coded("COMMITMENT_MISMATCH", "audit action binding differs");
  if (!equal(facts.usdcAddress, usdc) || facts.publicAmount !== Number(parts.intent.publicAmount) || !equal(facts.publicRecipient, parts.intent.publicRecipient)) coded("COMMITMENT_MISMATCH", "audit public facts differ");
  if (facts.applicationPolicyVersion !== Number(parts.intent.applicationPolicyVersion) || facts.hazePolicyVersion !== Number(parts.intent.hazePolicyVersion)) coded("COMMITMENT_MISMATCH", "audit policy facts differ");
}

function redact(record, fields) {
  const facts = record.facts;
  const output = {};
  for (const field of fields) {
    if (field === "tx_hash") output[field] = facts.actionReference;
    if (field === "user") output[field] = facts.authorizedUser;
    if (field === "counterparty") output[field] = facts.publicRecipient;
    if (field === "amount") output[field] = Number(facts.publicAmount);
    if (field === "asset") output[field] = facts.usdcAddress;
    if (field === "policy_version") output[field] = Number(facts.applicationPolicyVersion);
  }
  return output;
}

/** Explicitly marked local fixture KMS; never use this object in production configuration. */
export function createDevelopmentAuditKeyManagement({ applicationId, ikm = DEVELOPMENT_AUDIT_IKM } = {}) {
  return {
    mode: "development-fixture",
    notForProduction: true,
    async unwrapDataKey(requestedApplicationId, keyRef) {
      if (applicationId && !equal(requestedApplicationId, applicationId)) coded("APPLICATION_MISMATCH", "fixture KMS application differs");
      if (!String(keyRef).startsWith("audit:")) coded("KEYS_MISSING", "fixture KMS key reference is not an audit key");
      return Buffer.from(parseHex(ikm));
    },
  };
}

/** Verify, decrypt, authorize, and redact a completed live withdrawal audit envelope. */
export async function discloseLiveWithdrawal(input = {}) {
  const fields = validateRequestedFields(input.fields);
  const parts = planParts(input.plan ?? input.artifact);
  const intentApplication = parts.intent.applicationId;
  if (input.applicationId && !equal(input.applicationId, intentApplication)) coded("APPLICATION_MISMATCH", "disclosure application differs from the transaction");
  const applicationId = input.applicationId ?? intentApplication;
  if (!statusIsSuccess(input.receipt?.status)) coded("RECEIPT_REVERTED", "withdrawal receipt is not successful");
  const pool = input.pool ?? parts.intent.pool ?? input.plan?.pool;
  const usdc = input.usdc ?? input.plan?.usdc ?? parts.circuit.usdc;
  if (!pool || !usdc) coded("ENCODING_INVALID", "disclosure is missing pool or asset binding");
  validateEvent(input.receipt, pool, applicationId, parts.intent, parts.auditHash, parts.auditCommitment, parts.auditCiphertext, input.txHash);
  const declaredRecord = parts.circuit.auditRecord;
  if (declaredRecord?.facts?.actionReference && !equal(declaredRecord.facts.actionReference, parts.actionReference)) coded("COMMITMENT_MISMATCH", "authorization action reference differs from audit record");
  if (typeof input.authorize !== "function" || !(await input.authorize({ applicationId, fields, actionReference: parts.actionReference }))) coded("UNAUTHORIZED", "disclosure authorization denied");
  const envelope = parseEnvelope(parts.auditCiphertext);
  if (envelope.purpose !== "audit") coded("COMMITMENT_MISMATCH", "disclosure envelope is not an audit envelope");
  if (!input.keyManagement?.unwrapDataKey) coded("KEYS_MISSING", "production audit KMS is not configured");
  let ikm;
  try {
    ikm = await input.keyManagement.unwrapDataKey(applicationId, `audit:${envelope.keyVersion}`, new Uint8Array());
  } catch (error) {
    if (error?.code === "KEYS_MISSING") throw error;
    coded("UNAVAILABLE", "audit KMS is unavailable");
  }
  const aad = auditAad({
    chainId: input.chainId ?? 43113,
    pool,
    poolVersion: parts.intent.poolVersion,
    applicationId,
    auditKeyVersion: envelope.keyVersion,
    auditDataCommitment: parts.auditCommitment,
    action: 3,
    actionReference: parts.actionReference,
  });
  let record;
  try {
    record = openAuditRecord({ recipientIkm: toHex(ikm), envelope, aad, expectedCommitment: parts.auditCommitment });
  } catch (error) {
    if (error?.code === "CIPHERTEXT_INVALID") throw error;
    if (error?.code === "COMMITMENT_MISMATCH") throw error;
    coded("COMMITMENT_MISMATCH", "audit record integrity verification failed");
  }
  assertRecordBindings(record, parts, pool, applicationId, usdc, input.chainId ?? 43113);
  return { auditAcceptance: true, fields: redact(record, fields) };
}
