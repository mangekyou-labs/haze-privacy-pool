import { concatBytes, hexToBuf, toHex } from "./abi.ts";
import { encodeBrowserAuditRecord, type BrowserAuditFacts } from "./browser-audit.ts";
import { browserAuditAad, deriveBrowserX25519PublicKey, encodeBrowserEnvelope, sealBrowserHpke, sealBrowserHpkeToPublicKey } from "./browser-crypto.ts";
import { generateBrowserSecrets, type BrowserSecrets } from "./browser-prover.ts";
import { BN254_R, fieldToHex, u64be } from "./field.ts";
import { keccak256 } from "./keccak.ts";
import { decodeHazeAddress, requireAddressBinding, type HazeAddress } from "./address.ts";
import { SdkError } from "./errors.ts";
import { encodeRecipientPlaintext } from "./note.ts";
const text = new TextEncoder();
const RECIPIENT_INFO = text.encode("haze/avalanche/v1/recipient-note");
const AUDIT_INFO = text.encode("haze/avalanche/v1/audit-record");
type EnvelopeBinding = { hash: string; bytes: string };
type Witness = { circom: Record<string, any>; auditFacts: BrowserAuditFacts; actionReference: string; note: Record<string, any> | null; recipientNote?: Record<string, any> | null; membershipRoot: string; envelopes: Record<string, string> };
type WitnessFactory = (input: Record<string, unknown>) => Witness;

function nonzeroField(bytes: Uint8Array) { return fieldToHex((BigInt(toHex(bytes)) % (BN254_R - 1n)) + 1n); }
function envelope(purpose: "recipient" | "audit", keyVersion: bigint, sealed: { encapsulatedKey: Uint8Array; ciphertext: Uint8Array }): EnvelopeBinding {
  const bytes = encodeBrowserEnvelope({ purpose, keyVersion, ...sealed });
  return { bytes: toHex(bytes), hash: toHex(keccak256(bytes)) };
}
function recipientAad(input: { chainId: number; pool: string; poolVersion: string; applicationId: string; outputCommitment: string; outputIndex?: number }) {
  return concatBytes(u64be(input.chainId), hexToBuf(input.pool), hexToBuf(input.poolVersion), hexToBuf(input.applicationId), Uint8Array.of(input.outputIndex ?? 0), hexToBuf(input.outputCommitment), Uint8Array.of(1));
}

/** Construct recipient and audit envelopes around canonical witness facts, entirely in the browser. */
export function buildSealedBrowserWitness(input: {
  buildWitness: WitnessFactory; witnessInput: Record<string, unknown>; chainId: number; pool: string; poolVersion: string; applicationId: string;
  auditPublicKey: Uint8Array; auditKeyVersion: bigint; caseTag: Uint8Array; browserCrypto?: Pick<Crypto, "getRandomValues">; secrets?: BrowserSecrets;
}) {
  const secrets = input.secrets ?? generateBrowserSecrets(input.browserCrypto);
  const noteSecret = nonzeroField(secrets.noteSecret); const blinding = nonzeroField(secrets.blinding);
  const actionReference = toHex(secrets.actionReference); const auditSalt = nonzeroField(secrets.auditSalt);
  const x25519 = toHex(deriveBrowserX25519PublicKey(secrets.noteSecret));
  const base = { ...input.witnessInput, secret: noteSecret, blinding, x25519, actionReference, auditSalt };
  const initial = input.buildWitness(base);
  const outCommitment = String(initial.circom?.outputCommitment0 ?? "");
  const hasOutputNote = outCommitment !== "" && outCommitment !== "0" && outCommitment !== `0x${"00".repeat(32)}`;
  const note = initial.note as Record<string, string | number>;
  const recipient = hasOutputNote
    ? envelope("recipient", 0n, sealBrowserHpke({ recipientIkm: secrets.noteSecret, ephemeralSeed: secrets.recipientHpkeSeed, plaintext: encodeRecipientPlaintext({ value: Number(note.value), blinding, notePublicKey: String(note.npk), encryptionKeyHash: String(note.enc), applicationId: input.applicationId, poolVersion: input.poolVersion, commitment: String(note.commitment) }), info: RECIPIENT_INFO, aad: recipientAad({ ...input, outputCommitment: String(note.commitment) }) }))
    : { hash: `0x${"00".repeat(32)}`, bytes: "0x" };
  const draft = input.buildWitness({ ...base, recipientEnvelope0: recipient });
  const auditPlaintext = encodeBrowserAuditRecord(draft.auditFacts, input.caseTag);
  const audit = envelope("audit", input.auditKeyVersion, sealBrowserHpkeToPublicKey({ recipientPublicKey: input.auditPublicKey, ephemeralSeed: secrets.auditHpkeSeed, plaintext: auditPlaintext, info: AUDIT_INFO, aad: browserAuditAad({ chainId: BigInt(input.chainId), pool: hexToBuf(input.pool), poolVersion: hexToBuf(input.poolVersion), applicationId: hexToBuf(input.applicationId), keyVersion: input.auditKeyVersion, auditDataCommitment: hexToBuf(draft.circom.auditDataCommitment), action: draft.auditFacts.action, actionReference: secrets.actionReference }) }));
  const final = input.buildWitness({ ...base, recipientEnvelope0: recipient, auditEnvelope: audit });
  if (final.actionReference.toLowerCase() !== actionReference.toLowerCase() || final.auditFacts.actionReference.toLowerCase() !== actionReference.toLowerCase()
    || final.envelopes.recipientCiphertextHash0.toLowerCase() !== recipient.hash.toLowerCase() || final.envelopes.auditCiphertextHash.toLowerCase() !== audit.hash.toLowerCase()
    || final.circom.auditDataCommitment.toLowerCase() !== draft.circom.auditDataCommitment.toLowerCase()) throw new Error("WITNESS_BINDING_MISMATCH");
  return { witness: final, secrets, recipientEnvelope: recipient, auditEnvelope: audit };
}

/** Construct sealed recipient and audit envelopes for a private transfer (action 2). */
export function buildSealedBrowserTransferWitness(input: {
  buildWitness: WitnessFactory;
  witnessInput?: Record<string, unknown>;
  note: Record<string, unknown>;
  sendAmount: number | bigint;
  recipientAddress: string | HazeAddress;
  chainId: number;
  pool: string;
  poolVersion: string;
  applicationId: string;
  auditPublicKey: Uint8Array;
  auditKeyVersion: bigint;
  caseTag: Uint8Array;
  browserCrypto?: Pick<Crypto, "getRandomValues">;
  secrets?: BrowserSecrets;
  membershipLeaves?: Array<{ npk: string; enc: string }>;
  treeLeaves?: Array<{ leafIndex: number; commitment: string }>;
}) {
  if (!input.note || typeof input.note !== "object" || !input.note.secret || input.note.value === undefined) {
    throw new Error("DEPOSIT_NOTE_REQUIRED");
  }
  const noteValue = Number(input.note.value);
  const sendAmount = Number(input.sendAmount);
  if (!Number.isSafeInteger(sendAmount) || sendAmount <= 0 || sendAmount > noteValue) {
    throw new SdkError("ENCODING_INVALID");
  }
  const recipient =
    typeof input.recipientAddress === "string"
      ? decodeHazeAddress(input.recipientAddress)
      : input.recipientAddress;
  requireAddressBinding(recipient, {
    chainId: input.chainId,
    applicationId: input.applicationId,
    poolVersion: input.poolVersion,
  });

  const secrets = input.secrets ?? generateBrowserSecrets(input.browserCrypto);
  const actionReference = toHex(secrets.actionReference);
  const auditSalt = nonzeroField(secrets.auditSalt);
  const recipientSecret = nonzeroField(secrets.recipientNoteSecret);
  const recipientBlinding = nonzeroField(secrets.recipientBlinding);
  const changeSecret = nonzeroField(secrets.noteSecret);
  const changeBlinding = nonzeroField(secrets.blinding);
  const changeX25519 = toHex(deriveBrowserX25519PublicKey(secrets.noteSecret));

  const base = {
    ...input.witnessInput,
    pool: input.pool,
    poolVersion: input.poolVersion,
    applicationId: input.applicationId,
    note: input.note,
    sendAmount,
    recipientX25519: recipient.x25519PublicKey,
    recipientSecret,
    recipientBlinding,
    changeSecret,
    changeBlinding,
    changeX25519,
    actionReference,
    auditSalt,
    treeLeaves: input.treeLeaves,
    membershipLeaves: input.membershipLeaves,
  };
  const initial = input.buildWitness(base);

  const outCommitment0 = String(initial.circom?.outputCommitment0 ?? "");
  const recipientPlaintext = encodeRecipientPlaintext({
    value: sendAmount,
    blinding: recipientBlinding,
    notePublicKey: String(initial.recipientNote?.npk ?? recipient.notePublicKey),
    encryptionKeyHash: String(initial.recipientNote?.enc ?? ""),
    applicationId: input.applicationId,
    poolVersion: input.poolVersion,
    commitment: outCommitment0,
    spendingSecret: recipientSecret,
  });
  const recipientEnvelope0 = envelope(
    "recipient",
    0n,
    sealBrowserHpkeToPublicKey({
      recipientPublicKey: hexToBuf(recipient.x25519PublicKey),
      ephemeralSeed: secrets.recipientHpkeSeed,
      plaintext: recipientPlaintext,
      info: RECIPIENT_INFO,
      aad: recipientAad({ ...input, outputIndex: 0, outputCommitment: outCommitment0 }),
    }),
  );

  const outCommitment1 = String(initial.circom?.outputCommitment1 ?? "");
  const hasChange =
    outCommitment1 !== "" &&
    outCommitment1 !== "0" &&
    outCommitment1 !== `0x${"00".repeat(32)}`;
  const recipientEnvelope1 = hasChange
    ? envelope(
        "recipient",
        0n,
        sealBrowserHpke({
          recipientIkm: secrets.noteSecret,
          ephemeralSeed: secrets.recipientHpkeSeed,
          plaintext: encodeRecipientPlaintext({
            value: noteValue - sendAmount,
            blinding: changeBlinding,
            notePublicKey: String(initial.note?.npk ?? ""),
            encryptionKeyHash: String(initial.note?.enc ?? ""),
            applicationId: input.applicationId,
            poolVersion: input.poolVersion,
            commitment: outCommitment1,
          }),
          info: RECIPIENT_INFO,
          aad: recipientAad({ ...input, outputIndex: 1, outputCommitment: outCommitment1 }),
        }),
      )
    : { hash: `0x${"00".repeat(32)}`, bytes: "0x" };

  const draft = input.buildWitness({
    ...base,
    recipientEnvelope0,
    recipientEnvelope1,
  });
  const auditPlaintext = encodeBrowserAuditRecord(draft.auditFacts, input.caseTag);
  const audit = envelope(
    "audit",
    input.auditKeyVersion,
    sealBrowserHpkeToPublicKey({
      recipientPublicKey: input.auditPublicKey,
      ephemeralSeed: secrets.auditHpkeSeed,
      plaintext: auditPlaintext,
      info: AUDIT_INFO,
      aad: browserAuditAad({
        chainId: BigInt(input.chainId),
        pool: hexToBuf(input.pool),
        poolVersion: hexToBuf(input.poolVersion),
        applicationId: hexToBuf(input.applicationId),
        keyVersion: input.auditKeyVersion,
        auditDataCommitment: hexToBuf(draft.circom.auditDataCommitment),
        action: draft.auditFacts.action,
        actionReference: secrets.actionReference,
      }),
    }),
  );
  const final = input.buildWitness({
    ...base,
    recipientEnvelope0,
    recipientEnvelope1,
    auditEnvelope: audit,
  });
  if (
    final.actionReference.toLowerCase() !== actionReference.toLowerCase() ||
    final.auditFacts.actionReference.toLowerCase() !== actionReference.toLowerCase() ||
    final.envelopes.recipientCiphertextHash0.toLowerCase() !== recipientEnvelope0.hash.toLowerCase() ||
    final.envelopes.recipientCiphertextHash1.toLowerCase() !== recipientEnvelope1.hash.toLowerCase() ||
    final.envelopes.auditCiphertextHash.toLowerCase() !== audit.hash.toLowerCase() ||
    final.circom.auditDataCommitment.toLowerCase() !== draft.circom.auditDataCommitment.toLowerCase()
  ) {
    throw new Error("WITNESS_BINDING_MISMATCH");
  }
  return {
    witness: final,
    secrets,
    recipientEnvelope0,
    recipientEnvelope1,
    auditEnvelope: audit,
  };
}
