import { concatBytes, hexToBuf, toHex } from "./abi.ts";
import { encodeBrowserAuditRecord, type BrowserAuditFacts } from "./browser-audit.ts";
import { browserAuditAad, deriveBrowserX25519PublicKey, encodeBrowserEnvelope, sealBrowserHpke, sealBrowserHpkeToPublicKey } from "./browser-crypto.ts";
import { generateBrowserSecrets } from "./browser-prover.ts";
import { BN254_R, fieldToHex, u64be } from "./field.ts";
import { keccak256 } from "./keccak.ts";
import { encodeRecipientPlaintext } from "./note.ts";

const text = new TextEncoder();
const RECIPIENT_INFO = text.encode("haze/avalanche/v1/recipient-note");
const AUDIT_INFO = text.encode("haze/avalanche/v1/audit-record");
type EnvelopeBinding = { hash: string; bytes: string };
type Witness = { circom: Record<string, any>; auditFacts: BrowserAuditFacts; actionReference: string; note: Record<string, any>; membershipRoot: string; envelopes: Record<string, string> };
type WitnessFactory = (input: Record<string, unknown>) => Witness;

function nonzeroField(bytes: Uint8Array) { return fieldToHex((BigInt(toHex(bytes)) % (BN254_R - 1n)) + 1n); }
function envelope(purpose: "recipient" | "audit", keyVersion: bigint, sealed: { encapsulatedKey: Uint8Array; ciphertext: Uint8Array }): EnvelopeBinding {
  const bytes = encodeBrowserEnvelope({ purpose, keyVersion, ...sealed });
  return { bytes: toHex(bytes), hash: toHex(keccak256(bytes)) };
}
function recipientAad(input: { chainId: number; pool: string; poolVersion: string; applicationId: string; outputCommitment: string }) {
  return concatBytes(u64be(input.chainId), hexToBuf(input.pool), hexToBuf(input.poolVersion), hexToBuf(input.applicationId), Uint8Array.of(0), hexToBuf(input.outputCommitment), Uint8Array.of(1));
}

/** Construct recipient and audit envelopes around canonical witness facts, entirely in the browser. */
export function buildSealedBrowserWitness(input: {
  buildWitness: WitnessFactory; witnessInput: Record<string, unknown>; chainId: number; pool: string; poolVersion: string; applicationId: string;
  auditPublicKey: Uint8Array; auditKeyVersion: bigint; caseTag: Uint8Array; browserCrypto?: Pick<Crypto, "getRandomValues">; secrets?: ReturnType<typeof generateBrowserSecrets>;
}) {
  const secrets = input.secrets ?? generateBrowserSecrets(input.browserCrypto);
  const noteSecret = nonzeroField(secrets.noteSecret); const blinding = nonzeroField(secrets.blinding);
  const actionReference = toHex(secrets.actionReference); const auditSalt = nonzeroField(secrets.auditSalt);
  const x25519 = toHex(deriveBrowserX25519PublicKey(secrets.noteSecret));
  const base = { ...input.witnessInput, secret: noteSecret, blinding, x25519, actionReference, auditSalt };
  const initial = input.buildWitness(base); const note = initial.note as Record<string, string | number>;
  const plaintext = encodeRecipientPlaintext({ value: Number(note.value), blinding, notePublicKey: String(note.npk), encryptionKeyHash: String(note.enc), applicationId: input.applicationId, poolVersion: input.poolVersion, commitment: String(note.commitment) });
  const recipient = envelope("recipient", 0n, sealBrowserHpke({ recipientIkm: secrets.noteSecret, ephemeralSeed: secrets.recipientHpkeSeed, plaintext, info: RECIPIENT_INFO, aad: recipientAad({ ...input, outputCommitment: String(note.commitment) }) }));
  const draft = input.buildWitness({ ...base, recipientEnvelope0: recipient });
  const auditPlaintext = encodeBrowserAuditRecord(draft.auditFacts, input.caseTag);
  const audit = envelope("audit", input.auditKeyVersion, sealBrowserHpkeToPublicKey({ recipientPublicKey: input.auditPublicKey, ephemeralSeed: secrets.auditHpkeSeed, plaintext: auditPlaintext, info: AUDIT_INFO, aad: browserAuditAad({ chainId: BigInt(input.chainId), pool: hexToBuf(input.pool), poolVersion: hexToBuf(input.poolVersion), applicationId: hexToBuf(input.applicationId), keyVersion: input.auditKeyVersion, auditDataCommitment: hexToBuf(draft.circom.auditDataCommitment), action: draft.auditFacts.action, actionReference: secrets.actionReference }) }));
  const final = input.buildWitness({ ...base, recipientEnvelope0: recipient, auditEnvelope: audit });
  if (final.actionReference.toLowerCase() !== actionReference.toLowerCase() || final.auditFacts.actionReference.toLowerCase() !== actionReference.toLowerCase()
    || final.envelopes.recipientCiphertextHash0.toLowerCase() !== recipient.hash.toLowerCase() || final.envelopes.auditCiphertextHash.toLowerCase() !== audit.hash.toLowerCase()
    || final.circom.auditDataCommitment.toLowerCase() !== draft.circom.auditDataCommitment.toLowerCase()) throw new Error("WITNESS_BINDING_MISMATCH");
  return { witness: final, secrets, recipientEnvelope: recipient, auditEnvelope: audit };
}
