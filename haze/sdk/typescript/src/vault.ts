import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { encodeEnvelope, parseEnvelope, RECIPIENT_INFO } from "./envelope.ts";
import { SdkError } from "./errors.ts";
import { parseHex, toHex, u64be } from "./field.ts";
import { openRecipientNote, parseRecipientPlaintext, recipientAad } from "./hpke.ts";
import { encryptionKeyHash, noteCommitment, notePublicKey } from "./note.ts";
import type { ObjectStore } from "./providers.ts";
import { deriveShieldedAccount, type ShieldedAccount, type ShieldedAccountRequest } from "./prover.ts";

const VAULT_MAGIC = Buffer.from("HZVL");
const VAULT_VERSION = 1;

export type VaultAccount = ShieldedAccount & {
  notePublicKey: string;
  encryptionKeyHash: string;
};

export type VaultBinding = {
  chainId: number;
  pool: string;
  applicationId: string;
  poolVersion: string;
};

export type NoteEvent = {
  chainId: number;
  pool: string;
  poolVersion: string;
  applicationId: string;
  outputIndex: number;
  commitment: string;
  envelope: string;
  blockNumber: number;
  finalized: boolean;
  txHash: string;
  logIndex: number;
};

export type VaultNote = {
  chainId: number;
  commitment: string;
  value: bigint;
  blinding: string;
  notePublicKey: string;
  encryptionKeyHash: string;
  finalized: boolean;
  blockNumber: number;
  txHash: string;
  logIndex: number;
};

export type MemoryStore = ObjectStore & {
  keys(): string[];
  delete(key: string): Promise<void>;
};

export function createMemoryStore(): MemoryStore {
  const records = new Map<string, Uint8Array>();
  return {
    async put(key, value) {
      records.set(key, Uint8Array.from(value));
    },
    async get(key) {
      const value = records.get(key);
      if (!value) {
        throw new SdkError("ENCODING_INVALID");
      }
      return Uint8Array.from(value);
    },
    async delete(key) {
      records.delete(key);
    },
    keys() {
      return [...records.keys()];
    },
  };
}

export function deriveVaultAccount(
  request: ShieldedAccountRequest & { recoveryAdapter?: string },
): VaultAccount {
  if (request.recoveryAdapter === "smart-wallet") {
    throw new SdkError("RECOVERY_UNSUPPORTED");
  }
  const account = deriveShieldedAccount(request);
  return {
    ...account,
    notePublicKey: notePublicKey(account.spendingSecret),
    encryptionKeyHash: encryptionKeyHash(account.x25519PublicKey),
  };
}

function eventId(event: NoteEvent) {
  return `${event.chainId}:${event.txHash.toLowerCase()}:${event.logIndex}`;
}

function storeKey(binding: VaultBinding) {
  return `haze/vault/${binding.chainId}/${binding.applicationId.toLowerCase()}`;
}

function requireBinding(event: NoteEvent, binding: VaultBinding) {
  if (event.chainId !== binding.chainId) {
    throw new SdkError("CHAIN_MISMATCH");
  }
  if (event.applicationId.toLowerCase() !== binding.applicationId.toLowerCase()) {
    throw new SdkError("APPLICATION_MISMATCH");
  }
  if (event.poolVersion.toLowerCase() !== binding.poolVersion.toLowerCase()) {
    throw new SdkError("POOL_VERSION_MISMATCH");
  }
}

function serializeNotes(notes: VaultNote[]): Buffer {
  return Buffer.from(
    JSON.stringify(
      notes.map((note) => ({
        ...note,
        value: note.value.toString(),
      })),
    ),
  );
}

function deserializeNotes(bytes: Uint8Array): VaultNote[] {
  const parsed = JSON.parse(Buffer.from(bytes).toString("utf8")) as Array<
    Omit<VaultNote, "value"> & { value: string }
  >;
  return parsed.map((note) => ({ ...note, value: BigInt(note.value) }));
}

function vaultAad(binding: VaultBinding) {
  return Buffer.concat([
    u64be(binding.chainId),
    parseHex(binding.applicationId),
    parseHex(binding.poolVersion),
  ]);
}

function encryptVault(key: Buffer, binding: VaultBinding, notes: VaultNote[]): Uint8Array {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  const plaintext = serializeNotes(notes);
  cipher.setAAD(vaultAad(binding), { plaintextLength: plaintext.length });
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([VAULT_MAGIC, Buffer.from([VAULT_VERSION]), nonce, body, cipher.getAuthTag()]);
}

function decryptVault(key: Buffer, binding: VaultBinding, blob: Uint8Array): VaultNote[] {
  const buffer = Buffer.from(blob);
  if (buffer.length < 4 + 1 + 12 + 16 || !buffer.subarray(0, 4).equals(VAULT_MAGIC)) {
    throw new SdkError("ENCODING_INVALID");
  }
  if (buffer[4] !== VAULT_VERSION) {
    throw new SdkError("VERSION_UNSUPPORTED");
  }
  const nonce = buffer.subarray(5, 17);
  const tag = buffer.subarray(buffer.length - 16);
  const ciphertext = buffer.subarray(17, buffer.length - 16);
  try {
    const decipher = createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
    decipher.setAAD(vaultAad(binding), { plaintextLength: ciphertext.length });
    decipher.setAuthTag(tag);
    return deserializeNotes(Buffer.concat([decipher.update(ciphertext), decipher.final()]));
  } catch {
    throw new SdkError("CIPHERTEXT_INVALID");
  }
}

export function createLocalVault(input: { store: ObjectStore; account: VaultAccount; binding: VaultBinding }) {
  const notes: VaultNote[] = [];
  const seen = new Set<string>();
  const secrets: Uint8Array[] = [];
  const vaultKey = parseHex(input.account.localVaultKey);
  const key = storeKey(input.binding);

  function retainSecret(secret: Uint8Array) {
    secrets.push(secret);
    return secret;
  }

  function clearSecrets() {
    for (const secret of secrets) {
      secret.fill(0);
    }
    secrets.length = 0;
    vaultKey.fill(0);
  }

  function remember(note: VaultNote) {
    const id = eventId(note);
    if (seen.has(id)) {
      return false;
    }
    seen.add(id);
    notes.push(note);
    return true;
  }

  async function persist() {
    await input.store.put(key, encryptVault(vaultKey, input.binding, notes));
  }

  return {
    retainSecret,
    clearSecrets,
    listNotes(): VaultNote[] {
      return notes.map((note) => ({ ...note }));
    },
    persist,
    async load() {
      const blob = await input.store.get(key);
      notes.length = 0;
      seen.clear();
      for (const note of decryptVault(vaultKey, input.binding, blob)) {
        remember(note);
      }
    },
    async clearLocalState() {
      notes.length = 0;
      seen.clear();
      if ("delete" in input.store && typeof input.store.delete === "function") {
        await input.store.delete(key);
        return;
      }
      await input.store.put(key, new Uint8Array());
    },
    applyReorg(finalizedBlockNumber: number) {
      const kept = notes.filter((note) => note.finalized && note.blockNumber <= finalizedBlockNumber);
      notes.length = 0;
      seen.clear();
      for (const note of kept) {
        remember(note);
      }
    },
    async ingest(event: NoteEvent) {
      requireBinding(event, input.binding);
      const id = eventId(event);
      if (seen.has(id)) {
        return { accepted: false, note: notes.find((note) => eventId(note) === id) };
      }
      const envelope = parseEnvelope(parseHex(event.envelope));
      const aad = recipientAad({
        chainId: event.chainId,
        pool: event.pool,
        poolVersion: event.poolVersion,
        applicationId: event.applicationId,
        outputIndex: event.outputIndex,
        outputCommitment: event.commitment,
        envelopeVersion: 1,
      });
      const opened = openRecipientNote({
        recipientIkm: input.account.x25519Secret,
        encapsulatedKey: envelope.encapsulatedKey,
        ciphertext: envelope.ciphertext,
        info: RECIPIENT_INFO,
        aad,
      });
      const plaintext = parseRecipientPlaintext(opened);
      const recomputed = noteCommitment({
        chainId: event.chainId,
        pool: event.pool,
        poolVersion: event.poolVersion,
        applicationId: event.applicationId,
        value: plaintext.value,
        ownerNotePublicKey: plaintext.notePublicKey,
        ownerEncryptionKeyHash: plaintext.encryptionKeyHash,
        blinding: plaintext.blinding,
      });
      if (
        recomputed !== event.commitment.toLowerCase() ||
        plaintext.commitment.toLowerCase() !== event.commitment.toLowerCase()
      ) {
        throw new SdkError("COMMITMENT_MISMATCH");
      }
      const note: VaultNote = {
        chainId: event.chainId,
        commitment: recomputed,
        value: plaintext.value,
        blinding: plaintext.blinding,
        notePublicKey: plaintext.notePublicKey,
        encryptionKeyHash: plaintext.encryptionKeyHash,
        finalized: event.finalized,
        blockNumber: event.blockNumber,
        txHash: event.txHash,
        logIndex: event.logIndex,
      };
      remember(note);
      return { accepted: true, note };
    },
    async recover(events: NoteEvent[]) {
      const recovered = [];
      for (const event of events) {
        const result = await this.ingest(event);
        if (result.accepted && result.note) {
          recovered.push(result.note);
        }
      }
      return recovered;
    },
  };
}

export function encodeRecipientEnvelope(envelope: {
  purpose: "recipient" | "audit";
  keyVersion: bigint;
  encapsulatedKey: string;
  ciphertext: string;
}): Uint8Array {
  return encodeEnvelope(envelope);
}
