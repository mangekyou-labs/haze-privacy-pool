const VAULT_FORMAT = "haze-browser-operation-vault-v1";

export type BrowserVaultBinding = {
  chainId: number;
  applicationId: string;
  pool: string;
  wallet: string;
};

export type BrowserOperationState =
  | "proving"
  | "ready_to_submit"
  | "submitted"
  | "confirmed"
  | "failed";

export type BrowserOperation = {
  id: string;
  kind: "deposit" | "withdrawal";
  state: BrowserOperationState;
  note: Record<string, unknown>;
  transaction: Record<string, unknown>;
};

export type BrowserOperationStore = {
  get(key: string): Promise<Uint8Array | undefined>;
  put(key: string, value: Uint8Array): Promise<void>;
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function normalizedBinding(binding: BrowserVaultBinding): BrowserVaultBinding {
  return {
    chainId: binding.chainId,
    applicationId: binding.applicationId.toLowerCase(),
    pool: binding.pool.toLowerCase(),
    wallet: binding.wallet.toLowerCase(),
  };
}

function bytesFromHex(value: string): Uint8Array {
  const hex = value.startsWith("0x") ? value.slice(2) : value;
  if (hex.length === 0 || hex.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(hex)) {
    throw new Error("INVALID_WALLET_SIGNATURE");
  }
  return Uint8Array.from(hex.match(/.{2}/g) ?? [], (byte) => Number.parseInt(byte, 16));
}

function bindingInfo(binding: BrowserVaultBinding): Uint8Array {
  const value = normalizedBinding(binding);
  return encoder.encode(`${VAULT_FORMAT}:${value.chainId}:${value.applicationId}:${value.pool}:${value.wallet}`);
}

export async function deriveBrowserVaultKey(
  walletSignature: string,
  binding: BrowserVaultBinding,
): Promise<Uint8Array> {
  const source = await crypto.subtle.importKey("raw", bytesFromHex(walletSignature), "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: encoder.encode(VAULT_FORMAT),
      info: bindingInfo(binding),
    },
    source,
    256,
  );
  return new Uint8Array(bits);
}

function storageKeyFor(binding: BrowserVaultBinding): string {
  const value = normalizedBinding(binding);
  return `${VAULT_FORMAT}:${value.chainId}:${value.applicationId}:${value.pool}:${value.wallet}`;
}

async function aesKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function seal(key: CryptoKey, storageKey: string, operations: BrowserOperation[]): Promise<Uint8Array> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: encoder.encode(storageKey), tagLength: 128 },
    key,
    encoder.encode(JSON.stringify(operations)),
  ));
  const output = new Uint8Array(1 + nonce.length + ciphertext.length);
  output[0] = 1;
  output.set(nonce, 1);
  output.set(ciphertext, 13);
  return output;
}

async function open(key: CryptoKey, storageKey: string, value: Uint8Array): Promise<BrowserOperation[]> {
  if (value.length < 30 || value[0] !== 1) throw new Error("INVALID_VAULT_DATA");
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: value.subarray(1, 13), additionalData: encoder.encode(storageKey), tagLength: 128 },
      key,
      value.subarray(13),
    );
    const parsed = JSON.parse(decoder.decode(plaintext));
    if (!Array.isArray(parsed)) throw new Error("invalid vault payload");
    return parsed;
  } catch {
    throw new Error("VAULT_DECRYPTION_FAILED");
  }
}

const transitions: Record<BrowserOperationState, BrowserOperationState[]> = {
  proving: ["ready_to_submit", "failed"],
  ready_to_submit: ["submitted", "failed"],
  submitted: ["confirmed", "failed"],
  confirmed: [],
  failed: [],
};

export async function createBrowserOperationVault(options: {
  database: BrowserOperationStore;
  signature: string;
  binding: BrowserVaultBinding;
}) {
  const storageKey = storageKeyFor(options.binding);
  const key = await aesKey(await deriveBrowserVaultKey(options.signature, options.binding));
  const stored = await options.database.get(storageKey);
  const operations = stored ? await open(key, storageKey, stored) : [];

  async function persist(): Promise<void> {
    await options.database.put(storageKey, await seal(key, storageKey, operations));
  }

  async function get(id: string): Promise<BrowserOperation | undefined> {
    const operation = operations.find((candidate) => candidate.id === id);
    return operation ? structuredClone(operation) : undefined;
  }

  async function transition(
    id: string,
    state: BrowserOperationState,
    transaction?: Record<string, unknown>,
  ): Promise<BrowserOperation> {
    const operation = operations.find((candidate) => candidate.id === id);
    if (!operation) throw new Error("OPERATION_NOT_FOUND");
    if (!transitions[operation.state].includes(state)) throw new Error("INVALID_STATE");
    operation.state = state;
    if (transaction) operation.transaction = { ...operation.transaction, ...transaction };
    await persist();
    return structuredClone(operation);
  }

  return {
    storageKey,
    async create(input: Omit<BrowserOperation, "state">): Promise<BrowserOperation> {
      if (operations.some((operation) => operation.id === input.id)) throw new Error("OPERATION_EXISTS");
      const operation: BrowserOperation = { ...structuredClone(input), state: "proving" };
      operations.push(operation);
      await persist();
      return structuredClone(operation);
    },
    get,
    async list(): Promise<BrowserOperation[]> {
      return structuredClone(operations);
    },
    transition,
    async markSubmittedBeforeBroadcast<T>(
      id: string,
      transaction: Record<string, unknown>,
      broadcast: () => Promise<T>,
    ): Promise<T> {
      await transition(id, "submitted", transaction);
      return broadcast();
    },
  };
}

export function createMemoryIndexedDb(): BrowserOperationStore {
  const values = new Map<string, Uint8Array>();
  return {
    async get(key) {
      const value = values.get(key);
      return value ? value.slice() : undefined;
    },
    async put(key, value) {
      values.set(key, value.slice());
    },
  };
}

export function createIndexedDbOperationStore(options: {
  indexedDB?: IDBFactory;
  databaseName?: string;
} = {}): BrowserOperationStore {
  const factory = options.indexedDB ?? globalThis.indexedDB;
  if (!factory) throw new Error("INDEXEDDB_UNAVAILABLE");
  const databaseName = options.databaseName ?? "haze-fuji-operation-vault-v1";

  const database = new Promise<IDBDatabase>((resolve, reject) => {
    const request = factory.open(databaseName, 1);
    request.onupgradeneeded = () => request.result.createObjectStore("vaults");
    request.onerror = () => reject(request.error ?? new Error("INDEXEDDB_OPEN_FAILED"));
    request.onsuccess = () => resolve(request.result);
  });

  return {
    async get(key) {
      const db = await database;
      return new Promise((resolve, reject) => {
        const request = db.transaction("vaults", "readonly").objectStore("vaults").get(key);
        request.onerror = () => reject(request.error ?? new Error("INDEXEDDB_READ_FAILED"));
        request.onsuccess = () => {
          const value = request.result;
          resolve(value instanceof Uint8Array ? value : value instanceof ArrayBuffer ? new Uint8Array(value) : undefined);
        };
      });
    },
    async put(key, value) {
      const db = await database;
      return new Promise((resolve, reject) => {
        const request = db.transaction("vaults", "readwrite").objectStore("vaults").put(value, key);
        request.onerror = () => reject(request.error ?? new Error("INDEXEDDB_WRITE_FAILED"));
        request.onsuccess = () => resolve();
      });
    },
  };
}
