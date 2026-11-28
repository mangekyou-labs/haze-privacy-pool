export type MembershipLeaf = {
  npk: string;
  enc: string;
};

export type MembershipLeafLike = {
  npk?: unknown;
  enc?: unknown;
} | null | undefined;

export function unionMembershipLeaves(
  stored: MembershipLeafLike[] = [],
  inSlots: MembershipLeafLike[] = [],
  outSlots: MembershipLeafLike[] = [],
): MembershipLeaf[] {
  const union: MembershipLeaf[] = [];
  const seen = new Set<string>();
  for (const leaf of [...stored, ...inSlots, ...outSlots]) {
    if (!leaf || typeof leaf !== "object") continue;
    const npk = typeof leaf.npk === "string" ? leaf.npk : "";
    const enc = typeof leaf.enc === "string" ? leaf.enc : "";
    if (!npk || !enc) continue;
    const key = `${npk.toLowerCase()}:${enc.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    union.push({ npk, enc });
  }
  return union;
}

export type FujiMembershipStore = {
  list(): Promise<MembershipLeaf[]>;
  add(leaf: MembershipLeaf | MembershipLeaf[]): Promise<void>;
  clear(): Promise<void>;
};

export function createMemoryMembershipStore(initial: MembershipLeaf[] = []): FujiMembershipStore {
  let leaves: MembershipLeaf[] = [...initial];
  const seen = new Set(leaves.map((l) => `${l.npk.toLowerCase()}:${l.enc.toLowerCase()}`));

  return {
    async list() {
      return [...leaves];
    },
    async add(incoming) {
      const items = Array.isArray(incoming) ? incoming : [incoming];
      for (const item of items) {
        if (!item || !item.npk || !item.enc) continue;
        const key = `${item.npk.toLowerCase()}:${item.enc.toLowerCase()}`;
        if (!seen.has(key)) {
          seen.add(key);
          leaves.push({ npk: item.npk, enc: item.enc });
        }
      }
    },
    async clear() {
      leaves = [];
      seen.clear();
    },
  };
}

export function createFujiMembershipStore(options: {
  indexedDB?: IDBFactory;
  databaseName?: string;
} = {}): FujiMembershipStore {
  const factory = options.indexedDB ?? globalThis.indexedDB;
  if (!factory) {
    return createMemoryMembershipStore();
  }
  const databaseName = options.databaseName ?? "haze-fuji-membership-v1";

  const database = new Promise<IDBDatabase>((resolve, reject) => {
    const request = factory.open(databaseName, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains("members")) {
        request.result.createObjectStore("members", { keyPath: "key" });
      }
    };
    request.onerror = () => reject(request.error ?? new Error("INDEXEDDB_OPEN_FAILED"));
    request.onsuccess = () => resolve(request.result);
  });

  return {
    async list(): Promise<MembershipLeaf[]> {
      const db = await database;
      return new Promise((resolve, reject) => {
        const tx = db.transaction("members", "readonly");
        const request = tx.objectStore("members").getAll();
        request.onerror = () => reject(request.error ?? new Error("INDEXEDDB_READ_FAILED"));
        request.onsuccess = () => {
          const rows = request.result as Array<{ key: string; npk: string; enc: string }>;
          resolve((rows ?? []).map((row) => ({ npk: row.npk, enc: row.enc })));
        };
      });
    },
    async add(incoming: MembershipLeaf | MembershipLeaf[]): Promise<void> {
      const items = Array.isArray(incoming) ? incoming : [incoming];
      const db = await database;
      return new Promise((resolve, reject) => {
        const tx = db.transaction("members", "readwrite");
        const store = tx.objectStore("members");
        for (const item of items) {
          if (!item || !item.npk || !item.enc) continue;
          const key = `${item.npk.toLowerCase()}:${item.enc.toLowerCase()}`;
          store.put({ key, npk: item.npk, enc: item.enc });
        }
        tx.onerror = () => reject(tx.error ?? new Error("INDEXEDDB_WRITE_FAILED"));
        tx.oncomplete = () => resolve();
      });
    },
    async clear(): Promise<void> {
      const db = await database;
      return new Promise((resolve, reject) => {
        const tx = db.transaction("members", "readwrite");
        const request = tx.objectStore("members").clear();
        request.onerror = () => reject(request.error ?? new Error("INDEXEDDB_DELETE_FAILED"));
        request.onsuccess = () => resolve();
      });
    },
  };
}
