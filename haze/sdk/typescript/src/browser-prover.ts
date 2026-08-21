import { SdkError } from "./errors.ts";
import {
  ProverError,
  type DevelopmentProof,
  type ProverErrorCode,
  type WorkerOutbound,
} from "./prover-types.ts";

export type CircuitArtifactManifest = {
  profile: string;
  notForProduction?: boolean;
  artifactHash: string;
};

export type FujiProvingArtifact = {
  url: string;
  byteSize: number;
  sha256: string;
};

export type FujiProvingArtifactManifest = {
  circuitId: string;
  profile: "fuji-development";
  notForProduction: true;
  wasm: FujiProvingArtifact;
  zkey: FujiProvingArtifact;
};

export type ArtifactCache = {
  get(hash: string): Promise<Uint8Array>;
  put(entry: { artifactHash: string; bytes: Uint8Array }): Promise<void>;
};

export type BrowserWorker = {
  addEventListener(type: "message", listener: (event: { data: BrowserWorkerOutbound }) => void): void;
  removeEventListener?(type: "message", listener: (event: { data: BrowserWorkerOutbound }) => void): void;
  postMessage(data: BrowserWorkerInbound): void;
};

export type BrowserProgress = { stage: string; percent: number };
export type BrowserWorkerInbound = {
  type: string;
  requestId?: string;
  value?: number;
  circom?: Record<string, unknown>;
  wasm?: Uint8Array;
  zkey?: Uint8Array;
};
export type BrowserWorkerOutbound =
  | WorkerOutbound
  | { type: "progress"; requestId: string; stage: string; percent: number }
  | { type: "success"; requestId: string; proof: DevelopmentProof | unknown }
  | { type: "cancelled"; requestId?: string }
  | { type: "error"; requestId?: string; code: string; message?: string };

export type BrowserProverConfig = {
  worker: BrowserWorker;
  cache?: ArtifactCache;
  profile: string;
  expectedArtifactHash: string;
};

function normalizeHash(value: string) {
  return value.toLowerCase();
}

function hex(bytes: Uint8Array) {
  return `0x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

/** Generate independent secret material using the browser CSPRNG. */
export function generateBrowserSecrets(
  browserCrypto: Pick<Crypto, "getRandomValues"> = globalThis.crypto,
) {
  if (typeof browserCrypto?.getRandomValues !== "function") {
    throw new ProverError("UNSUPPORTED_RECOVERY");
  }
  const random32 = () => browserCrypto.getRandomValues(new Uint8Array(32));
  return {
    noteSecret: random32(),
    blinding: random32(),
    actionReference: random32(),
    auditSalt: random32(),
    recipientHpkeSeed: random32(),
    auditHpkeSeed: random32(),
  };
}

async function verifiedArtifact(
  descriptor: FujiProvingArtifact,
  supplied: Uint8Array | undefined,
  fetchArtifact: typeof fetch,
) {
  let bytes = supplied;
  if (bytes === undefined) {
    const response = await fetchArtifact(descriptor.url);
    if (!response.ok) {
      throw new ProverError("ARTIFACT_INVALID");
    }
    bytes = new Uint8Array(await response.arrayBuffer());
  }
  if (bytes.byteLength !== descriptor.byteSize) {
    throw new ProverError("ARTIFACT_INVALID");
  }
  const digest = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
  if (normalizeHash(digest) !== normalizeHash(descriptor.sha256)) {
    throw new ProverError("ARTIFACT_INVALID");
  }
  return bytes;
}

/** Fetch or accept immutable Fuji proving bytes and reject every manifest mismatch. */
export async function loadFujiProvingArtifacts(
  manifest: FujiProvingArtifactManifest,
  sources: {
    wasm?: Uint8Array;
    zkey?: Uint8Array;
    fetch?: typeof fetch;
  } = {},
) {
  if (manifest.profile !== "fuji-development" || manifest.notForProduction !== true) {
    throw new ProverError("ARTIFACT_INVALID");
  }
  const fetchArtifact = sources.fetch ?? globalThis.fetch;
  if (typeof fetchArtifact !== "function") {
    throw new ProverError("ARTIFACT_INVALID");
  }
  const [wasm, zkey] = await Promise.all([
    verifiedArtifact(manifest.wasm, sources.wasm, fetchArtifact),
    verifiedArtifact(manifest.zkey, sources.zkey, fetchArtifact),
  ]);
  return { circuitId: manifest.circuitId, wasm, zkey };
}

/** In-memory proving-artifact cache keyed by content hash. */
export function createArtifactCache(store?: Map<string, Uint8Array>): ArtifactCache {
  const memory = store ?? new Map<string, Uint8Array>();
  return {
    async put({ artifactHash, bytes }) {
      memory.set(normalizeHash(artifactHash), bytes);
    },
    async get(hash) {
      const hit = memory.get(normalizeHash(hash));
      if (hit === undefined) {
        throw new ProverError("ARTIFACT_INVALID");
      }
      return hit;
    },
  };
}

/** Select a circuit artifact whose profile and hash match the host, matching Rust selection. */
export async function selectCircuitArtifact(
  profile: string,
  manifest: CircuitArtifactManifest,
  expectedHash: string,
) {
  if (profile === "production" && (manifest.notForProduction || manifest.profile !== "production")) {
    throw new SdkError("VERSION_UNSUPPORTED");
  }
  if (manifest.profile !== profile) {
    throw new SdkError("VERSION_UNSUPPORTED");
  }
  if (normalizeHash(manifest.artifactHash) !== normalizeHash(expectedHash)) {
    throw new ProverError("ARTIFACT_INVALID");
  }
  return manifest;
}

function asProverError(code: string | undefined): ProverError {
  const known: ProverErrorCode[] = [
    "CANCELLED",
    "KEYS_MISSING",
    "UNSUPPORTED_RECOVERY",
    "ARTIFACT_INVALID",
    "WITNESS_INVALID",
    "PROOF_INVALID",
  ];
  if (code !== undefined && known.includes(code as ProverErrorCode)) {
    return new ProverError(code as ProverErrorCode);
  }
  return new ProverError("PROOF_INVALID");
}

let nextRequestId = 0;

function requestWorker(
  worker: BrowserWorker,
  message: BrowserWorkerInbound,
  onProgress?: (progress: BrowserProgress) => void,
) {
  const requestId = `haze-proof-${++nextRequestId}`;
  return new Promise<{ proof: DevelopmentProof | unknown; stages: string[] }>((resolve, reject) => {
    const cleanup = () => worker.removeEventListener?.("message", onMessage);
    const onMessage = (event: { data: BrowserWorkerOutbound }) => {
      const data = event.data;
      if ("requestId" in data && data.requestId !== undefined && data.requestId !== requestId) {
        return;
      }
      if (data.type === "progress") {
        onProgress?.({ stage: data.stage, percent: data.percent });
        return;
      }
      if (data.type === "cancelled") {
        cleanup();
        reject(new ProverError("CANCELLED"));
        return;
      }
      if (data.type === "cleared") {
        return;
      }
      if (data.type === "error") {
        cleanup();
        reject(asProverError(data.code));
        return;
      }
      if (data.type === "success") {
        cleanup();
        resolve({ proof: data.proof, stages: [] });
        return;
      }
      if (data.type === "proof") {
        cleanup();
        resolve({ proof: data.proof, stages: data.stages });
      }
    };
    worker.addEventListener("message", onMessage);
    worker.postMessage({ ...message, requestId });
  });
}

/** Host that drives a proving Web Worker with cache, cancel, and progress hooks. */
export function createBrowserProver(config: BrowserProverConfig) {
  const cache = config.cache ?? createArtifactCache();
  const stages: string[] = [];
  let fujiArtifacts: Awaited<ReturnType<typeof loadFujiProvingArtifacts>> | undefined;

  return {
    stages() {
      return [...stages];
    },
    cancel() {
      config.worker.postMessage({ type: "cancel" });
    },
    clear() {
      config.worker.postMessage({ type: "clear" });
      fujiArtifacts?.wasm.fill(0);
      fujiArtifacts?.zkey.fill(0);
      fujiArtifacts = undefined;
    },
    async loadFujiArtifacts(
      manifest: FujiProvingArtifactManifest,
      sources: Parameters<typeof loadFujiProvingArtifacts>[1] = {},
    ) {
      fujiArtifacts = await loadFujiProvingArtifacts(manifest, sources);
      return fujiArtifacts.circuitId;
    },
    async ensureArtifacts(
      manifest: CircuitArtifactManifest & { bytes: Uint8Array },
    ) {
      await selectCircuitArtifact(config.profile, manifest, config.expectedArtifactHash);
      await cache.put({ artifactHash: manifest.artifactHash, bytes: manifest.bytes });
    },
    async proveDevelopment(
      value: number,
      options?: { onProgress?: (stage: string) => void },
    ): Promise<DevelopmentProof> {
      const reportedProgress: BrowserProgress[] = [];
      const result = await requestWorker(config.worker, { type: "prove-development", value }, (progress) => {
        reportedProgress.push(progress);
        if (!stages.includes(progress.stage)) stages.push(progress.stage);
        options?.onProgress?.(progress as never);
      });
      const reported = result.stages.length > 0 ? result.stages : ["development"];
      for (const stage of reported) {
        if (!stages.includes(stage)) {
          stages.push(stage);
        }
        if (reportedProgress.length === 0) options?.onProgress?.(stage as never);
      }
      return result.proof as DevelopmentProof;
    },
    async proveSpend(circom: Record<string, unknown>) {
      const result = await requestWorker(config.worker, {
        type: "prove-spend",
        circom,
        wasm: fujiArtifacts?.wasm,
        zkey: fujiArtifacts?.zkey,
      });
      return result.proof;
    },
  };
}
