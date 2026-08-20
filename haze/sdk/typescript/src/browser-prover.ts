import { SdkError } from "./errors.ts";
import {
  ProverError,
  type DevelopmentProof,
  type ProverErrorCode,
  type WorkerOutbound,
} from "./prover-session.ts";

export type CircuitArtifactManifest = {
  profile: string;
  notForProduction?: boolean;
  artifactHash: string;
};

export type ArtifactCache = {
  get(hash: string): Promise<Uint8Array>;
  put(entry: { artifactHash: string; bytes: Uint8Array }): Promise<void>;
};

export type BrowserWorker = {
  addEventListener(type: "message", listener: (event: { data: WorkerOutbound }) => void): void;
  postMessage(data: { type: string; value?: number; circom?: Record<string, unknown> }): void;
};

export type BrowserProverConfig = {
  worker: BrowserWorker;
  cache?: ArtifactCache;
  profile: string;
  expectedArtifactHash: string;
};

function normalizeHash(value: string) {
  return value.toLowerCase();
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

function requestWorker(worker: BrowserWorker, message: { type: string; value?: number; circom?: Record<string, unknown> }) {
  return new Promise<Extract<WorkerOutbound, { type: "proof" }>>((resolve, reject) => {
    const onMessage = (event: { data: WorkerOutbound }) => {
      const data = event.data;
      if (data.type === "cancelled" || data.type === "cleared") {
        return;
      }
      if (data.type === "error") {
        reject(asProverError(data.code));
        return;
      }
      if (data.type === "proof") {
        resolve(data);
      }
    };
    worker.addEventListener("message", onMessage);
    worker.postMessage(message);
  });
}

/** Host that drives a proving Web Worker with cache, cancel, and progress hooks. */
export function createBrowserProver(config: BrowserProverConfig) {
  const cache = config.cache ?? createArtifactCache();
  const stages: string[] = [];

  return {
    stages() {
      return [...stages];
    },
    cancel() {
      config.worker.postMessage({ type: "cancel" });
    },
    clear() {
      config.worker.postMessage({ type: "clear" });
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
      const result = await requestWorker(config.worker, { type: "prove-development", value });
      const reported = result.stages.length > 0 ? result.stages : ["development"];
      for (const stage of reported) {
        if (!stages.includes(stage)) {
          stages.push(stage);
        }
        options?.onProgress?.(stage);
      }
      return result.proof;
    },
    async proveSpend(circom: Record<string, unknown>) {
      const result = await requestWorker(config.worker, { type: "prove-spend", circom });
      return result.proof;
    },
  };
}
