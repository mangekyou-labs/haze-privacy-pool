import { keccakHex } from "./abi.ts";
import { SdkError } from "./errors.ts";
import { HAZE_PRODUCT_ID } from "./identity.ts";

const SECRET_KEYS = new Set(["privatekey", "secret", "ssn", "password", "mnemonic", "seed"]);

export type ApplicationManifest = {
  schemaVersion: number;
  productId: string;
  applicationId: string;
  organizationName: string;
  gatekeeperEndpoint: string;
  portalEndpoint: string;
  auditorPolicy: Record<string, unknown>;
  kmsKeyRefs: string[];
  auditKeys: Array<{ version: number; publicKey: string }>;
  sourceTokens: Array<{ token: string; decimals: number }>;
  manifestVersion: number;
};

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = canonicalize((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

function assertNoSecrets(value: unknown): void {
  if (Array.isArray(value)) {
    for (const item of value) {
      assertNoSecrets(item);
    }
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
      if (SECRET_KEYS.has(key.toLowerCase())) {
        throw new SdkError("ENCODING_INVALID");
      }
      assertNoSecrets(nested);
    }
  }
}

/** Keccak-256 of canonical sorted-key JSON. */
export function hashManifest(manifest: Record<string, unknown>): string {
  return keccakHex(Buffer.from(JSON.stringify(canonicalize(manifest))));
}

/** Reject secret fields and version/hash drift before accepting a manifest. */
export function parseManifest(
  manifest: Record<string, unknown>,
  expectedHash: string,
): ApplicationManifest {
  assertNoSecrets(manifest);
  if (
    manifest.schemaVersion !== 1 ||
    manifest.productId !== HAZE_PRODUCT_ID ||
    manifest.manifestVersion !== 1
  ) {
    throw new SdkError("VERSION_UNSUPPORTED");
  }
  if (hashManifest(manifest).toLowerCase() !== expectedHash.toLowerCase()) {
    throw new SdkError("ENCODING_INVALID");
  }
  return manifest as ApplicationManifest;
}
