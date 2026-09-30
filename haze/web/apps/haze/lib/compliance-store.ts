/**
 * ComplianceStore factory for the Next.js BFF layer.
 *
 * Returns a Postgres-backed ComplianceStore when DATABASE_URL is set and the
 * `pg` package is available, otherwise falls back to the SDK's in-memory store.
 *
 * In production (Vercel), set DATABASE_URL in the environment to enable durable
 * compliance storage across serverless cold starts.
 */

import {
  ComplianceMemoryStore,
  type ComplianceStore,
} from "../../../../sdk/typescript/src/compliance-service.ts";
import { CompliancePostgresStore } from "./compliance-postgres-store.ts";

let _cachedStore: ComplianceStore | null = null;

/**
 * Get or create the global compliance store.
 * Postgres-backed when DATABASE_URL is available; in-memory otherwise.
 */
export function getComplianceStore(): ComplianceStore {
  if (_cachedStore) return _cachedStore;

  const dbUrl = process.env.DATABASE_URL;
  const forceMemory = process.env.HAZE_COMPLIANCE_STORE === "memory";

  if (dbUrl && !forceMemory) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const pg = require("pg");
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const Pool = (pg as any).Pool;
      const pool = new Pool({
        connectionString: dbUrl,
        max: 5,
        idleTimeoutMillis: 10_000,
        connectionTimeoutMillis: 5_000,
      });
      _cachedStore = new CompliancePostgresStore(pool);
      console.info("[compliance-store] Using Postgres-backed store");
      return _cachedStore;
    } catch (err) {
      console.warn("[compliance-store] DATABASE_URL set but pg unavailable, falling back to memory:", err);
    }
  }

  _cachedStore = new ComplianceMemoryStore();
  return _cachedStore;
}

/**
 * Reset the cached store (for testing only).
 */
export function resetComplianceStore(): void {
  _cachedStore = null;
}
