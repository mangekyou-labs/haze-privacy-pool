import type { HazeIntentFields } from "./eip712.ts";
import { parseGatekeeperError, SdkError } from "./errors.ts";
import { HAZE_API_VERSION } from "./identity.ts";
import { hashManifest, parseManifest, type ApplicationManifest } from "./manifest.ts";

type GatekeeperFetch = (
  url: string,
  init: { method: string; headers: Record<string, string>; body?: string },
) => Promise<{
  ok: boolean;
  status: number;
  headers: { get(name: string): string | null };
  json(): Promise<unknown>;
  text(): Promise<string>;
}>;

function joinPath(endpoint: string, path: string): string {
  return `${endpoint.replace(/\/$/, "")}/${path.replace(/^\//, "")}`;
}

function requireApiVersion(headers: { get(name: string): string | null }, expected: number): void {
  if (headers.get("haze-api-version") !== String(expected)) {
    throw new SdkError("VERSION_UNSUPPORTED");
  }
}

/** Versioned gatekeeper HTTP client. */
export function createGatekeeperClient(config: {
  endpoint: string;
  apiVersion?: number;
  fetch: GatekeeperFetch;
}) {
  const apiVersion = config.apiVersion ?? HAZE_API_VERSION;
  const headers = {
    "haze-api-version": String(apiVersion),
    accept: "application/json",
  };

  return {
    async requestAuthorization(request: {
      applicationId: string;
      session: string;
      intent: HazeIntentFields;
    }) {
      const response = await config.fetch(joinPath(config.endpoint, "authorizations"), {
        method: "POST",
        headers,
        body: JSON.stringify(request),
      });
      requireApiVersion(response.headers, apiVersion);
      if (!response.ok) {
        const body = (await response.json()) as { code?: string };
        throw new SdkError(parseGatekeeperError(body));
      }
      return response.json();
    },

    async fetchManifest(applicationId: string): Promise<ApplicationManifest> {
      const response = await config.fetch(
        joinPath(config.endpoint, `applications/${applicationId}/manifest`),
        { method: "GET", headers },
      );
      requireApiVersion(response.headers, apiVersion);
      if (!response.ok) {
        const body = (await response.json()) as { code?: string };
        throw new SdkError(parseGatekeeperError(body));
      }
      const body = (await response.json()) as Record<string, unknown>;
      return parseManifest(body, hashManifest(body));
    },
  };
}
