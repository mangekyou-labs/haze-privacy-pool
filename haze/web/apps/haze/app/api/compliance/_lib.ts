import { cookies } from "next/headers.js";
import { type NextRequest, NextResponse } from "next/server.js";

export const DISCLOSURE_BASE_URL =
  process.env.HAZE_DISCLOSURE_ORIGIN ||
  process.env.NEXT_PUBLIC_HAZE_DISCLOSURE_ORIGIN ||
  "https://haze-fuji-disclosure-uegs.onrender.com";

export async function forwardToDisclosure(
  endpoint: string,
  req: NextRequest,
  init?: RequestInit,
): Promise<Response> {
  let sessionToken: string | undefined;
  try {
    const cookieJar = await cookies();
    sessionToken = cookieJar.get("haze_audit_session")?.value;
  } catch {
    // outside Next.js request storage (e.g. unit tests)
  }

  if (!sessionToken && req?.headers) {
    const cookieHeader = req.headers.get("cookie");
    if (cookieHeader) {
      for (const cookie of cookieHeader.split(";")) {
        const [k, v] = cookie.trim().split("=");
        if (k === "haze_audit_session") {
          sessionToken = v;
          break;
        }
      }
    }
  }

  const headers = new Headers(init?.headers || {});
  if (sessionToken && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${sessionToken}`);
  }
  if (!headers.has("Content-Type") && init?.body) {
    headers.set("Content-Type", "application/json");
  }

  const targetUrl = `${DISCLOSURE_BASE_URL.replace(/\/$/, "")}${endpoint}`;
  try {
    return await fetch(targetUrl, {
      ...init,
      headers,
      signal: init?.signal ?? AbortSignal.timeout(8_000),
    });
  } catch (error) {
    return new Response(
      JSON.stringify({
        code: "UNAVAILABLE",
        message: "Compliance service unavailable",
      }),
      { status: 503, headers: { "Content-Type": "application/json" } },
    );
  }
}

const DISCLOSURE_FIELDS = new Set(["tx_hash", "amount", "asset", "timestamp", "policy_version"]);

export function sanitizeBrowserPayload(value: unknown, key = ""): unknown {
  if (Array.isArray(value)) return value.map((item) => sanitizeBrowserPayload(item));
  if (!value || typeof value !== "object") return value;
  const output: Record<string, unknown> = {};
  for (const [childKey, childValue] of Object.entries(value)) {
    const normalized = childKey.toLowerCase();
    if (normalized === "user" || normalized === "counterparty" || normalized === "authorizeduser") continue;
    if (key === "fields" && !DISCLOSURE_FIELDS.has(childKey)) continue;
    output[childKey] = sanitizeBrowserPayload(childValue, childKey);
  }
  return output;
}

export async function sanitizedJsonResponse(response: Response): Promise<NextResponse> {
  const body = await response.json().catch(() => ({ code: "UNAVAILABLE", message: "Invalid upstream response" }));
  return NextResponse.json(sanitizeBrowserPayload(body), { status: response.status });
}
