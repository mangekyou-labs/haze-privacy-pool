import { cookies } from "next/headers.js";
import { type NextRequest, NextResponse } from "next/server.js";
import { keccak256 } from "../../../../../../sdk/typescript/src/keccak.ts";

export { keccak256 };

export const CHAIN_ID = 43113;
export const DEFAULT_APPLICATION_ID = "0x0000000000000000000000000000000000000000000000000000000000000a11";
export const ACTIVE_POOL_VERSION = "0x000000000000000000000000000000000000000000000000000000000000b001";
export const REPLACEMENT_POOL_VERSION = "0x000000000000000000000000000000000000000000000000000000000000b003";

export const FUJI_SESSION_COOKIE = "haze_fuji_session";

export type NormalizedRole =
  | "pool-user"
  | "application-admin"
  | "application-auditor"
  | "governance-operator"
  | "super-auditor";

export type SessionPayload = {
  wallet: string;
  applicationId: string;
  role: NormalizedRole;
  orgId?: string;
  organization?: string;
  subject?: string;
  expiresAt: number;
  dependencyUnavailable?: true;
};

function unavailableSession(): SessionPayload {
  return {
    wallet: "",
    applicationId: "",
    role: "pool-user",
    expiresAt: 0,
    dependencyUnavailable: true,
  };
}

export function isSessionDependencyUnavailable(
  session: SessionPayload | null,
): boolean {
  return session?.dependencyUnavailable === true;
}

export type ChallengePayload = {
  challengeId: string;
  nonce: string;
  message: string;
  expiresAt: number;
  chainId: number;
};

// In-memory fallback for unit tests and local mock mode
const localChallenges = new Map<
  string,
  {
    challengeId: string;
    nonce: string;
    wallet: string;
    applicationId: string;
    role: NormalizedRole;
    message: string;
    expiresAt: number;
    consumed: boolean;
  }
>();

const localSessions = new Map<
  string, // token hash hex
  SessionPayload & { revoked: boolean }
>();

function hashToken(token: string): string {
  const bytes = Buffer.from(token, "utf-8");
  return Buffer.from(keccak256(bytes)).toString("hex");
}

export function isFixtureMode(): boolean {
  if (process.env.NODE_ENV === "production") return false;
  return process.env.HAZE_FIXTURE_MODE === "true" || process.env.NODE_ENV === "test";
}

export function validateOrigin(req: NextRequest): boolean {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return true;

  const origin = req.headers.get("origin");
  const host = req.headers.get("host");

  if (!origin) {
    const referer = req.headers.get("referer");
    if (referer && host) {
      try {
        const refUrl = new URL(referer);
        if (refUrl.host === host) return true;
      } catch {}
    }
    return false;
  }

  try {
    const originUrl = new URL(origin);
    if (host && originUrl.host === host) return true;

    const allowedOrigins = [
      process.env.HAZE_VERCEL_ORIGIN,
      process.env.HAZE_AUTH_ORIGIN,
      process.env.HAZE_ORIGIN,
      "http://localhost:3000",
      "http://127.0.0.1:3000",
      "http://localhost:3010",
      "http://127.0.0.1:3010",
      "http://localhost:8080",
      "http://127.0.0.1:8080",
    ].filter(Boolean);

    return allowedOrigins.some((ao) => origin === ao || originUrl.origin === ao);
  } catch {
    return false;
  }
}

export function setSessionCookie(res: NextResponse, token: string): void {
  res.cookies.set(FUJI_SESSION_COOKIE, token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    path: "/",
    maxAge: 3600,
  });
}

export function clearSessionCookie(res: NextResponse): void {
  res.cookies.set(FUJI_SESSION_COOKIE, "", {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    path: "/",
    maxAge: 0,
  });
}

export async function extractSessionToken(req?: NextRequest): Promise<string | null> {
  try {
    const jar = await cookies();
    const cookieVal = jar.get(FUJI_SESSION_COOKIE)?.value;
    if (cookieVal && cookieVal.trim().length > 0) return cookieVal.trim();
  } catch {}

  if (req?.headers) {
    const authHdr = req.headers.get("authorization") || req.headers.get("Authorization");
    if (authHdr?.startsWith("Bearer ")) {
      const t = authHdr.slice(7).trim();
      if (t.length > 0) return t;
    }

    const rawCookie = req.headers.get("cookie") || req.headers.get("Cookie");
    if (rawCookie) {
      for (const pair of rawCookie.split(";")) {
        const [k, v] = pair.trim().split("=");
        if (k === FUJI_SESSION_COOKIE && v && v.trim().length > 0) {
          return v.trim();
        }
      }
    }
  }

  return null;
}

export async function introspectSession(req?: NextRequest): Promise<SessionPayload | null> {
  const token = await extractSessionToken(req);
  if (!token) return null;

  const authOrigin = process.env.HAZE_AUTH_ORIGIN;
  if (authOrigin) {
    try {
      const res = await fetch(`${authOrigin.replace(/\/+$/, "")}/v1/auth/introspect`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
      });
      if (!res.ok) return res.status >= 500 ? unavailableSession() : null;
      const data = await res.json();
      if (!data.valid) return null;
      return {
        wallet: data.wallet,
        applicationId: data.applicationId,
        role: data.role,
        orgId: data.orgId,
        organization: data.organization || data.orgId,
        subject: data.subject,
        expiresAt: data.expiresAt,
      };
    } catch {
      return unavailableSession();
    }
  }

  if (!isFixtureMode()) {
    return unavailableSession();
  }

  // Local in-memory session validation for explicit fixtures
  const tokenHash = hashToken(token);
  const session = localSessions.get(tokenHash);
  if (!session) return null;
  if (session.revoked) return null;
  if (session.expiresAt <= Math.floor(Date.now() / 1000)) return null;

  return {
    wallet: session.wallet,
    applicationId: session.applicationId,
    role: session.role,
    orgId: session.orgId,
    organization: session.organization || session.orgId,
    subject: session.subject,
    expiresAt: session.expiresAt,
  };
}

export function requireRole(
  session: SessionPayload | null,
  allowedRoles: NormalizedRole | NormalizedRole[],
): NextResponse | null {
  if (isSessionDependencyUnavailable(session)) {
    return NextResponse.json(
      { code: "UNAVAILABLE", error: "UNAVAILABLE", message: "Authentication service unavailable" },
      { status: 503 },
    );
  }

  if (!session) {
    return NextResponse.json(
      { code: "UNAUTHORIZED", error: "UNAUTHORIZED", message: "Authentication required" },
      { status: 401 },
    );
  }

  const allowedList = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];

  // Super-auditor strictly isolated from admin or governance
  if (
    session.role === "super-auditor" &&
    (allowedList.includes("application-admin") || allowedList.includes("governance-operator"))
  ) {
    return NextResponse.json(
      { code: "FORBIDDEN", error: "FORBIDDEN", message: "Super-auditor access restricted to audit" },
      { status: 403 },
    );
  }

  if (!allowedList.includes(session.role)) {
    return NextResponse.json(
      { code: "FORBIDDEN", error: "FORBIDDEN", message: `Role ${session.role} unauthorized for route` },
      { status: 403 },
    );
  }

  return null;
}

export async function createChallengeBFF(
  wallet: string,
  applicationId: string,
  role: NormalizedRole,
  oidcToken?: string,
  requestHost?: string,
): Promise<ChallengePayload> {
  const authOrigin = process.env.HAZE_AUTH_ORIGIN;
  if (authOrigin) {
    const res = await fetch(`${authOrigin.replace(/\/+$/, "")}/v1/auth/challenge`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(requestHost ? { "X-Haze-Origin-Host": requestHost } : {}),
        ...(oidcToken ? { Authorization: `Bearer ${oidcToken}` } : {}),
      },
      body: JSON.stringify({
        wallet,
        applicationId,
        role,
        oidcToken,
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      const code = err.code || "USER_INELIGIBLE";
      throw new Error(code);
    }
    return await res.json();
  }

  if (!isFixtureMode()) {
    throw new Error("SERVICE_UNAVAILABLE");
  }

  // Local in-memory challenge generation for explicit fixtures
  const nonce = Buffer.from(keccak256(Buffer.from(`${wallet}:${Date.now()}:${Math.random()}`)))
    .toString("hex")
    .slice(0, 32);
  const challengeId = `0x${Buffer.from(keccak256(Buffer.from(`${nonce}:${wallet}`))).toString("hex")}`;
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + 300;

  const appPart = applicationId ? `\nResources:\n- urn:haze:app:${applicationId.replace(/^0x/, "")}` : "";
  const host = requestHost || process.env.HAZE_COMPLIANCE_DOMAIN || "localhost:3000";
  const protocol = host.startsWith("localhost") || host.startsWith("127.0.0.1") ? "http" : "https";
  const message = `${host} wants you to sign in with your Ethereum account:\n${wallet}\n\nSign in to Haze Compliance Portal (Fuji)\n\nURI: ${protocol}://${host}/audit\nVersion: 1\nChain ID: ${CHAIN_ID}\nNonce: ${nonce}\nIssued At: ${new Date(now * 1000).toISOString()}\nExpiration Time: ${new Date(expiresAt * 1000).toISOString()}${appPart}`;

  localChallenges.set(challengeId, {
    challengeId,
    nonce,
    wallet: wallet.toLowerCase(),
    applicationId,
    role,
    message,
    expiresAt,
    consumed: false,
  });

  return {
    challengeId,
    nonce,
    message,
    expiresAt,
    chainId: CHAIN_ID,
  };
}

export async function verifyChallengeBFF(
  challengeId: string,
  message: string,
  signature: string,
): Promise<{ token: string; session: SessionPayload }> {
  const authOrigin = process.env.HAZE_AUTH_ORIGIN;
  if (authOrigin) {
    const res = await fetch(`${authOrigin.replace(/\/+$/, "")}/v1/auth/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ challengeId, message, signature }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.code || "REJECTED");
    }
    const data = await res.json();
    return {
      token: data.token,
      session: {
        wallet: data.wallet,
        applicationId: data.applicationId,
        role: data.role,
        orgId: data.orgId,
        organization: data.orgId,
        subject: data.subject,
        expiresAt: data.expiresAt,
      },
    };
  }

  if (!isFixtureMode()) {
    throw new Error("SERVICE_UNAVAILABLE");
  }

  // Local in-memory verification for explicit fixtures
  const challenge = localChallenges.get(challengeId);
  if (!challenge) throw new Error("AUTHORIZATION_EXPIRED");
  if (challenge.consumed) throw new Error("REJECTED");
  if (challenge.expiresAt <= Math.floor(Date.now() / 1000)) throw new Error("AUTHORIZATION_EXPIRED");
  if (challenge.message.trim() !== message.trim()) throw new Error("REJECTED");

  challenge.consumed = true;

  const rawToken = `0x${Buffer.from(keccak256(Buffer.from(`${challengeId}:${Date.now()}:${Math.random()}`))).toString("hex")}`;
  const tokenHash = hashToken(rawToken);
  const now = Math.floor(Date.now() / 1000);
  const sessionExpiresAt = now + 3600;

  const sessionPayload: SessionPayload & { revoked: boolean } = {
    wallet: challenge.wallet,
    applicationId: challenge.applicationId,
    role: challenge.role,
    orgId: "org-haze-fuji",
    organization: "org-haze-fuji",
    expiresAt: sessionExpiresAt,
    revoked: false,
  };

  localSessions.set(tokenHash, sessionPayload);

  return {
    token: rawToken,
    session: {
      wallet: sessionPayload.wallet,
      applicationId: sessionPayload.applicationId,
      role: sessionPayload.role,
      orgId: sessionPayload.orgId,
      organization: sessionPayload.organization,
      expiresAt: sessionPayload.expiresAt,
    },
  };
}

export async function revokeSessionBFF(token: string): Promise<boolean> {
  const authOrigin = process.env.HAZE_AUTH_ORIGIN;
  if (authOrigin) {
    try {
      const res = await fetch(`${authOrigin.replace(/\/+$/, "")}/v1/auth/revoke`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
      });
      if (res.status >= 500) throw new Error("SERVICE_UNAVAILABLE");
      return res.ok;
    } catch {
      throw new Error("SERVICE_UNAVAILABLE");
    }
  }

  if (!isFixtureMode()) {
    throw new Error("SERVICE_UNAVAILABLE");
  }

  const tokenHash = hashToken(token);
  const session = localSessions.get(tokenHash);
  if (session) {
    session.revoked = true;
    return true;
  }
  return false;
}
