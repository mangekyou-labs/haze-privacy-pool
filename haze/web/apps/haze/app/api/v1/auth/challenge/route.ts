import { type NextRequest, NextResponse } from "next/server.js";
import {
  DEFAULT_APPLICATION_ID,
  createChallengeBFF,
  type NormalizedRole,
  validateOrigin,
} from "../../_lib.ts";

export async function POST(req: NextRequest) {
  if (!validateOrigin(req)) {
    return NextResponse.json(
      { code: "FORBIDDEN", error: "CSRF_ORIGIN_INVALID", message: "Origin validation failed" },
      { status: 403 },
    );
  }

  try {
    const body = await req.json().catch(() => ({}));
    const wallet = String(body.wallet || "").trim();
    if (!wallet || !/^0x[0-9a-fA-F]{40}$/.test(wallet)) {
      return NextResponse.json(
        { code: "ENCODING_INVALID", error: "ENCODING_INVALID", message: "Valid 20-byte hex wallet required" },
        { status: 400 },
      );
    }

    const applicationId = String(body.applicationId || DEFAULT_APPLICATION_ID).trim();
    const role: NormalizedRole = (body.role as NormalizedRole) || "pool-user";

    const authHeader = req.headers.get("authorization") || req.headers.get("Authorization");
    const headerToken = authHeader?.startsWith("Bearer ") ? authHeader.slice(7).trim() : undefined;
    const oidcToken = body.oidcToken || headerToken;

    const requestHost = req.headers.get("host")?.split(":", 1)[0];
    const challenge = await createChallengeBFF(wallet, applicationId, role, oidcToken, requestHost);
    return NextResponse.json(challenge);
  } catch (error: any) {
    const msg = error?.message || "ENCODING_INVALID";
    if (msg === "USER_INELIGIBLE" || msg === "APPLICATION_MISMATCH") {
      return NextResponse.json({ code: msg, error: msg, message: "User ineligible for role" }, { status: 403 });
    }
    if (msg === "UNAVAILABLE" || msg === "SERVICE_UNAVAILABLE") {
      return NextResponse.json({ code: "SERVICE_UNAVAILABLE", error: "SERVICE_UNAVAILABLE", message: "Auth service unavailable" }, { status: 503 });
    }
    return NextResponse.json({ code: "ENCODING_INVALID", error: "ENCODING_INVALID", message: msg }, { status: 400 });
  }
}
