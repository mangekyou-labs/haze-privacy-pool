import { type NextRequest, NextResponse } from "next/server.js";
import {
  setSessionCookie,
  validateOrigin,
  verifyChallengeBFF,
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
    const challengeId = String(body.challengeId || "").trim();
    const message = String(body.message || "").trim();
    const signature = String(body.signature || "").trim();

    if (!challengeId || !signature) {
      return NextResponse.json(
        { code: "ENCODING_INVALID", error: "ENCODING_INVALID", message: "Challenge ID and signature required" },
        { status: 400 },
      );
    }

    const { token, session } = await verifyChallengeBFF(challengeId, message, signature);

    // Return safe public metadata (NEVER expose token in JSON)
    const res = NextResponse.json({
      ok: true,
      authenticated: true,
      wallet: session.wallet,
      applicationId: session.applicationId,
      role: session.role,
      organization: session.organization || session.orgId,
      expiresAt: session.expiresAt,
    });

    setSessionCookie(res, token);
    return res;
  } catch (error: any) {
    const msg = error?.message || "REJECTED";
    if (msg === "AUTHORIZATION_EXPIRED") {
      return NextResponse.json(
        { code: "AUTHORIZATION_EXPIRED", error: "AUTHORIZATION_EXPIRED", message: "Challenge expired" },
        { status: 401 },
      );
    }
    if (msg === "REJECTED") {
      return NextResponse.json(
        { code: "REJECTED", error: "REJECTED", message: "Signature verification failed" },
        { status: 401 },
      );
    }
    return NextResponse.json(
      { code: "REJECTED", error: "REJECTED", message: msg },
      { status: 401 },
    );
  }
}
