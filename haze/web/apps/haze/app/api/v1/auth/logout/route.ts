import { type NextRequest, NextResponse } from "next/server.js";
import {
  clearSessionCookie,
  extractSessionToken,
  revokeSessionBFF,
  validateOrigin,
} from "../../_lib.ts";

export async function POST(req: NextRequest) {
  if (!validateOrigin(req)) {
    return NextResponse.json(
      { code: "FORBIDDEN", error: "CSRF_ORIGIN_INVALID", message: "Origin validation failed" },
      { status: 403 },
    );
  }

  const token = await extractSessionToken(req);
  if (token) {
    try {
      await revokeSessionBFF(token);
    } catch {
      return NextResponse.json(
        { code: "UNAVAILABLE", error: "UNAVAILABLE", message: "Authentication service unavailable" },
        { status: 503 },
      );
    }
  }

  const res = NextResponse.json({ ok: true, revoked: true });
  clearSessionCookie(res);
  res.cookies.delete("haze_session");
  res.cookies.delete("haze_audit_session");
  res.cookies.delete("haze-role");
  return res;
}
