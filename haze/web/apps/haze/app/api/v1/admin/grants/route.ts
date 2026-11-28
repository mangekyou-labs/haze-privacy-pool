import { type NextRequest, NextResponse } from "next/server.js";
import {
  introspectSession,
  isFixtureMode,
  requireRole,
  validateOrigin,
} from "../../_lib.ts";

export async function POST(req: NextRequest) {
  if (!validateOrigin(req)) {
    return NextResponse.json(
      { code: "FORBIDDEN", error: "CSRF_ORIGIN_INVALID", message: "Origin validation failed" },
      { status: 403 },
    );
  }

  const session = await introspectSession(req);
  const authErr = requireRole(session, "application-admin");
  if (authErr) return authErr;

  try {
    const body = await req.json().catch(() => ({}));
    const { grantId, auditorWallet, grantedFields, deniedFields, revoke = false } = body;

    if (auditorWallet && !/^0x[0-9a-fA-F]{40}$/.test(auditorWallet)) {
      return NextResponse.json(
        { code: "ENCODING_INVALID", error: "ENCODING_INVALID", message: "Invalid auditor wallet address" },
        { status: 400 },
      );
    }

    if (!isFixtureMode()) {
      return NextResponse.json(
        { code: "UNAVAILABLE", error: "UNAVAILABLE", message: "Grant management backend unavailable" },
        { status: 503 },
      );
    }

    return NextResponse.json({
      ok: true,
      grantId: grantId || "0x0000000000000000000000000000000000000000000000000000000000000001",
      auditorWallet: auditorWallet ? auditorWallet.toLowerCase() : "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
      grantedFields: grantedFields || ["amount", "asset", "timestamp", "tx_hash"],
      deniedFields: deniedFields || ["user", "counterparty"],
      revoked: Boolean(revoke),
    });
  } catch {
    return NextResponse.json(
      { code: "GRANT_UPDATE_FAILED", error: "GRANT_UPDATE_FAILED", message: "Failed to update auditor grant" },
      { status: 500 },
    );
  }
}
