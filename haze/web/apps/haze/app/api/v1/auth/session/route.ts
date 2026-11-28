import { type NextRequest, NextResponse } from "next/server.js";
import {
  introspectSession,
  isSessionDependencyUnavailable,
} from "../../_lib.ts";

export async function GET(req: NextRequest) {
  const session = await introspectSession(req);
  if (isSessionDependencyUnavailable(session)) {
    return NextResponse.json(
      { code: "UNAVAILABLE", error: "UNAVAILABLE", message: "Authentication service unavailable" },
      { status: 503 },
    );
  }
  if (!session) {
    return NextResponse.json({
      authenticated: false,
      wallet: null,
      applicationId: null,
      organization: null,
      role: null,
      expiresAt: null,
    });
  }

  return NextResponse.json({
    authenticated: true,
    wallet: session.wallet,
    applicationId: session.applicationId,
    organization: session.organization || session.orgId || null,
    role: session.role,
    expiresAt: session.expiresAt,
  });
}
