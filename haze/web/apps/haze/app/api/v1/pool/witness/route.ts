import { type NextRequest, NextResponse } from "next/server.js";
import {
  DEFAULT_APPLICATION_ID,
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
  const authErr = requireRole(session, "pool-user");
  if (authErr) return authErr;

  try {
    const body = await req.json().catch(() => ({}));
    const applicationId = body.applicationId || DEFAULT_APPLICATION_ID;

    if (!isFixtureMode()) {
      return NextResponse.json(
        { code: "UNAVAILABLE", error: "UNAVAILABLE", message: "Policy witness service unavailable" },
        { status: 503 },
      );
    }

    return NextResponse.json({
      applicationId,
      noteTreeRoot: "0x0834693af15be6ce56617a953ce591e1e46e146699b852358b6edbac846ca885",
      applicationPolicyVersion: 1,
      hazePolicyVersion: 1,
      applicationMembershipRoot: "0x0000000000000000000000000000000000000000000000000000000000000011",
      hazeBlocklistRoot: "0x0000000000000000000000000000000000000000000000000000000000000044",
      activeVersion: "0x000000000000000000000000000000000000000000000000000000000000b001",
      replacementVersion: "0x000000000000000000000000000000000000000000000000000000000000b003",
    });
  } catch {
    return NextResponse.json(
      { code: "WITNESS_UNAVAILABLE", error: "WITNESS_UNAVAILABLE", message: "Failed to generate policy witness" },
      { status: 500 },
    );
  }
}
