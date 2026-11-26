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
  const authErr = requireRole(session, "application-admin");
  if (authErr) return authErr;

  try {
    const body = await req.json().catch(() => ({}));
    const { applicationId = DEFAULT_APPLICATION_ID, memberWallet } = body;
    if (!memberWallet || !/^0x[0-9a-fA-F]{40}$/.test(memberWallet)) {
      return NextResponse.json(
        { code: "ENCODING_INVALID", error: "ENCODING_INVALID", message: "Valid member wallet required" },
        { status: 400 },
      );
    }

    if (!isFixtureMode()) {
      return NextResponse.json(
        { code: "UNAVAILABLE", error: "UNAVAILABLE", message: "Membership management backend unavailable" },
        { status: 503 },
      );
    }

    const updatedMembershipVersion = 2;
    const updatedMembershipRoot = "0x0000000000000000000000000000000000000000000000000000000000000022";

    return NextResponse.json({
      ok: true,
      applicationId,
      memberWallet: memberWallet.toLowerCase(),
      membershipVersion: updatedMembershipVersion,
      membershipRoot: updatedMembershipRoot,
      status: "enrolled",
    });
  } catch {
    return NextResponse.json(
      { code: "ENROLLMENT_FAILED", error: "ENROLLMENT_FAILED", message: "Failed to enroll member" },
      { status: 500 },
    );
  }
}
