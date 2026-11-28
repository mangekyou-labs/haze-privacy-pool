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
  const authErr = requireRole(session, "governance-operator");
  if (authErr) return authErr;

  try {
    const body = await req.json().catch(() => ({}));
    const { proposalId } = body;
    if (proposalId === undefined || proposalId === null) {
      return NextResponse.json(
        { code: "ENCODING_INVALID", error: "ENCODING_INVALID", message: "Proposal ID required" },
        { status: 400 },
      );
    }

    if (!isFixtureMode()) {
      return NextResponse.json(
        { code: "UNAVAILABLE", error: "UNAVAILABLE", message: "Governance backend unavailable" },
        { status: 503 },
      );
    }

    return NextResponse.json({
      ok: true,
      proposalId: Number(proposalId),
      approvalsCount: 2,
      readyToExecute: true,
    });
  } catch {
    return NextResponse.json(
      { code: "APPROVAL_FAILED", error: "APPROVAL_FAILED", message: "Failed to approve proposal" },
      { status: 500 },
    );
  }
}
