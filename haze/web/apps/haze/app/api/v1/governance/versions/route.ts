import { type NextRequest, NextResponse } from "next/server.js";
import {
  ACTIVE_POOL_VERSION,
  REPLACEMENT_POOL_VERSION,
  introspectSession,
  isFixtureMode,
  requireRole,
} from "../../_lib.ts";

export async function GET(req: NextRequest) {
  const session = await introspectSession(req);
  const authErr = requireRole(session, "governance-operator");
  if (authErr) return authErr;

  if (!isFixtureMode()) {
    return NextResponse.json(
      { code: "UNAVAILABLE", error: "UNAVAILABLE", message: "Version registry backend unavailable" },
      { status: 503 },
    );
  }

  return NextResponse.json({
    activeVersion: {
      versionTag: ACTIVE_POOL_VERSION,
      label: "B002",
      status: "active",
      supportUntil: new Date(Date.now() + 180 * 24 * 3600 * 1000).toISOString(),
    },
    stagedVersion: {
      versionTag: REPLACEMENT_POOL_VERSION,
      label: "B003",
      status: "staged_replacement",
      supportUntil: new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString(),
    },
    protocolVersionTag: "0x2afe8a5679df289719eae23ad89b300434b9dfbb8194dad0b50dee97f91a3868",
  });
}
