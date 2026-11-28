import { type NextRequest, NextResponse } from "next/server.js";
import {
  DEFAULT_APPLICATION_ID,
  introspectSession,
  isFixtureMode,
  requireRole,
} from "../../_lib.ts";

export async function GET(req: NextRequest) {
  const session = await introspectSession(req);
  const authErr = requireRole(session, "application-admin");
  if (authErr) return authErr;

  if (!isFixtureMode()) {
    return NextResponse.json(
      { code: "UNAVAILABLE", error: "UNAVAILABLE", message: "Application repository unavailable" },
      { status: 503 },
    );
  }

  return NextResponse.json({
    applications: [
      {
        applicationId: DEFAULT_APPLICATION_ID,
        name: "Haze Avalanche Fuji Default App",
        adminWallet: "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
        gatekeeperSigner: "0xed37fd0d6f0f69236e7472b36796e133d20ecc32",
        policyAuthority: "0xed37fd0d6f0f69236e7472b36796e133d20ecc32",
        auditPublicKey: "0x1111111111111111111111111111111111111111111111111111111111111111",
        auditKeyVersion: 1,
        membershipRoot: "0x0000000000000000000000000000000000000000000000000000000000000011",
        membershipVersion: 1,
        status: "active",
        kmsHealth: "healthy",
      },
    ],
  });
}
