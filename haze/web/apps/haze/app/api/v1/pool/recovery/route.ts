import { type NextRequest, NextResponse } from "next/server.js";
import {
  introspectSession,
  isFixtureMode,
  requireRole,
} from "../../_lib.ts";

export async function GET(req: NextRequest) {
  const session = await introspectSession(req);
  const authErr = requireRole(session, "pool-user");
  if (authErr) return authErr;

  const requestedWallet = req.nextUrl.searchParams.get("wallet");
  if (
    requestedWallet &&
    session &&
    requestedWallet.toLowerCase() !== session.wallet.toLowerCase()
  ) {
    return NextResponse.json(
      { code: "FORBIDDEN", error: "FORBIDDEN", message: "Cannot access other wallet recovery" },
      { status: 403 },
    );
  }

  const wallet = session ? session.wallet : requestedWallet || "0x0000000000000000000000000000000000000000";

  if (!isFixtureMode()) {
    return NextResponse.json(
      { code: "UNAVAILABLE", error: "UNAVAILABLE", message: "Recovery service unavailable" },
      { status: 503 },
    );
  }

  return NextResponse.json({
    wallet: wallet.toLowerCase(),
    envelopes: [
      {
        commitment: "0x0acd50a5afb0a74605cea66358fae514a6aba02dce5ee081ae888fee11f716c3",
        leafIndex: 0,
        encryptedPayload: "0x112233445566",
        txHash: "0xf83220015bdca26a7d801f84558590159007ffe59d613a85c90d7c29a5293036",
      },
    ],
  });
}
