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
      { code: "FORBIDDEN", error: "FORBIDDEN", message: "Cannot access other wallet history" },
      { status: 403 },
    );
  }

  const wallet = session ? session.wallet : requestedWallet || "0x0000000000000000000000000000000000000000";

  if (!isFixtureMode()) {
    return NextResponse.json(
      { code: "UNAVAILABLE", error: "UNAVAILABLE", message: "Indexer history service unavailable" },
      { status: 503 },
    );
  }

  const notes = [
    {
      id: "note-1",
      kind: "deposit",
      amount: "1000000",
      asset: "USDC",
      commitment: "0x0acd50a5afb0a74605cea66358fae514a6aba02dce5ee081ae888fee11f716c3",
      leafIndex: 0,
      timestamp: Date.now() - 3600000,
      status: "confirmed",
    },
  ];

  return NextResponse.json({
    wallet: wallet.toLowerCase(),
    notes,
    totalNotes: notes.length,
    spendableBalance: "1000000",
  });
}
