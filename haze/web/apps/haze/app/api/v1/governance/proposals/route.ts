import { type NextRequest, NextResponse } from "next/server.js";
import {
  introspectSession,
  isFixtureMode,
  requireRole,
  validateOrigin,
} from "../../_lib.ts";

const proposalsStore = [
  {
    proposalId: 0,
    target: "0x55aA4F400f3819498eD4Cbe120839E609f0897F3", // VersionRegistry
    value: "0",
    data: "0x",
    description: "Activate Fuji Protocol Version B002 and Stage B003",
    executed: false,
    approvalsCount: 1,
    approvers: ["0xed37fd0d6f0f69236e7472b36796e133d20ecc32"],
  },
];

export async function GET(req: NextRequest) {
  const session = await introspectSession(req);
  const authErr = requireRole(session, "governance-operator");
  if (authErr) return authErr;

  if (!isFixtureMode()) {
    return NextResponse.json(
      { code: "UNAVAILABLE", error: "UNAVAILABLE", message: "Governance backend unavailable" },
      { status: 503 },
    );
  }

  return NextResponse.json({
    proposals: proposalsStore,
    totalProposals: proposalsStore.length,
    threshold: 2,
    owners: [
      "0xed37fd0d6f0f69236e7472b36796e133d20ecc32",
      "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
      "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
    ],
  });
}

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
    const { target, value = "0", data = "0x", description = "New proposal" } = body;

    if (!target || !/^0x[0-9a-fA-F]{40}$/.test(target)) {
      return NextResponse.json(
        { code: "ENCODING_INVALID", error: "ENCODING_INVALID", message: "Valid target address required" },
        { status: 400 },
      );
    }

    if (!isFixtureMode()) {
      return NextResponse.json(
        { code: "UNAVAILABLE", error: "UNAVAILABLE", message: "Governance backend unavailable" },
        { status: 503 },
      );
    }

    const proposalId = proposalsStore.length;
    const newProposal = {
      proposalId,
      target,
      value: String(value),
      data,
      description,
      executed: false,
      approvalsCount: 1,
      approvers: [session?.wallet || "0xed37fd0d6f0f69236e7472b36796e133d20ecc32"],
    };
    proposalsStore.push(newProposal);
    return NextResponse.json({ ok: true, proposal: newProposal });
  } catch {
    return NextResponse.json(
      { code: "PROPOSAL_FAILED", error: "PROPOSAL_FAILED", message: "Failed to create proposal" },
      { status: 500 },
    );
  }
}
