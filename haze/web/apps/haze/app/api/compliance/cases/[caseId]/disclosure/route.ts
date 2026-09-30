import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { getComplianceStore } from "../../../../../../lib/compliance-store.ts";

export async function POST(
  _request: Request,
  { params }: { params: Promise<{ caseId: string }> }
) {
  try {
    const { caseId } = await params;
    const jar = await cookies();
    const token = jar.get("haze_compliance_session")?.value;
    const store = getComplianceStore();
    const session = await store.getSession(token);
    if (!session || session.role !== "application-auditor") {
      return NextResponse.json({ error: "UNAUTHORIZED" }, { status: 401 });
    }
    const result = await store.discloseCase(caseId, session.address);
    return NextResponse.json({
      ok: true,
      ...result,
    });
  } catch (err: any) {
    const code = err?.code || "UNAUTHORIZED";
    const status = code === "FINALITY_REQUIRED" ? 400 : 403;
    return NextResponse.json({ ok: false, error: err?.message || code, code }, { status });
  }
}
