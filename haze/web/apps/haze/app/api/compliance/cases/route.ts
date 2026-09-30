import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { getComplianceStore } from "../../../../lib/compliance-store.ts";

export async function GET() {
  const jar = await cookies();
  const token = jar.get("haze_compliance_session")?.value;
  const store = getComplianceStore();
  const session = await store.getSession(token);
  if (!session || session.role !== "application-auditor") {
    return NextResponse.json({ error: "UNAUTHORIZED" }, { status: 401 });
  }
  const cases = await store.listAssignedCases(session.address, session.applicationId);
  return NextResponse.json({
    cases,
    total: cases.length,
    auditor: session.address,
    applicationId: session.applicationId,
  });
}
