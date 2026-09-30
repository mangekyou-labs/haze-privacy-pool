import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { getComplianceStore } from "../../../../lib/compliance-store.ts";

export async function GET() {
  const jar = await cookies();
  const token = jar.get("haze_compliance_session")?.value;
  const store = getComplianceStore();
  const session = await store.getSession(token);
  if (!session) {
    return NextResponse.json({ authenticated: false }, { status: 200 });
  }
  return NextResponse.json({
    authenticated: true,
    address: session.address,
    role: session.role,
    applicationId: session.applicationId,
  });
}

export async function DELETE() {
  const jar = await cookies();
  const token = jar.get("haze_compliance_session")?.value;
  const store = getComplianceStore();
  await store.deleteSession(token);
  const response = NextResponse.json({ ok: true });
  response.cookies.delete("haze_compliance_session");
  return response;
}
