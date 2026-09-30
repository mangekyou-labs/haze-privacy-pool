import { NextResponse } from "next/server";
import { getComplianceStore } from "../../../../../lib/compliance-store.ts";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { nonce, address, signature } = body;
    if (!nonce || !address || !signature) {
      return NextResponse.json({ ok: false, error: "INVALID_PARAMETERS" }, { status: 400 });
    }
    const store = getComplianceStore();
    const result = await store.verifySiweChallenge(nonce, address, signature);
    const response = NextResponse.json({
      ok: true,
      address: result.address,
      role: result.role,
      applicationId: result.applicationId,
    });
    response.cookies.set("haze_compliance_session", result.token, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      path: "/",
      maxAge: 86400,
    });
    return response;
  } catch (err: any) {
    return NextResponse.json({ ok: false, error: err?.message || "UNAUTHORIZED" }, { status: 401 });
  }
}
