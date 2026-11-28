import { type NextRequest, NextResponse } from "next/server.js";
import { forwardToDisclosure } from "../../_lib.ts";

export async function POST(req: NextRequest) {
  const body = await req.text();
  const resp = await forwardToDisclosure("/v1/auth/verify", req, {
    method: "POST",
    body,
  });

  if (!resp.ok) {
    const errorData = await resp.text();
    return new NextResponse(errorData, {
      status: resp.status,
      headers: { "Content-Type": "application/json" },
    });
  }

  const session = await resp.json();
  const token = session.token;
  const nowSecs = Math.floor(Date.now() / 1000);
  const maxAge = Math.max(0, (session.expiresAt || nowSecs + 3600) - nowSecs);

  const response = NextResponse.json({
    address: session.address,
    applicationId: session.applicationId,
    role: session.role,
    expiresAt: session.expiresAt,
  });

  if (token) {
    response.cookies.set("haze_audit_session", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/",
      maxAge,
    });
  }

  return response;
}
