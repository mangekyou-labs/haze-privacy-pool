import { cookies } from "next/headers.js";
import { type NextRequest, NextResponse } from "next/server.js";
import { forwardToDisclosure } from "../_lib.ts";

function tokenFromCookieHeader(req: NextRequest): string | undefined {
  const cookieHeader = req?.headers?.get("cookie");
  if (!cookieHeader) return undefined;
  for (const cookie of cookieHeader.split(";")) {
    const [k, v] = cookie.trim().split("=");
    if (k === "haze_audit_session" && v) return v;
  }
  return undefined;
}

export async function GET(req: NextRequest) {
  let sessionToken: string | undefined;
  try {
    const cookieJar = await cookies();
    sessionToken = cookieJar.get("haze_audit_session")?.value;
  } catch {
    // outside Next.js request storage (e.g. unit tests)
  }
  if (!sessionToken) sessionToken = tokenFromCookieHeader(req);
  if (!sessionToken) {
    return NextResponse.json({ code: "UNAUTHENTICATED" }, { status: 401 });
  }

  const resp = await forwardToDisclosure("/v1/session", req, {
    method: "GET",
  });

  const data = await resp.text();
  return new NextResponse(data, {
    status: resp.status,
    headers: { "Content-Type": "application/json" },
  });
}

export async function DELETE(req: NextRequest) {
  const resp = await forwardToDisclosure("/v1/session", req, {
    method: "DELETE",
  });

  const response = new NextResponse(await resp.text(), {
    status: resp.status,
    headers: { "Content-Type": "application/json" },
  });

  response.cookies.set("haze_audit_session", "", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
    maxAge: 0,
  });

  return response;
}
