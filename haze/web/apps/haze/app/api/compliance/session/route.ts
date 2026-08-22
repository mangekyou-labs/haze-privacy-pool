import { type NextRequest, NextResponse } from "next/server.js";
import { forwardToDisclosure } from "../_lib.ts";

export async function GET(req: NextRequest) {
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
