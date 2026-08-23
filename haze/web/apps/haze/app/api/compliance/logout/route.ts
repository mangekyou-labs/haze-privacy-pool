import { type NextRequest, NextResponse } from "next/server.js";
import { forwardToDisclosure } from "../_lib.ts";

async function handleLogout(req: NextRequest) {
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

export async function POST(req: NextRequest) {
  return handleLogout(req);
}

export async function DELETE(req: NextRequest) {
  return handleLogout(req);
}
