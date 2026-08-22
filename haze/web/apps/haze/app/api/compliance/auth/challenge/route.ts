import { type NextRequest, NextResponse } from "next/server.js";
import { forwardToDisclosure } from "../../_lib.ts";

export async function POST(req: NextRequest) {
  const body = await req.text();
  const resp = await forwardToDisclosure("/v1/auth/challenge", req, {
    method: "POST",
    body,
  });

  const data = await resp.text();
  return new NextResponse(data, {
    status: resp.status,
    headers: {
      "Content-Type": "application/json",
    },
  });
}
