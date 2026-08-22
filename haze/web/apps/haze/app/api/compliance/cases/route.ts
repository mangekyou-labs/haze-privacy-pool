import { type NextRequest, NextResponse } from "next/server.js";
import { forwardToDisclosure } from "../_lib.ts";

export async function GET(req: NextRequest) {
  const resp = await forwardToDisclosure("/v1/cases", req, {
    method: "GET",
  });

  const data = await resp.text();
  return new NextResponse(data, {
    status: resp.status,
    headers: { "Content-Type": "application/json" },
  });
}
