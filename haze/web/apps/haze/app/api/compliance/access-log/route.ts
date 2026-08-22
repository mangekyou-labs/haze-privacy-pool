import { type NextRequest, NextResponse } from "next/server.js";
import { forwardToDisclosure } from "../_lib.ts";

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const queryString = searchParams.toString();
  const endpoint = queryString ? `/v1/access-log?${queryString}` : "/v1/access-log";

  const resp = await forwardToDisclosure(endpoint, req, {
    method: "GET",
  });

  const data = await resp.text();
  return new NextResponse(data, {
    status: resp.status,
    headers: { "Content-Type": "application/json" },
  });
}
