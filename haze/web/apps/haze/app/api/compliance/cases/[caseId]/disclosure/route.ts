import { type NextRequest, NextResponse } from "next/server.js";
import { forwardToDisclosure } from "../../../_lib.ts";

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ caseId: string }> },
) {
  const { caseId } = await params;
  const body = await req.text();
  const resp = await forwardToDisclosure(
    `/v1/cases/${encodeURIComponent(caseId)}/disclosure`,
    req,
    {
      method: "POST",
      body: body || undefined,
    },
  );

  const data = await resp.text();
  return new NextResponse(data, {
    status: resp.status,
    headers: { "Content-Type": "application/json" },
  });
}
