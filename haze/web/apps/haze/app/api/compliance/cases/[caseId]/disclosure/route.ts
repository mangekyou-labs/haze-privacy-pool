import { type NextRequest } from "next/server.js";
import { forwardToDisclosure, sanitizedJsonResponse } from "../../../_lib.ts";

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

  return sanitizedJsonResponse(resp);
}
