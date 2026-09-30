import { NextResponse } from "next/server";
import { getComplianceStore } from "../../../../../lib/compliance-store.ts";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const address = body.address;
    if (!address || typeof address !== "string") {
      return NextResponse.json({ error: "ADDRESS_REQUIRED" }, { status: 400 });
    }
    const store = getComplianceStore();
    const requestHost = request.headers.get("host")?.split(":", 1)[0];
    const challenge = await store.createSiweChallenge(address, requestHost);
    return NextResponse.json(challenge);
  } catch (err: any) {
    return NextResponse.json({ error: err?.message || "CHALLENGE_FAILED" }, { status: 500 });
  }
}
