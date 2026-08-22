import { cookies } from "next/headers.js";
import { type NextRequest, NextResponse } from "next/server.js";

export const DISCLOSURE_BASE_URL =
  process.env.HAZE_DISCLOSURE_ORIGIN ||
  process.env.NEXT_PUBLIC_HAZE_DISCLOSURE_ORIGIN ||
  "https://haze-fuji-disclosure.onrender.com";

export async function forwardToDisclosure(
  endpoint: string,
  req: NextRequest,
  init?: RequestInit,
): Promise<Response> {
  let sessionToken: string | undefined;
  try {
    const cookieJar = await cookies();
    sessionToken = cookieJar.get("haze_audit_session")?.value;
  } catch {
    // outside Next.js request storage (e.g. unit tests)
  }

  if (!sessionToken && req?.headers) {
    const cookieHeader = req.headers.get("cookie");
    if (cookieHeader) {
      for (const cookie of cookieHeader.split(";")) {
        const [k, v] = cookie.trim().split("=");
        if (k === "haze_audit_session") {
          sessionToken = v;
          break;
        }
      }
    }
  }

  const headers = new Headers(init?.headers || {});
  if (sessionToken && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${sessionToken}`);
  }
  if (!headers.has("Content-Type") && init?.body) {
    headers.set("Content-Type", "application/json");
  }

  const targetUrl = `${DISCLOSURE_BASE_URL.replace(/\/$/, "")}${endpoint}`;
  try {
    return await fetch(targetUrl, {
      ...init,
      headers,
    });
  } catch (error) {
    return new Response(
      JSON.stringify({
        code: "UNAVAILABLE",
        message: error instanceof Error ? error.message : "Service Unavailable",
      }),
      { status: 503, headers: { "Content-Type": "application/json" } },
    );
  }
}
