import { notFound } from "next/navigation";
import { cookies } from "next/headers";
import { createHazeSite } from "../../../../packages/ui/src/site.ts";
import { renderHazeFragment } from "../../../../packages/ui/src/html.ts";
import { LIVE_APP_ID } from "../../../../../sdk/typescript/src/compliance-service.ts";
import { getComplianceStore } from "../../lib/compliance-store.ts";
import type { Role } from "../../../../../apps/_shared/ux.ts";
import { FujiBrowserClient } from "./fuji-browser-client";

const ROUTES = new Set([
  "swap",
  "shield",
  "send",
  "withdraw",
  "history",
  "emergency-exit",
  "migrate",
  "admin",
  "audit",
  "governance",
]);

export default async function RoutePage({
  params,
  searchParams,
}: {
  params: Promise<{ route: string }>;
  searchParams: Promise<{ live?: string; caseId?: string; reviewed?: string }>;
}) {
  const { route } = await params;
  const query = await searchParams;
  if (!ROUTES.has(route)) {
    notFound();
  }

  const jar = await cookies();
  const complianceToken = jar.get("haze_compliance_session")?.value;
  const store = getComplianceStore();
  const session = await store.getSession(complianceToken);

  let role: Role = "pool-user";
  let boundWallet: string | undefined = undefined;
  let auditOptions: any = undefined;

  if (route === "audit" && session && session.role === "application-auditor") {
    role = "application-auditor";
    boundWallet = session.address;
    const cases = await store.listAssignedCases(session.address, session.applicationId);
    const accessLog = await store.getAccessLog();
    auditOptions = {
      boundWallet,
      cases,
      selectedCaseId: query.caseId ?? cases[0]?.caseId,
      access: accessLog.entries,
      chainVerified: accessLog.verified,
      headHash: accessLog.headHash,
    };
  }

  // Fail-closed: /admin and /governance cannot be authorized via ?role or haze-role in production.
  const site = createHazeSite({
    role,
    applicationId: LIVE_APP_ID,
  });

  const html = renderHazeFragment(site, `/${route}`, {
    live: query.live === "1",
    reviewed: query.reviewed === "1",
    audit: auditOptions,
  });

  return (
    <>
      <div dangerouslySetInnerHTML={{ __html: html }} />
      <FujiBrowserClient route={route} />
    </>
  );
}
