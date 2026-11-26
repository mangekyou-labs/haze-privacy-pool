import { cookies } from "next/headers";
import { createHazeSite, grantForAddress } from "../../../../packages/ui/src/site.ts";
import { renderHazeFragment } from "../../../../packages/ui/src/html.ts";
import type { Role } from "../../../../../apps/_shared/ux.ts";
import { FujiBrowserClient } from "./fuji-browser-client.tsx";
import { AuditBrowserClient } from "./audit-browser-client.tsx";

const ROUTES = new Set([
  "overview",
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
  searchParams: Promise<{ role?: string }>;
}) {
  const { route } = await params;
  const query = await searchParams;
  if (!ROUTES.has(route)) {
    return <p>not found</p>;
  }
  const jar = await cookies();
  const address = jar.get("haze-address")?.value;
  const grant = address ? grantForAddress(address) : null;
  const role = (query.role ?? jar.get("haze-role")?.value ?? grant?.role ?? "pool-user") as Role;
  const site = createHazeSite({
    role,
    applicationId: "0x0000000000000000000000000000000000000000000000000000000000000a11",
  });
  const html = renderHazeFragment(site, `/${route}`, {
    mode: "fuji-browser",
    address,
  });
  return <>
    <div dangerouslySetInnerHTML={{ __html: html }} />
    {route === "audit" ? <AuditBrowserClient /> : <FujiBrowserClient route={route} />}
  </>;
}
