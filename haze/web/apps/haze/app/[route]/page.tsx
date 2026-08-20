import { cookies } from "next/headers";
import { createHazeSite } from "../../../../packages/ui/src/site.ts";
import { renderHazePage } from "../../../../packages/ui/src/html.ts";
import type { Role } from "../../../../../apps/_shared/ux.ts";

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
  searchParams: Promise<{ role?: string; live?: string }>;
}) {
  const { route } = await params;
  const query = await searchParams;
  if (!ROUTES.has(route)) {
    return <p>not found</p>;
  }
  const jar = await cookies();
  const role = (query.role ?? jar.get("haze-role")?.value ?? "pool-user") as Role;
  const site = createHazeSite({
    role,
    applicationId: "0x0000000000000000000000000000000000000000000000000000000000000a11",
  });
  const html = renderHazePage(site, `/${route}`, { live: query.live === "1" });
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
