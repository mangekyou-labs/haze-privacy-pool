/** Hosted Haze app-shell concerns: planes, nav, network chrome, mount paths. */

export type NavEntry = { path: string; label: string };
export type Plane = "user" | "auditor";

const USER_RAIL = ["/overview", "/shield", "/swap", "/send", "/withdraw", "/history"] as const;
const USER_MORE_RAIL = ["/emergency-exit", "/migrate"] as const;
const MOUNT_PATHS = [
  "/overview",
  "/shield",
  "/swap",
  "/send",
  "/withdraw",
  "/history",
  "/emergency-exit",
  "/migrate",
] as const;

const LABELS: Record<string, string> = {
  "/overview": "Overview",
  "/shield": "Shield",
  "/swap": "Swap",
  "/send": "Send",
  "/withdraw": "Withdraw",
  "/history": "History",
  "/emergency-exit": "Emergency exit",
  "/migrate": "Migrate",
  "/audit": "Cases",
};

export const USER_NAV: NavEntry[] = USER_RAIL.map((path) => ({ path, label: LABELS[path] }));
export const USER_MORE: NavEntry[] = USER_MORE_RAIL.map((path) => ({
  path,
  label: LABELS[path],
}));
export const AUDITOR_NAV: NavEntry[] = [
  { path: "/audit", label: "Cases" },
  { path: "/audit#access-log", label: "Audit log" },
];

export function fujiBrowserMountPaths(): readonly string[] {
  return MOUNT_PATHS;
}

export function networkChrome(input: {
  mode?: "standalone" | "fuji-browser";
  live?: boolean;
  chainId?: number;
}): { network: string; badge?: string } {
  if (input.chainId === 43113) {
    return { network: "Avalanche", badge: "Testnet" };
  }
  return { network: "Local", badge: undefined };
}

export function planeForPath(path: string): Plane {
  if (path === "/audit" || path === "/admin" || path === "/governance") {
    return "auditor";
  }
  return "user";
}

export function userChromeAllowsDisclosure(role: string, path: string): boolean {
  return role === "application-auditor" && path === "/audit";
}
