import {
  authorizeRoute,
  copyFor,
  designSystem,
  lintPrivacyCopy,
} from "../../../../apps/_shared/ux.ts";
import type { Role, Session } from "../../../../apps/_shared/ux.ts";

export const FIXTURE_ACCOUNTS = [
  {
    index: 0,
    address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    role: "pool-user" as Role,
  },
  {
    index: 1,
    address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    role: "application-admin" as Role,
  },
  {
    index: 2,
    address: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
    role: "application-auditor" as Role,
  },
  {
    index: 3,
    address: "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
    role: "super-auditor" as Role,
  },
];

export function grantForAddress(address?: string | null) {
  return (
    FIXTURE_ACCOUNTS.find(
      (item) => item.address.toLowerCase() === String(address ?? "").toLowerCase(),
    ) ?? null
  );
}

const POOL_ROUTES = [
  "/overview",
  "/swap",
  "/shield",
  "/send",
  "/withdraw",
  "/history",
  "/emergency-exit",
  "/migrate",
] as const;

const COMPLIANCE_ROUTES = ["/admin", "/audit", "/governance"] as const;

export const HAZE_ROLES: Role[] = [
  "pool-user",
  "application-admin",
  "application-auditor",
  "super-auditor",
];

export type NavItem = {
  path: (typeof POOL_ROUTES)[number] | (typeof COMPLIANCE_ROUTES)[number];
  group: "pool" | "compliance";
  label: string;
  enabled: boolean;
};

const LABELS: Record<string, string> = {
  "/overview": "Overview",
  "/swap": "Swap",
  "/shield": "Shield",
  "/send": "Send",
  "/withdraw": "Withdraw",
  "/history": "History",
  "/emergency-exit": "Emergency exit",
  "/migrate": "Migrate",
  "/admin": "Admin",
  "/audit": "Audit",
  "/governance": "Governance",
};

function kindFor(path: string): "privacy-pool-dex" | "compliance-portal" {
  return (COMPLIANCE_ROUTES as readonly string[]).includes(path)
    ? "compliance-portal"
    : "privacy-pool-dex";
}

export function decidePath(session: Session, path: string) {
  return authorizeRoute(kindFor(path), session, path);
}

export function createHazeSite(session: Session) {
  const nav: NavItem[] = [
    ...POOL_ROUTES.map((path) => ({
      path,
      group: "pool" as const,
      label: LABELS[path],
      enabled: decidePath(session, path).ok,
    })),
    ...COMPLIANCE_ROUTES.map((path) => ({
      path,
      group: "compliance" as const,
      label: LABELS[path],
      enabled: decidePath(session, path).ok,
    })),
  ];

  return {
    origin: "single" as const,
    productName: designSystem.productName,
    language: designSystem.language,
    tokens: designSystem.tokens,
    session,
    vaultLocked: session.role !== "pool-user",
    nav,
    decide(path: string) {
      return decidePath(session, path);
    },
    switchRole(role: Role) {
      return createHazeSite({ role, applicationId: session.applicationId });
    },
    homePath() {
      if (session.role === "application-admin") {
        return "/admin";
      }
      if (session.role === "application-auditor") {
        return "/audit";
      }
      if (session.role === "super-auditor") {
        return "/governance";
      }
      return "/overview";
    },
    warnings(path: string, acknowledged: boolean) {
      const facts =
        path === "/overview" || path === "/history" || path === "/admin" || path === "/audit" || path === "/governance"
          ? []
          : path === "/shield"
          ? ["deposit-amount", "wallet-address", "gas"]
          : path === "/swap"
            ? ["source-token-swap", "deposit-amount", "wallet-address", "gas"]
            : path === "/send"
              ? ["wallet-address", "gas"]
              : path === "/withdraw" || path === "/emergency-exit"
                ? ["withdrawal-amount", "wallet-address", "gas"]
                : path === "/migrate"
                  ? ["withdrawal-amount", "deposit-amount", "wallet-address", "gas", "version-migration"]
                  : [];
      return facts.map((fact) => ({ fact, ...copyFor(fact), acknowledged }));
    },
  };
}

export function failClosedReasons(input: { broadcast: boolean; spendProve: string }) {
  const reasons: string[] = [];
  if (input.broadcast !== true) {
    reasons.push("broadcast:false");
  }
  if (input.spendProve === "KEYS_MISSING") {
    reasons.push("KEYS_MISSING");
  }
  return reasons;
}

export function liveDepositAllowed(input: {
  path: string;
  live: boolean;
  sidecarBroadcast: boolean;
}) {
  return input.live === true && input.sidecarBroadcast === true && input.path === "/shield";
}

export function operatorHatchOpen(input: {
  live: boolean;
  operatorProve: boolean;
  zkeyExists: boolean;
  productionCeremonyApproved?: boolean;
  writeCommittedFuji?: boolean;
}) {
  if (input.productionCeremonyApproved === true) {
    throw Object.assign(new Error("production ceremony stays KEYS_MISSING"), { code: "KEYS_MISSING" });
  }
  if (input.writeCommittedFuji === true) {
    throw Object.assign(new Error("committed fuji-v1.json is immutable"), { code: "SC-09" });
  }
  return input.live === true && input.operatorProve === true && input.zkeyExists === true;
}

export function liveOperatorWithdrawAllowed(input: {
  path: string;
  live: boolean;
  operatorProve: boolean;
  zkeyExists: boolean;
  productionCeremonyApproved?: boolean;
  writeCommittedFuji?: boolean;
}) {
  return input.path === "/withdraw" && operatorHatchOpen(input);
}

export function liveOperatorShieldAllowed(input: {
  path: string;
  live: boolean;
  operatorProve: boolean;
  zkeyExists: boolean;
  productionCeremonyApproved?: boolean;
  writeCommittedFuji?: boolean;
}) {
  return input.path === "/shield" && operatorHatchOpen(input);
}

export const TITLES: Record<string, string> = {
  "/overview": "Overview",
  "/swap": "Public swap and shield",
  "/shield": "Direct shield",
  "/send": "Private send",
  "/withdraw": "Withdraw",
  "/history": "History",
  "/emergency-exit": "Emergency exit",
  "/migrate": "Version migration",
  "/admin": "Application administration",
  "/audit": "Investigation",
  "/governance": "Governance",
};

export const PATH_KIND: Record<string, string> = {
  "/overview": "overview",
  "/swap": "swap-and-shield",
  "/shield": "direct-shield",
  "/send": "private-send",
  "/withdraw": "withdraw",
  "/emergency-exit": "emergency-exit",
  "/migrate": "exit-and-reshield",
};

const SPEND_PATHS = new Set(["/swap", "/send", "/withdraw", "/emergency-exit", "/migrate"]);

export function isSpendPath(path: string) {
  return SPEND_PATHS.has(path);
}

export function sessionFromAddress(address?: string | null, fallback?: Session): Session {
  const grant = address ? grantForAddress(address) : null;
  if (grant) {
    return {
      role: grant.role as Role,
      applicationId: fallback?.applicationId ?? "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    };
  }
  if (fallback?.role) {
    return fallback;
  }
  return { role: null, applicationId: fallback?.applicationId };
}

export function workspaceChoices(address?: string | null) {
  const grant = address ? grantForAddress(address) : null;
  return grant ? [grant.role] : [];
}

export function humanStatus(code: string) {
  switch (code) {
    case "broadcast:false":
      return "Committed Fuji stays closed. Local stack only.";
    case "KEYS_MISSING":
      return "Spend proofs unavailable — withdrawals and private sends stay closed.";
    case "wrong-chain":
      return "Wallet is on the wrong network. Switch to the local Haze chain.";
    case "FORBIDDEN":
      return "This workspace is not authorized for the connected wallet.";
    case "live-sidecar":
      return "Live sidecar — development-digest deposit only. Spend stays closed.";
    case "operator-demo":
      return "Fuji demo · operator keys local";
    default:
      return code;
  }
}

export function statusStrip(input: {
  broadcast: boolean;
  spendProve: string;
  live?: boolean;
  path: string;
  walletStatus?: string;
  operatorProve?: boolean;
  zkeyExists?: boolean;
}) {
  const items = failClosedReasons({
    broadcast: input.broadcast,
    spendProve: input.spendProve,
  }).map((code) => ({ code, message: humanStatus(code) }));
  const hatch = operatorHatchOpen({
    live: input.live === true,
    operatorProve: input.operatorProve === true,
    zkeyExists: input.zkeyExists === true,
  });
  if (input.live && input.path === "/shield" && !hatch) {
    items.push({ code: "live-sidecar", message: humanStatus("live-sidecar") });
  }
  if (hatch) {
    items.push({ code: "operator-demo", message: humanStatus("operator-demo") });
  }
  if (input.walletStatus === "wrong-chain") {
    items.push({ code: "wrong-chain", message: humanStatus("wrong-chain") });
  }
  return items;
}

export function canSignAction(input: {
  path: string;
  walletStatus: string;
  reviewed: boolean;
  role: Role | null;
  spendProve: string;
  live?: boolean;
  operatorProve?: boolean;
  zkeyExists?: boolean;
}) {
  if (input.walletStatus !== "connected") {
    return false;
  }
  if (input.role !== "pool-user") {
    return false;
  }
  if (!input.reviewed) {
    return false;
  }
  if (isSpendPath(input.path) && input.spendProve === "KEYS_MISSING") {
    const hatch = liveOperatorWithdrawAllowed({
      path: input.path,
      live: input.live === true,
      operatorProve: input.operatorProve === true,
      zkeyExists: input.zkeyExists === true,
    });
    if (!hatch) {
      return false;
    }
  }
  if (input.path === "/history") {
    return false;
  }
  return true;
}

export function copyLint(text: string) {
  return lintPrivacyCopy(text);
}

export { HAZE_ROLES as roles };
