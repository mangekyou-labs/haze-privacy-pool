/** Shared Haze UX contracts. Not a workspace package; both apps re-export this. */

export type Role =
  | "pool-user"
  | "application-admin"
  | "application-auditor"
  | "super-auditor";

export type Session = {
  role: Role | null;
  applicationId?: string;
};

export type AppKind = "privacy-pool-dex" | "compliance-portal";

export type Decision = { ok: true; code?: undefined } | { ok: false; code: DenyCode };

export type DenyCode = "FORBIDDEN" | "APPLICATION_MISMATCH";

export type Visibility = "public" | "private";

type Resource = { applicationId?: string };

const DENY: Record<DenyCode, Decision> = {
  FORBIDDEN: { ok: false, code: "FORBIDDEN" },
  APPLICATION_MISMATCH: { ok: false, code: "APPLICATION_MISMATCH" },
};

const ALLOW: Decision = { ok: true };

const DEX_ROUTES = [
  "/overview",
  "/swap",
  "/shield",
  "/send",
  "/withdraw",
  "/history",
  "/emergency-exit",
  "/migrate",
] as const;

const PORTAL_ROUTE_ROLES: Record<string, readonly Role[]> = {
  "/admin": ["application-admin"],
  "/audit": ["application-auditor"],
  "/governance": ["super-auditor"],
};

const DEX_APIS: Record<string, readonly Role[]> = {
  "POST /v1/authorizations": ["pool-user"],
};

const PORTAL_APIS: Record<string, readonly Role[]> = {
  "GET /v1/disclosures/query": ["application-auditor"],
  "GET /v1/cases": ["application-admin", "application-auditor"],
  "GET /v1/access-log": ["application-auditor"],
  "POST /v1/auth/challenge": ["application-auditor"],
  "POST /v1/auth/token": ["application-auditor"],
  "POST /v1/cases": ["application-admin"],
  "POST /v1/manifests": ["application-admin"],
  "POST /v1/delegations": ["application-admin"],
  "POST /v1/delegations/revoke": ["application-admin"],
  "GET /v1/reports/application": ["application-admin"],
  "POST /v1/disclosures/export": ["application-admin", "application-auditor"],
  "GET /v1/health/kms": ["application-admin"],
  "GET /v1/health/gatekeeper": ["application-admin"],
  "POST /v1/governance/schedule": ["super-auditor"],
  "POST /v1/governance/execute": ["super-auditor"],
  "GET /v1/governance/status": ["super-auditor"],
  "GET /v1/governance/schedules": ["super-auditor"],
  "GET /v1/governance/ceremony": ["super-auditor"],
  "POST /v1/governance/super-auditor": ["super-auditor"],
};

const CUSTODY_APIS = new Set(["POST /v1/pool/deposit", "POST /v1/pool/transact"]);

const PUBLIC_FACTS = {
  "source-token-swap": {
    label: "Public source-token swap",
    warning: "The quote route, source token, and swap amount are public.",
  },
  "deposit-amount": {
    label: "Public deposit amount",
    warning: "The shielded deposit amount is visible on chain.",
  },
  "withdrawal-amount": {
    label: "Public withdrawal amount",
    warning: "The withdrawal amount and recipient are visible on chain.",
  },
  "application-affiliation": {
    label: "Public application affiliation",
    warning: "Gatekeeper authorization reveals the application.",
  },
  gas: {
    label: "Public gas payment",
    warning: "Wallet gas is a public C-Chain payment.",
  },
  "wallet-address": {
    label: "Public wallet address",
    warning: "The connected wallet address is visible on chain.",
  },
  "version-migration": {
    label: "Public version migration",
    warning: "Exit-and-re-shield links the old and new public withdrawals.",
  },
} as const;

const PRIVATE_FACTS = {
  "shielded-note-amount": {
    label: "Private note amount",
    warning: "Shielded note amounts stay in the local vault and proof.",
  },
} as const;

function channel(hex: string, index: number): number {
  return Number.parseInt(hex.slice(index, index + 2), 16);
}

function srgb(value: number): number {
  const scaled = value / 255;
  return scaled <= 0.03928 ? scaled / 12.92 : ((scaled + 0.055) / 1.055) ** 2.4;
}

function luminance(hex: string): number {
  const value = hex.replace("#", "");
  return 0.2126 * srgb(channel(value, 0)) + 0.7152 * srgb(channel(value, 2)) + 0.0722 * srgb(channel(value, 4));
}

export function contrastRatio(foreground: string, background: string): number {
  const first = luminance(foreground);
  const second = luminance(background);
  const lighter = Math.max(first, second);
  const darker = Math.min(first, second);
  return (lighter + 0.05) / (darker + 0.05);
}

const TOKENS = {
  background: "#16130f",
  surface: "#221e18",
  text: "#f3ece2",
  muted: "#d4c4ae",
  primary: "#1f6b62",
  primaryText: "#f3ece2",
  publicMark: "#c47a3a",
  privateMark: "#8ea3c7",
} as const;

export const designSystem = {
  productName: "Haze",
  language: "alpine-volcanic",
  fontSans: "IBM Plex Sans",
  fontMono: "IBM Plex Mono",
  tokens: TOKENS,
  contrast: {
    body: contrastRatio(TOKENS.text, TOKENS.background),
    large: contrastRatio(TOKENS.muted, TOKENS.background),
    primary: contrastRatio(TOKENS.primaryText, TOKENS.primary),
  },
} as const;

export const threatModel = {
  navIsAuthorization: false,
  logWitnesses: false,
  logPlaintextNotes: false,
  independentDeployment: true,
  csp: {
    defaultSrc: "'self'",
    scriptSrc: "'self'",
    connectSrc: "'self'",
  },
} as const;

const PRIMITIVES = {
  button: {
    role: "button",
    name: "Haze action",
    tabIndex: 0,
    focusRestore: true,
    labelledBy: "haze-action-label",
    ariaLive: "off",
    reducedMotion: true,
  },
  "text-field": {
    role: "textbox",
    name: "Haze field",
    tabIndex: 0,
    focusRestore: true,
    labelledBy: "haze-field-label",
    ariaLive: "off",
    reducedMotion: true,
  },
  alert: {
    role: "alert",
    name: "Haze alert",
    tabIndex: -1,
    focusRestore: true,
    labelledBy: "haze-alert-label",
    ariaLive: "assertive",
    reducedMotion: true,
  },
  status: {
    role: "status",
    name: "Haze status",
    tabIndex: -1,
    focusRestore: true,
    labelledBy: "haze-status-label",
    ariaLive: "polite",
    reducedMotion: true,
  },
} as const;

export function primitive(name: keyof typeof PRIMITIVES) {
  return PRIMITIVES[name];
}

export function layoutFor(width: number) {
  if (width < 720) {
    return { mode: "stack" as const, breakpoint: "mobile" as const };
  }
  if (width < 1080) {
    return { mode: "split" as const, breakpoint: "tablet" as const };
  }
  return { mode: "workspace" as const, breakpoint: "desktop" as const };
}

export function copyFor(fact: string) {
  if (fact in PUBLIC_FACTS) {
    return { visibility: "public" as const, ...PUBLIC_FACTS[fact as keyof typeof PUBLIC_FACTS] };
  }
  if (fact in PRIVATE_FACTS) {
    return { visibility: "private" as const, ...PRIVATE_FACTS[fact as keyof typeof PRIVATE_FACTS] };
  }
  throw new Error(`unknown privacy fact ${fact}`);
}

export function lintPrivacyCopy(text: string): string[] {
  const lower = text.toLowerCase();
  const violations: string[] = [];
  if (/\bprivate\s+swap\b/.test(lower)) {
    violations.push("source-token-swap");
  }
  if (/deposit amount/.test(lower) && /private/.test(lower)) {
    violations.push("deposit-amount");
  }
  if (/withdrawal amount/.test(lower) && /private/.test(lower)) {
    violations.push("withdrawal-amount");
  }
  if (/private\s+application affiliation/.test(lower)) {
    violations.push("application-affiliation");
  }
  if (/\bprivate\s+gas\b/.test(lower)) {
    violations.push("gas");
  }
  if (/private[^.]*migrat|migrat[^.]*private/.test(lower)) {
    violations.push("version-migration");
  }
  if (/across applications|cross-application/.test(lower)) {
    violations.push("cross-application-anonymity");
  }
  return violations;
}

function scoped(session: Session, resource?: Resource): Decision {
  if (resource?.applicationId && resource.applicationId !== session.applicationId) {
    return DENY.APPLICATION_MISMATCH;
  }
  return ALLOW;
}

export function authorizeRoute(
  app: AppKind,
  session: Session,
  path: string,
  resource?: Resource,
): Decision {
  if (app === "privacy-pool-dex") {
    if (!(DEX_ROUTES as readonly string[]).includes(path)) {
      return DENY.FORBIDDEN;
    }
    if (session.role !== "pool-user") {
      return DENY.FORBIDDEN;
    }
    return ALLOW;
  }
  const allowed = PORTAL_ROUTE_ROLES[path];
  if (!allowed) {
    return DENY.FORBIDDEN;
  }
  if (!session.role || !allowed.includes(session.role)) {
    return DENY.FORBIDDEN;
  }
  if (path !== "/governance") {
    const scope = scoped(session, resource);
    if (!scope.ok) {
      return scope;
    }
  }
  return ALLOW;
}

export function authorizeApi(
  app: AppKind,
  session: Session,
  method: string,
  path: string,
  resource?: Resource,
): Decision {
  const key = `${method} ${path}`;
  if (CUSTODY_APIS.has(key)) {
    return DENY.FORBIDDEN;
  }
  const catalog = app === "privacy-pool-dex" ? DEX_APIS : PORTAL_APIS;
  const allowed = catalog[key];
  if (!allowed) {
    return DENY.FORBIDDEN;
  }
  if (!session.role || !allowed.includes(session.role)) {
    return DENY.FORBIDDEN;
  }
  if (app === "compliance-portal") {
    const scope = scoped(session, resource);
    if (!scope.ok) {
      return scope;
    }
  }
  return ALLOW;
}

export function navFor(app: AppKind, session: Session) {
  if (app === "privacy-pool-dex") {
    if (session.role !== "pool-user") {
      return [];
    }
    return DEX_ROUTES.map((path) => ({ path, visible: true }));
  }
  return Object.entries(PORTAL_ROUTE_ROLES)
    .filter(([, roles]) => session.role !== null && roles.includes(session.role))
    .map(([path]) => ({ path, visible: true }));
}
