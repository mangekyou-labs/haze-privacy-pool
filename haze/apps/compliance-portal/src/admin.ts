/** Library-first application administration workspace. Hosted Next.js remains T6.2. */

import { authorizeApi, authorizeRoute, designSystem, layoutFor, navFor, primitive } from "../../_shared/ux.ts";
import type { Session } from "../../_shared/ux.ts";
import { SdkError } from "../../../sdk/typescript/src/errors.ts";
import { hashManifest, parseManifest } from "../../../sdk/typescript/src/manifest.ts";
import type { ApplicationManifest } from "../../../sdk/typescript/src/manifest.ts";

const APP = "compliance-portal" as const;

export type AdminGrant = {
  grantId: string;
  auditor: string;
  expiresAt: number;
  capabilities: string[];
  applicationId: string;
  revoked: boolean;
};

export type AdminCase = {
  caseId: string;
  title: string;
  reason: string;
  applicationId: string;
};

export type AdminReport = {
  applicationId: string;
  txHash: string;
  kind: string;
};

export type AdminStatus = {
  applicationId: string;
  manifestHash?: string;
  organizationName?: string;
  kmsHealth?: string;
  gatekeeperSigner?: string;
  grants: AdminGrant[];
  cases: AdminCase[];
};

export type AdminScreen = {
  path: string;
  title: string;
  role: Session["role"];
  status: AdminStatus;
  nav: { path: string; visible: boolean }[];
  layout: ReturnType<typeof layoutFor>;
};

export type AdminWorkspaceConfig = {
  applicationId: string;
  auditAuth: {
    createCase(input: { title: string; reason: string }): Promise<AdminCase>;
    listCases(): Promise<AdminCase[]>;
    delegate(input: {
      auditor: string;
      expiresAt: number;
      capabilities: string[];
    }): Promise<AdminGrant>;
    revoke(input: { grantId: string }): Promise<AdminGrant>;
  };
  disclosure: {
    export(input: {
      caseId: string;
      fields: string[];
      applicationId: string;
    }): Promise<{ caseId: string; fields: string[]; applicationId: string; rows: unknown[] }>;
  };
  indexer: {
    queryApplication(input: { applicationId: string }): Promise<AdminReport[]>;
  };
  health: {
    kms(): Promise<{ status: string; refs: string[] }>;
    gatekeeper(): Promise<{ status: string; signer: string }>;
  };
};

function denyToError(code: string): never {
  if (code === "APPLICATION_MISMATCH") {
    throw new SdkError("APPLICATION_MISMATCH");
  }
  throw new SdkError("UNAUTHORIZED");
}

function assertAdmin(session: Session, method: string, path: string, applicationId: string): void {
  const decision = authorizeApi(APP, session, method, path, { applicationId });
  if (!decision.ok) {
    denyToError(decision.code);
  }
}

export function createAdminWorkspace(config: AdminWorkspaceConfig) {
  let session: Session = { role: null };
  let path = "/admin";
  let manifest: ApplicationManifest | undefined;
  let manifestHash: string | undefined;
  let kmsHealth: string | undefined;
  let gatekeeperSigner: string | undefined;
  const grants: AdminGrant[] = [];
  const cases: AdminCase[] = [];

  function status(): AdminStatus {
    return {
      applicationId: config.applicationId,
      manifestHash,
      organizationName: manifest?.organizationName,
      kmsHealth,
      gatekeeperSigner,
      grants: [...grants],
      cases: [...cases],
    };
  }

  function screen(width = 1080): AdminScreen {
    return {
      path,
      title: "Application administration",
      role: session.role,
      status: status(),
      nav: navFor(APP, session),
      layout: layoutFor(width),
    };
  }

  return {
    session() {
      return session;
    },
    signIn(next: Session) {
      const decision = authorizeRoute(APP, next, "/admin", { applicationId: config.applicationId });
      if (decision.ok) {
        session = next;
      }
      return decision;
    },
    navigate(next: string) {
      const decision = authorizeRoute(APP, session, next, { applicationId: config.applicationId });
      if (decision.ok) {
        path = next;
      }
      return decision;
    },
    status,
    screen,
    async registerManifest(raw: Record<string, unknown>, expectedHash: string) {
      assertAdmin(session, "POST", "/v1/manifests", config.applicationId);
      const parsed = parseManifest(raw, expectedHash);
      if (parsed.applicationId !== config.applicationId) {
        throw new SdkError("APPLICATION_MISMATCH");
      }
      if (hashManifest(raw).toLowerCase() !== expectedHash.toLowerCase()) {
        throw new SdkError("ENCODING_INVALID");
      }
      manifest = parsed;
      manifestHash = expectedHash;
      return { applicationId: parsed.applicationId, hash: expectedHash };
    },
    async registerKms(refs: string[]) {
      assertAdmin(session, "GET", "/v1/health/kms", config.applicationId);
      const health = await config.health.kms();
      if (refs.some((ref) => !health.refs.includes(ref))) {
        throw new SdkError("UNAVAILABLE");
      }
      kmsHealth = health.status;
      return health;
    },
    async gatekeeperSigner() {
      assertAdmin(session, "GET", "/v1/health/gatekeeper", config.applicationId);
      const health = await config.health.gatekeeper();
      gatekeeperSigner = health.signer;
      return health;
    },
    async delegateAuditor(input: { auditor: string; expiresAt: number; capabilities: string[] }) {
      assertAdmin(session, "POST", "/v1/delegations", config.applicationId);
      const grant = await config.auditAuth.delegate(input);
      grants.push(grant);
      return grant;
    },
    async revokeAccess(input: { grantId: string }) {
      assertAdmin(session, "POST", "/v1/delegations/revoke", config.applicationId);
      const grant = await config.auditAuth.revoke(input);
      const index = grants.findIndex((item) => item.grantId === grant.grantId);
      if (index >= 0) {
        grants[index] = grant;
      }
      return grant;
    },
    async createCase(input: { title: string; reason: string }) {
      assertAdmin(session, "POST", "/v1/cases", config.applicationId);
      const opened = await config.auditAuth.createCase(input);
      cases.push(opened);
      return opened;
    },
    async listCases() {
      assertAdmin(session, "GET", "/v1/cases", config.applicationId);
      const listed = await config.auditAuth.listCases();
      return listed;
    },
    async transactionReports() {
      assertAdmin(session, "GET", "/v1/reports/application", config.applicationId);
      return config.indexer.queryApplication({ applicationId: config.applicationId });
    },
    async exportDisclosure(input: { caseId: string; fields: string[] }) {
      assertAdmin(session, "POST", "/v1/disclosures/export", config.applicationId);
      return config.disclosure.export({
        ...input,
        applicationId: config.applicationId,
      });
    },
  };
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

export function renderAdminHtml(screen: AdminScreen): string {
  const tokens = designSystem.tokens;
  const button = primitive("button");
  const status = primitive("status");
  const navMarkup = screen.nav
    .filter((item) => item.visible)
    .map((item) => `<a href="${escapeHtml(item.path)}">${escapeHtml(item.path)}</a>`)
    .join("");
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Haze Compliance Portal — ${escapeHtml(screen.title)}</title>
  <style>
    :root {
      --haze-bg: ${tokens.background};
      --haze-surface: ${tokens.surface};
      --haze-text: ${tokens.text};
      --haze-muted: ${tokens.muted};
      --haze-primary: ${tokens.primary};
    }
    body {
      margin: 0;
      font-family: "${designSystem.fontSans}", sans-serif;
      background: var(--haze-bg);
      color: var(--haze-text);
    }
    .skip { position: absolute; left: -999px; }
    .skip:focus { left: 8px; top: 8px; }
  </style>
</head>
<body data-layout="${screen.layout.mode}">
  <a class="skip" href="#haze-main">Skip to content</a>
  <nav aria-label="Haze Compliance Portal">${navMarkup}</nav>
  <main id="haze-main">
    <h1 id="haze-action-label">${escapeHtml(screen.title)}</h1>
    <p role="${status.role}" aria-live="${status.ariaLive}">
      ${escapeHtml(screen.status.applicationId)} · ${escapeHtml(screen.status.kmsHealth ?? "unregistered")}
    </p>
    <section>
      <h2>Manifest</h2>
      <p>${escapeHtml(screen.status.manifestHash ?? "none")}</p>
    </section>
    <section>
      <h2>Gatekeeper signer</h2>
      <p>${escapeHtml(screen.status.gatekeeperSigner ?? "unknown")}</p>
    </section>
    <section>
      <h2>Cases</h2>
      <ul>${screen.status.cases.map((item) => `<li>${escapeHtml(item.caseId)}</li>`).join("")}</ul>
    </section>
    <button type="button" role="${button.role}" tabindex="${button.tabIndex}" aria-labelledby="${button.labelledBy}">
      Register manifest
    </button>
  </main>
</body>
</html>`;
}
