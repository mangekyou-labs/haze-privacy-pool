/** Library-first auditor investigation workspace. Hosted Next.js remains T6.2. */

import { authorizeApi, authorizeRoute, designSystem, layoutFor, navFor, primitive } from "../../_shared/ux.ts";
import type { Session } from "../../_shared/ux.ts";
import { SdkError } from "../../../sdk/typescript/src/errors.ts";

const APP = "compliance-portal" as const;

export type AuditCase = {
  caseId: string;
  title: string;
  applicationId: string;
  fields: string[];
  expiresAt: number;
  revoked: boolean;
};

export type AuditGrant = {
  fields: string[];
  expiresAt: number;
  revoked: boolean;
};

export type AccessEntry = {
  action: string;
  caseId?: string;
  allowed: boolean;
};

export type AuditStatus = {
  applicationId: string;
  auditor: string;
  boundWallet?: string;
  expired: boolean;
  revoked: boolean;
  cases: AuditCase[];
};

export type AuditScreen = {
  path: string;
  title: string;
  role: Session["role"];
  status: AuditStatus;
  nav: { path: string; visible: boolean }[];
  layout: ReturnType<typeof layoutFor>;
};

export type AuditWorkspaceConfig = {
  applicationId: string;
  auditor: string;
  clock?: () => number;
  grantOverride?: Partial<AuditGrant>;
  auditAuth: {
    challenge(input: { address: string }): Promise<{ nonce: string; address: string }>;
    token(input: {
      address: string;
      signature: string;
      nonce: string;
    }): Promise<{ token: string; address: string }>;
    listAssigned(): Promise<AuditCase[]>;
  };
  disclosure: {
    query(input: {
      caseId: string;
      fields: string[];
      applicationId: string;
      grant: AuditGrant;
    }): Promise<{ rows: Record<string, unknown>[] }>;
    export(input: {
      caseId: string;
      fields: string[];
      applicationId: string;
      grant: AuditGrant;
    }): Promise<{ caseId: string; fields: string[]; applicationId: string; rows: unknown[] }>;
    accessLog(): Promise<AccessEntry[]>;
  };
};

function denyToError(code: string): never {
  if (code === "APPLICATION_MISMATCH") {
    throw new SdkError("APPLICATION_MISMATCH");
  }
  throw new SdkError("UNAUTHORIZED");
}

function assertAuditor(session: Session, method: string, path: string, applicationId: string): void {
  const decision = authorizeApi(APP, session, method, path, { applicationId });
  if (!decision.ok) {
    denyToError(decision.code);
  }
}

export function createAuditWorkspace(config: AuditWorkspaceConfig) {
  let session: Session = { role: null };
  let path = "/audit";
  let boundWallet: string | undefined;
  let siweToken: string | undefined;
  const denied: AccessEntry[] = [];
  const clock = config.clock ?? (() => 1_800_000_000);

  function grantFrom(assigned: AuditCase[]): AuditGrant {
    const first = assigned[0];
    return {
      fields: config.grantOverride?.fields ?? first?.fields ?? [],
      expiresAt: config.grantOverride?.expiresAt ?? first?.expiresAt ?? 0,
      revoked: config.grantOverride?.revoked ?? first?.revoked ?? false,
    };
  }

  function status(assigned: AuditCase[] = []): AuditStatus {
    const grant = grantFrom(assigned);
    return {
      applicationId: config.applicationId,
      auditor: config.auditor,
      boundWallet,
      expired: grant.expiresAt <= clock(),
      revoked: grant.revoked,
      cases: assigned,
    };
  }

  function screen(width = 1080, assigned: AuditCase[] = []): AuditScreen {
    return {
      path,
      title: "Investigation",
      role: session.role,
      status: status(assigned),
      nav: navFor(APP, session),
      layout: layoutFor(width),
    };
  }

  async function assignedCases(): Promise<AuditCase[]> {
    assertAuditor(session, "GET", "/v1/cases", config.applicationId);
    return (await config.auditAuth.listAssigned()).filter(
      (item) => item.applicationId === config.applicationId,
    );
  }

  function activeGrant(assigned: AuditCase[]): AuditGrant {
    const grant = grantFrom(assigned);
    if (grant.revoked) {
      throw new SdkError("UNAUTHORIZED");
    }
    if (grant.expiresAt <= clock()) {
      throw new SdkError("AUTHORIZATION_EXPIRED");
    }
    return grant;
  }

  return {
    session() {
      return session;
    },
    signIn(next: Session) {
      const decision = authorizeRoute(APP, next, "/audit", { applicationId: config.applicationId });
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
    status() {
      return status();
    },
    screen(width = 1080) {
      return screen(width);
    },
    async startSiwe(address: string) {
      assertAuditor(
        { role: "application-auditor", applicationId: config.applicationId },
        "POST",
        "/v1/auth/challenge",
        config.applicationId,
      );
      return config.auditAuth.challenge({ address });
    },
    async completeSiwe(input: { address: string; signature: string; nonce: string }) {
      assertAuditor(
        { role: "application-auditor", applicationId: config.applicationId },
        "POST",
        "/v1/auth/token",
        config.applicationId,
      );
      const bound = await config.auditAuth.token(input);
      boundWallet = bound.address;
      siweToken = bound.token;
      return bound;
    },
    token() {
      return siweToken;
    },
    assignedCases,
    async search(input: { caseId: string; fields: string[] }) {
      assertAuditor(session, "GET", "/v1/disclosures/query", config.applicationId);
      const assigned = await assignedCases();
      if (!assigned.some((item) => item.caseId === input.caseId)) {
        denied.push({ action: "query", caseId: input.caseId, allowed: false });
        throw new SdkError("UNAUTHORIZED");
      }
      try {
        return await config.disclosure.query({
          ...input,
          applicationId: config.applicationId,
          grant: activeGrant(assigned),
        });
      } catch (error) {
        denied.push({ action: "query", caseId: input.caseId, allowed: false });
        throw error;
      }
    },
    async exportDisclosure(input: { caseId: string; fields: string[] }) {
      assertAuditor(session, "POST", "/v1/disclosures/export", config.applicationId);
      const assigned = await assignedCases();
      if (!assigned.some((item) => item.caseId === input.caseId)) {
        denied.push({ action: "export", caseId: input.caseId, allowed: false });
        throw new SdkError("UNAUTHORIZED");
      }
      return config.disclosure.export({
        ...input,
        applicationId: config.applicationId,
        grant: activeGrant(assigned),
      });
    },
    async accessHistory() {
      assertAuditor(session, "GET", "/v1/access-log", config.applicationId);
      return [...(await config.disclosure.accessLog()), ...denied];
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

export function renderAuditHtml(screen: AuditScreen): string {
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
      ${escapeHtml(screen.status.applicationId)} · ${screen.status.expired ? "expired" : "active"}
      · ${screen.status.revoked ? "revoked" : "granted"}
    </p>
    <section>
      <h2>Assigned cases</h2>
      <ul>${screen.status.cases.map((item) => `<li>${escapeHtml(item.caseId)}</li>`).join("")}</ul>
    </section>
    <button type="button" role="${button.role}" tabindex="${button.tabIndex}" aria-labelledby="${button.labelledBy}">
      Export scoped records
    </button>
  </main>
</body>
</html>`;
}
