/** Library-first Haze governance workspace. Hosted Next.js remains T6.2. */

import { authorizeApi, authorizeRoute, designSystem, layoutFor, navFor, primitive } from "../../_shared/ux.ts";
import type { Session } from "../../_shared/ux.ts";
import { SdkError } from "../../../sdk/typescript/src/errors.ts";

const APP = "compliance-portal" as const;

export type GovernanceKind =
  | "policy-root"
  | "application-register"
  | "application-suspend"
  | "version-activate";

export type GovernancePreview = {
  id: string;
  kind: GovernanceKind;
  target: string;
  timelock: string;
  calldata: string;
  eta: number;
  delay: number;
};

export type GovernanceSchedule = GovernancePreview & { executed: boolean };

export type ProtocolSnapshot = {
  suspended: string[];
  emergency: { paused: boolean; exitOpen: boolean };
  versions: { pool: string; artifactHash: string; provenance: string };
  ceremony: { transcriptHash: string; production: boolean };
};

export type GovernanceScreen = {
  path: string;
  title: string;
  role: Session["role"];
  preview?: GovernancePreview;
  snapshot?: ProtocolSnapshot;
  nav: { path: string; visible: boolean }[];
  layout: ReturnType<typeof layoutFor>;
};

export type GovernanceWorkspaceConfig = {
  applicationId: string;
  clock?: () => number;
  registry: {
    address: string;
    timelock: string;
    delay: number;
    schedule(tx: GovernancePreview): Promise<GovernanceSchedule>;
    execute(id: string): Promise<GovernanceSchedule>;
    list(): Promise<GovernanceSchedule[]>;
  };
  status: {
    snapshot(): Promise<ProtocolSnapshot>;
  };
};

function denyToError(code: string): never {
  if (code === "APPLICATION_MISMATCH") {
    throw new SdkError("APPLICATION_MISMATCH");
  }
  throw new SdkError("UNAUTHORIZED");
}

function assertGov(session: Session, method: string, path: string, applicationId: string): void {
  const decision = authorizeApi(APP, session, method, path, { applicationId });
  if (!decision.ok) {
    denyToError(decision.code);
  }
}

export function createGovernanceWorkspace(config: GovernanceWorkspaceConfig) {
  let session: Session = { role: null };
  let path = "/governance";
  let preview: GovernancePreview | undefined;
  let snapshot: ProtocolSnapshot | undefined;
  let nextId = 1;
  const clock = config.clock ?? (() => 0);

  return {
    session() {
      return session;
    },
    signIn(next: Session) {
      const decision = authorizeRoute(APP, next, "/governance", {
        applicationId: config.applicationId,
      });
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
    screen(width = 1080): GovernanceScreen {
      return {
        path,
        title: "Haze governance",
        role: session.role,
        preview,
        snapshot,
        nav: navFor(APP, session),
        layout: layoutFor(width),
      };
    },
    async previewSchedule(input: {
      kind: GovernanceKind;
      target: string;
      calldata: string;
      eta: number;
    }): Promise<GovernancePreview> {
      assertGov(session, "POST", "/v1/governance/schedule", config.applicationId);
      if (input.target.toLowerCase() !== config.registry.address.toLowerCase()) {
        throw new SdkError("UNAUTHORIZED");
      }
      preview = {
        id: `gov-${nextId++}`,
        kind: input.kind,
        target: input.target,
        timelock: config.registry.timelock,
        calldata: input.calldata,
        eta: input.eta,
        delay: config.registry.delay,
      };
      return preview;
    },
    async schedule() {
      assertGov(session, "POST", "/v1/governance/schedule", config.applicationId);
      if (!preview) {
        throw new SdkError("TIMELOCK");
      }
      return config.registry.schedule(preview);
    },
    async execute(input: { id: string }) {
      assertGov(session, "POST", "/v1/governance/execute", config.applicationId);
      const listed = await config.registry.list();
      const item = listed.find((entry) => entry.id === input.id);
      if (!item || clock() < item.eta) {
        throw new SdkError("TIMELOCK");
      }
      return config.registry.execute(input.id);
    },
    async protocolStatus() {
      assertGov(session, "GET", "/v1/governance/status", config.applicationId);
      snapshot = await config.status.snapshot();
      return snapshot;
    },
    async grantSuperAuditor(input: { wallet: string }) {
      assertGov(session, "POST", "/v1/governance/super-auditor", config.applicationId);
      return { wallet: input.wallet, role: "super-auditor" as const, custody: false };
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

export function renderGovernanceHtml(screen: GovernanceScreen): string {
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
      ${escapeHtml(screen.preview?.target ?? "no preview")} · ${escapeHtml(screen.preview?.timelock ?? "no timelock")}
    </p>
    <section>
      <h2>Ceremony</h2>
      <p>${escapeHtml(screen.snapshot?.ceremony.transcriptHash ?? "none")}</p>
    </section>
    <button type="button" role="${button.role}" tabindex="${button.tabIndex}" aria-labelledby="${button.labelledBy}">
      Preview schedule
    </button>
  </main>
</body>
</html>`;
}
