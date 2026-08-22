import {
  TITLES,
  canSignAction,
  humanStatus,
  isSpendPath,
  liveOperatorWithdrawAllowed,
  PATH_KIND,
  statusStrip,
  workspaceChoices,
} from "./site.ts";
import type { createHazeSite } from "./site.ts";

type Site = ReturnType<typeof createHazeSite>;

export type RenderOptions = {
  mode?: "standalone" | "fuji-browser";
  live?: boolean;
  operatorProve?: boolean;
  zkeyExists?: boolean;
  address?: string | null;
  walletStatus?: "disconnected" | "connecting" | "connected" | "rejected" | "wrong-chain";
  reviewed?: boolean;
  phase?: string;
  notes?: number;
  lastError?: string;
  quote?: string;
  publicUsdc?: string;
  privateUsdc?: string;
  poolUsdc?: string;
  admin?: {
    manifestHash?: string;
    kmsHealth?: string;
    gatekeeperSigner?: string;
    cases?: { caseId: string; title: string }[];
    grants?: { grantId: string; auditor: string; revoked: boolean }[];
  };
  audit?: {
    boundWallet?: string;
    cases?: { caseId: string; title: string }[];
    access?: { action: string; allowed: boolean }[];
    rows?: { field: string; value: string }[];
  };
  governance?: {
    previewTarget?: string;
    timelock?: string;
    ceremonyProduction?: boolean;
    emergency?: string;
  };
};

function escapeHtml(value: string) {
  return value.replace(/[&<>"']/g, (char) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char] ?? char,
  );
}

function truncateAddress(address: string) {
  if (address.length < 12) {
    return address;
  }
  return `${address.slice(0, 6)}…${address.slice(-4)}`;
}

function reviewPanel(site: Site, path: string, reviewed: boolean) {
  const warnings = site.warnings(path, reviewed);
  if (warnings.length === 0) {
    return "";
  }
  const items = warnings
    .map(
      (item) =>
        `<li data-visibility="${item.visibility}"><strong>${escapeHtml(item.label)}</strong> ${escapeHtml(item.warning)}</li>`,
    )
    .join("");
  return `<section class="haze-review" data-review="public-facts" data-reviewed="${reviewed ? "true" : "false"}">
    <h2>Review public facts</h2>
    <ul>${items}</ul>
    <button class="haze-button haze-button-secondary" type="button" data-action="preview" data-kind="${escapeHtml(PATH_KIND[path] ?? "")}" ${reviewed ? "disabled" : ""}>I understand — continue</button>
  </section>`;
}

function hatchAllowed(path: string, options: RenderOptions) {
  return liveOperatorWithdrawAllowed({
    path,
    live: options.live === true,
    operatorProve: options.operatorProve === true,
    zkeyExists: options.zkeyExists === true,
  });
}

function poolForm(path: string, options: RenderOptions, canSign: boolean, disabledReason: string) {
  const kind = PATH_KIND[path] ?? "";
  if (path === "/history") {
    const empty = (options.notes ?? 0) === 0;
    return `<section class="haze-form" data-workspace="history">
      ${empty ? `<p class="haze-empty">No notes in the local vault yet. Shield USDC to create one.</p>` : `<p class="haze-mono">${options.notes} note(s) in the local vault.</p>`}
      <div class="haze-actions">
        <button class="haze-button haze-button-secondary" type="button" data-action="wipe">Wipe local vault</button>
        <button class="haze-button" type="button" data-action="recover">Recover from wallet message</button>
      </div>
    </section>`;
  }

  const amountRow = (name: string, value: string) =>
    `<div class="haze-amount-row">
      <label class="haze-field haze-amount-field">Amount
        <input class="haze-amount haze-figure" name="${name}" value="${value}" inputmode="decimal" autocomplete="off">
      </label>
      <span class="haze-token">USDC</span>
    </div>`;
  const fields =
    path === "/swap"
      ? `<input type="hidden" name="tokenIn" value="USDC-source">
         ${amountRow("amountIn", "1")}
         <p class="haze-muted">Public in → private USDC.</p>
         ${options.quote ? `<p class="haze-mono" data-quote>Quote ${escapeHtml(options.quote)} USDC</p>` : `<p class="haze-muted">Quote appears after connect.</p>`}`
      : path === "/send"
        ? `<label class="haze-field">Recipient haze1<input class="haze-figure" name="recipient" placeholder="haze1…" autocomplete="off"></label>
           ${amountRow("amount", "0.5")}`
        : path === "/withdraw"
          ? `<label class="haze-field">Public recipient<input class="haze-figure" name="recipient" placeholder="0x…" autocomplete="off"></label>
             ${amountRow("amount", "1")}`
          : path === "/emergency-exit"
            ? `<p data-code="TIMELOCK">Public emergency exit waits the seven-day cooldown before execute.</p>
               <label class="haze-field">Public recipient<input class="haze-figure" name="recipient" placeholder="0x…" autocomplete="off"></label>`
            : path === "/migrate"
              ? `<p>Exit-and-re-shield is a public withdrawal then a separately authorized shield. The two public amounts are linked.</p>
                 <label class="haze-field">Replacement pool<input class="haze-figure" name="replacementPool" autocomplete="off"></label>`
              : amountRow("amount", "1");

  const liveForm = (options.live === true && path === "/shield") || hatchAllowed(path, options);
  return `<form class="haze-form" data-action="${escapeHtml(kind || "direct-shield")}" data-live="${liveForm ? "true" : "false"}">
    ${fields}
    <button class="haze-button" type="submit" data-action="run" data-kind="${escapeHtml(kind)}" ${canSign ? "" : "disabled"}>${canSign ? "Sign and submit" : disabledReason}</button>
    ${hatchAllowed(path, options) ? `<p class="haze-muted" data-prove-phase></p>` : ""}
    <p class="haze-mono" data-live-status></p>
  </form>`;
}

function adminWorkspace(options: RenderOptions) {
  const admin = options.admin ?? {};
  const cases = (admin.cases ?? []).map((item) => `<li>${escapeHtml(item.caseId)} ${escapeHtml(item.title)}</li>`).join("");
  const grants = (admin.grants ?? [])
    .map((item) => `<li>${escapeHtml(item.grantId)} ${escapeHtml(item.auditor)} ${item.revoked ? "revoked" : "active"}</li>`)
    .join("");
  return `<div class="haze-workspace-grid" data-workspace="admin">
    <section>
      <h2>Manifest</h2>
      <p class="haze-mono">${escapeHtml(admin.manifestHash ?? "none")}</p>
      <button class="haze-button" type="button" data-action="manifest">Register manifest</button>
    </section>
    <section>
      <h2>Health</h2>
      <p>KMS ${escapeHtml(admin.kmsHealth ?? "unregistered")}</p>
      <p>Gatekeeper ${escapeHtml(admin.gatekeeperSigner ?? "unknown")}</p>
    </section>
    <section>
      <h2>Delegations</h2>
      <ul>${grants || "<li>No auditor grants</li>"}</ul>
      <button class="haze-button haze-button-secondary" type="button" data-action="delegate">Delegate auditor</button>
      <button class="haze-button haze-button-secondary" type="button" data-action="revoke">Revoke</button>
    </section>
    <section>
      <h2>Cases</h2>
      <ul>${cases || "<li>No cases</li>"}</ul>
      <button class="haze-button haze-button-secondary" type="button" data-action="case">Open case</button>
      <button class="haze-button haze-button-secondary" type="button" data-action="export" data-field="commitment">Scoped export</button>
    </section>
  </div>`;
}

function auditWorkspace(options: RenderOptions) {
  const audit = options.audit ?? {};
  const cases = (audit.cases ?? []).map((item) => `<li>${escapeHtml(item.caseId)} ${escapeHtml(item.title)}</li>`).join("");
  const access = (audit.access ?? [])
    .map((item) => `<li>${escapeHtml(item.action)} ${item.allowed ? "allowed" : "denied"}</li>`)
    .join("");
  const rows = (audit.rows ?? [])
    .map(
      (item) =>
        `<li data-audit-row data-field="${escapeHtml(item.field)}"><span class="haze-muted">${escapeHtml(item.field)}</span> <span class="haze-figure">${escapeHtml(item.value)}</span></li>`,
    )
    .join("");
  return `<div class="haze-workspace-grid" data-workspace="audit">
    <section>
      <h2>SIWE session</h2>
      <p class="haze-mono">${escapeHtml(audit.boundWallet ?? "not bound")}</p>
      <button class="haze-button" type="button" data-action="siwe">Sign in with Ethereum</button>
    </section>
    <section>
      <h2>Assigned cases</h2>
      <ul>${cases || "<li>No assigned cases</li>"}</ul>
      <label class="haze-field">Fields<input name="fields" value="commitment" autocomplete="off"></label>
      <button class="haze-button haze-button-secondary" type="button" data-action="export" data-field="commitment">Export granted fields</button>
      <button class="haze-button haze-button-secondary" type="button" data-action="export" data-field="plaintext">Export overreach</button>
    </section>
    <section>
      <h2>Decrypted fields</h2>
      <ul data-audit-rows>${rows || "<li>No granted decrypt yet</li>"}</ul>
    </section>
    <section>
      <h2>Access log</h2>
      <ul>${access || "<li>No queries yet</li>"}</ul>
    </section>
  </div>`;
}

function dexBalances(options: RenderOptions) {
  const pub = options.publicUsdc ?? "—";
  const priv = options.privateUsdc ?? "0.00";
  const pool = options.poolUsdc ?? "—";
  return `<div class="haze-balances">
    <div class="haze-balance" data-balance="public"><span class="haze-muted">Public</span><span class="haze-figure">${escapeHtml(pub)} USDC</span></div>
    <div class="haze-balance" data-balance="private"><span class="haze-muted">Private</span><span class="haze-figure">${escapeHtml(priv)} USDC</span></div>
    <div class="haze-balance" data-pool-usdc><span class="haze-muted">Pool</span><span class="haze-figure">${escapeHtml(pool)} USDC</span></div>
  </div>`;
}

function governanceWorkspace(options: RenderOptions) {
  const gov = options.governance ?? {};
  return `<div class="haze-workspace-grid" data-workspace="governance">
    <section>
      <h2>On-chain preview</h2>
      <p class="haze-mono">Target ${escapeHtml(gov.previewTarget ?? "none")}</p>
      <p class="haze-mono">Timelock ${escapeHtml(gov.timelock ?? "none")}</p>
      <button class="haze-button" type="button" data-action="gov-preview">Preview schedule</button>
      <button class="haze-button haze-button-secondary" type="button" data-action="gov-execute">Execute now</button>
      <p data-code="TIMELOCK">Early execute stays TIMELOCK until the delay elapses.</p>
    </section>
    <section>
      <h2>Ceremony provenance</h2>
      <p>Production ceremony ${gov.ceremonyProduction ? "approved" : "closed"}</p>
      <p>Emergency ${escapeHtml(gov.emergency ?? "inactive")}</p>
      <p>Super-auditor grant has no note custody.</p>
    </section>
  </div>`;
}

export function renderHazeFragment(site: Site, path: string, options: RenderOptions = {}) {
  const fujiBrowser =
    options.mode === "fuji-browser" &&
    (path === "/shield" || path === "/withdraw" || path === "/audit");
  const decision = site.decide(path);
  const walletStatus = options.walletStatus ?? (options.address ? "connected" : "disconnected");
  const reviewed = Boolean(options.reviewed);
  const hatch = hatchAllowed(path, options);
  const strip = statusStrip({
    broadcast: false,
    spendProve: "KEYS_MISSING",
    live: options.live,
    path,
    walletStatus,
    operatorProve: options.operatorProve,
    zkeyExists: options.zkeyExists,
  });
  const canSign = decision.ok
    ? canSignAction({
        path,
        walletStatus,
        reviewed,
        role: site.session.role,
        spendProve: "KEYS_MISSING",
        live: options.live,
        operatorProve: options.operatorProve,
        zkeyExists: options.zkeyExists,
      })
    : false;
  const disabledReason = !decision.ok
    ? "Not authorized"
    : walletStatus !== "connected"
      ? "Connect wallet"
      : !reviewed && site.warnings(path, false).length > 0
        ? "Review public facts first"
        : isSpendPath(path) && !hatch
          ? "Spend proofs unavailable"
          : "Sign and submit";

  const chrome = site.session.role && site.session.role !== "pool-user" ? "compliance" : "dex";
  const primaryPaths =
    chrome === "compliance"
      ? (["/admin", "/audit", "/governance"] as const)
      : (["/swap", "/shield", "/send", "/withdraw"] as const);
  const morePaths =
    chrome === "compliance"
      ? (["/shield"] as const)
      : (["/history", "/emergency-exit", "/migrate"] as const);
  const tabNav = primaryPaths
    .map((item) => {
      const current = item === path ? ' aria-current="page"' : "";
      const label = site.nav.find((entry) => entry.path === item)?.label ?? item.slice(1);
      return `<a class="haze-tab" href="${item}"${current}>${escapeHtml(label)}</a>`;
    })
    .join("");
  const moreNav = morePaths
    .map((item) => {
      const label = site.nav.find((entry) => entry.path === item)?.label ?? item.slice(1);
      return `<a class="haze-more-link" href="${item}">${escapeHtml(label)}</a>`;
    })
    .join("");

  const workspaces = workspaceChoices(options.address);
  const showRole = walletStatus === "connected" && Boolean(site.session.role);
  const workspaceChip = showRole
    ? workspaces.length > 1
      ? `<label class="haze-chip">Workspace <select name="workspace">${workspaces
          .map((role) => `<option>${escapeHtml(role)}</option>`)
          .join("")}</select></label>`
      : `<span class="haze-chip" data-role="${escapeHtml(site.session.role ?? "")}">${escapeHtml(site.session.role ?? "")}</span>`
    : "";

  const walletChip = fujiBrowser
    ? ""
    : walletStatus === "connected" && options.address
      ? `<span class="haze-chip haze-chip-wallet" data-address="${escapeHtml(options.address)}">${escapeHtml(truncateAddress(options.address))}</span>
         <button class="haze-button haze-button-secondary" type="button" data-action="disconnect">Disconnect</button>`
      : `<button class="haze-button" type="button" data-action="connect">Connect wallet</button>`;

  const deniedCopy =
    walletStatus === "connected"
      ? humanStatus(decision.code ?? "FORBIDDEN")
      : "Connect a wallet that is granted this workspace.";
  const banners = [
    ...(!decision.ok && !(fujiBrowser && path === "/audit")
      ? [`<div class="haze-banner" role="alert" data-code="${decision.code}">${deniedCopy}</div>`]
      : []),
    ...(walletStatus === "wrong-chain"
      ? [
          `<div class="haze-banner" role="alert" data-code="wrong-chain">${humanStatus("wrong-chain")} <button class="haze-button" type="button" data-action="switch-network">Switch network</button></div>`,
        ]
      : []),
    ...(!fujiBrowser ? strip : [])
      .filter(
        (item) =>
          item.code === "live-sidecar" ||
          item.code === "operator-demo" ||
          (isSpendPath(path) && item.code === "KEYS_MISSING"),
      )
      .map(
        (item) =>
          `<div class="haze-banner" role="status" data-code="${item.code}">${escapeHtml(item.message)}</div>`,
      ),
  ].join("");

  const warningsMarkup = fujiBrowser ? "" : reviewPanel(site, path, reviewed);

  const body = fujiBrowser
    ? path === "/audit"
      ? `<div id="haze-audit-workstation-root"></div>`
      : `<div id="fuji-browser-transaction-root"></div>`
    : !decision.ok
    ? `<p>${deniedCopy}</p>`
    : path === "/admin"
      ? adminWorkspace(options)
      : path === "/audit"
        ? auditWorkspace(options)
        : path === "/governance"
          ? governanceWorkspace(options)
          : `${poolForm(path, options, canSign, disabledReason)}`;

  const title = TITLES[path] ?? path.slice(1);

  const statusChips = (fujiBrowser ? [] : strip)
    .map((item) => `<span class="haze-chip" data-code="${item.code}">${escapeHtml(item.message)}</span>`)
    .join("");

  return `<a class="haze-skip" href="#content">Skip to content</a>
  <div class="haze-shell" data-origin="single" data-chrome="${chrome}">
    <header class="haze-top">
      <a class="haze-brand" href="${chrome === "dex" ? "/shield" : "/admin"}">Haze</a>
      <div class="haze-status" role="status">${statusChips}</div>
      <div class="haze-session">
        <span class="haze-chip" data-network>${fujiBrowser || options.live ? "Fuji · 43113" : "Local · 31337"}</span>
        ${workspaceChip}
        ${walletChip}
      </div>
    </header>
    <main id="content" class="haze-stage">
      <section class="haze-card" data-card="${path === "/audit" && fujiBrowser ? "compliance-audit" : chrome === "dex" ? "pool" : "compliance"}">
        ${path === "/audit" && fujiBrowser ? "" : `<nav class="haze-dex-tabs" aria-label="${chrome === "dex" ? "Pool" : "Compliance"}">${tabNav}</nav>
        <h1 class="haze-title">${escapeHtml(title)}</h1>`}
        ${chrome === "dex" && !fujiBrowser ? dexBalances(options) : ""}
        ${banners}
        ${!fujiBrowser && decision.ok && path !== "/history" && path !== "/admin" && path !== "/audit" && path !== "/governance" ? warningsMarkup : ""}
        ${body}
        ${fujiBrowser ? "" : `<p class="haze-mono haze-phase">Phase ${escapeHtml(options.phase ?? "idle")} · Notes ${options.notes ?? 0}</p>
        <p class="haze-mono" data-error>${escapeHtml(options.lastError ?? "")}</p>`}
        ${path === "/audit" && fujiBrowser ? "" : `<nav class="haze-more">${moreNav}</nav>`}
      </section>
    </main>
  </div>`;
}

export function renderHazePage(site: Site, path: string, options: RenderOptions = {}) {
  const title = TITLES[path] ?? path.slice(1);
  const hatch = hatchAllowed(path, options);
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Haze — ${escapeHtml(title)}</title>
  <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='4' fill='%2316130f'/%3E%3Ctext x='16' y='22' text-anchor='middle' font-size='16' fill='%23f3ece2' font-family='ui-sans-serif'%3EH%3C/text%3E%3C/svg%3E">
  <link rel="stylesheet" href="/theme.css">
  <link rel="stylesheet" href="/fonts/plex.css">
  <style>html{font-family:"IBM Plex Sans",ui-sans-serif,system-ui,sans-serif}</style>
</head>
<body>
  ${renderHazeFragment(site, path, options)}
  <script src="/client.js" defer></script>
  ${path === "/shield" && options.live ? `<script src="/shield-live.js" defer></script>` : ""}
  ${hatch ? `<script src="/withdraw-live.js" defer></script>` : ""}
</body>
</html>`;
}
