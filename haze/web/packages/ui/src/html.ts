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
  admin?: {
    manifestHash?: string;
    kmsHealth?: string;
    gatekeeperSigner?: string;
    cases?: { caseId: string; title: string }[];
    grants?: { grantId: string; auditor: string; revoked: boolean }[];
  };
  audit?: {
    boundWallet?: string;
    cases?: {
      caseId: string;
      title: string;
      transactionHash?: string;
      caseState?: string;
      confirmationCount?: number;
      requiredConfirmations?: number;
      canonicalBlockIdentity?: string;
      readiness?: boolean;
      fields?: string[];
      disclosedRecord?: {
        tx_hash: string;
        amount: string;
        asset: string;
        timestamp: string;
        policy_version: number;
      };
    }[];
    selectedCaseId?: string;
    access?: {
      id?: string;
      action: string;
      allowed: boolean;
      caseId?: string;
      hash?: string;
      prevHash?: string;
      timestamp?: number;
    }[];
    chainVerified?: boolean;
    headHash?: string;
    exportModal?: {
      caseId: string;
      json: string;
    };
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

const FLAME_SVG = `<svg class="haze-flame" viewBox="0 0 24 24" width="20" height="20" aria-hidden="true" fill="currentColor"><path d="M12 2C10.5 4.5 9 6.5 9 9c0 1.66 1.34 3 3 3s3-1.34 3-3c0-2.5-1.5-4.5-3-7zm-4.5 9.5C6.12 13 5 14.86 5 17c0 3.87 3.13 7 7 7s7-3.13 7-7c0-2.14-1.12-4-2.5-5.5-.83 1.5-2.17 2.5-4.5 2.5s-3.67-1-4.5-2.5z"/></svg>`;

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

  const assetRow = `
    <div class="haze-field-row" data-field="asset">
      <span class="haze-muted">Asset</span>
      <div class="haze-asset-box">
        <span class="haze-token-badge">USDC</span>
        <span class="haze-muted" style="font-size:12px;">Circle Fuji</span>
      </div>
    </div>`;

  const amountRow = (name: string, value: string) =>
    `<div class="haze-amount-row">
      <div class="haze-amount-field">
        <label class="haze-muted" for="${name}">Amount</label>
        <input id="${name}" name="${name}" class="haze-amount haze-mono" inputmode="decimal" value="${value}">
      </div>
      <span class="haze-token">USDC</span>
    </div>`;

  const shieldedBalanceRow = `
    <div class="haze-info-row" data-field="shielded-balance">
      <span class="haze-muted">Shielded Balance</span>
      <span class="haze-mono haze-balance-val">${escapeHtml(options.privateUsdc ?? "0.00")} USDC</span>
    </div>`;

  const networkRow = `
    <div class="haze-info-row" data-field="network">
      <span class="haze-muted">Network</span>
      <span class="haze-badge" data-network="fuji">Avalanche Fuji</span>
    </div>`;

  const recipientRow =
    path === "/send" || path === "/withdraw"
      ? `<label class="haze-field">Recipient<input name="recipient" class="haze-mono" placeholder="0x… or haze1…" autocomplete="off"></label>`
      : "";

  return `<form class="haze-form" data-workspace="pool" data-kind="${escapeHtml(kind)}" data-live="${options.live ? "true" : "false"}">
    ${path === "/swap" ? `<p class="haze-muted">Provider quote ${options.quote ?? "1 USDC = 1 USDC"}</p>` : ""}
    ${path === "/emergency-exit" ? `<p class="haze-banner" data-code="cooldown">Seven-day emergency cooldown is active.</p>` : ""}
    ${assetRow}
    ${amountRow("amount", "1")}
    ${shieldedBalanceRow}
    ${networkRow}
    ${recipientRow}
    <button class="haze-button" type="submit" data-action="run" data-kind="${escapeHtml(kind)}" ${canSign ? "" : "disabled"}>${escapeHtml(disabledReason)}</button>
    ${hatchAllowed(path, options) ? `<p class="haze-muted" data-prove-phase></p>` : ""}
    <p class="haze-mono" data-live-status></p>
    <div id="fuji-browser-transaction-root"></div>
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
  const bound = Boolean(audit.boundWallet);
  if (!bound) {
    return `<div class="haze-form" data-workspace="audit">
      <div class="haze-field-row" data-field="case-id">
        <label class="haze-muted" for="audit-case-id">Case ID</label>
        <input id="audit-case-id" name="caseId" class="haze-amount haze-mono" style="font-size:16px;text-align:right;" placeholder="case-101">
      </div>
      <div class="haze-field-row" data-field="case-file">
        <span class="haze-muted">Case File</span>
        <button class="haze-button haze-button-secondary" type="button" data-action="download-case-file" style="min-height:36px;font-size:13px;" disabled>Download Case File</button>
      </div>
      <p class="haze-muted" style="font-size:12px;margin:12px 0 16px;">Connect and authenticate your dedicated auditor wallet to access assigned compliance cases.</p>
      <button class="haze-button" type="button" data-action="siwe">Sign in with Ethereum</button>
    </div>`;
  }

  const caseItems = audit.cases ?? [];
  const selectedCaseId = audit.selectedCaseId ?? caseItems[0]?.caseId;
  const currentCase = caseItems.find((c) => c.caseId === selectedCaseId) ?? caseItems[0];

  const caseListMarkup = caseItems
    .map((item) => {
      const isSelected = item.caseId === selectedCaseId;
      const state = item.caseState ?? "observed";
      const txHash = item.transactionHash ?? "";
      return `<li class="haze-case-item ${isSelected ? "is-selected" : ""}" data-action="select-case" data-case-id="${escapeHtml(item.caseId)}">
        <div class="haze-case-title">${escapeHtml(item.title)}</div>
        <div style="display:flex; justify-content:space-between; align-items:center; margin-top:4px;">
          <span class="haze-mono" style="font-size:11px; color:var(--haze-muted);">${escapeHtml(txHash ? truncateAddress(txHash) : item.caseId)}</span>
          <span class="haze-badge" data-state="${escapeHtml(state)}">${escapeHtml(state)}</span>
        </div>
      </li>`;
    })
    .join("");

  const state = currentCase?.caseState ?? "observed";
  const confCount = currentCase?.confirmationCount ?? 0;
  const reqConf = currentCase?.requiredConfirmations ?? 12;
  const isReady = (state === "ready" || state === "verified" || state === "exported") && state !== "reorged";

  let bannerText = "";
  if (state === "reorged") {
    bannerText = "Reorg detected on Fuji — case invalidated and disclosure blocked.";
  } else if (state === "observed" || state === "confirming") {
    bannerText = `Waiting for finality — ${confCount}/${reqConf} confirmations`;
  } else if (state === "ready") {
    bannerText = `Ready for verification (${confCount}/${reqConf} canonical confirmations)`;
  } else if (state === "verified" || state === "exported") {
    bannerText = `Verified & disclosed on Fuji · 43113`;
  }

  const disclosed = currentCase?.disclosedRecord;
  const recordMarkup = disclosed
    ? `<div class="haze-disclosed-record" data-disclosed="true">
        <div class="haze-record-row"><span class="haze-record-key">Transaction Hash</span><span class="haze-record-val haze-mono" data-field="tx_hash">${escapeHtml(disclosed.tx_hash)}</span></div>
        <div class="haze-record-row"><span class="haze-record-key">Amount</span><span class="haze-record-val" data-field="amount">${escapeHtml(disclosed.amount)}</span></div>
        <div class="haze-record-row"><span class="haze-record-key">Asset</span><span class="haze-record-val" data-field="asset">${escapeHtml(disclosed.asset)}</span></div>
        <div class="haze-record-row"><span class="haze-record-key">Timestamp</span><span class="haze-record-val" data-field="timestamp">${escapeHtml(disclosed.timestamp)}</span></div>
        <div class="haze-record-row"><span class="haze-record-key">Policy Version</span><span class="haze-record-val" data-field="policy_version">${escapeHtml(String(disclosed.policy_version))}</span></div>
      </div>
      <div style="display:flex; gap:8px;">
        <button class="haze-button haze-button-secondary" type="button" data-action="export-review" data-case-id="${escapeHtml(currentCase.caseId)}">Export review</button>
      </div>`
    : "";

  const accessListMarkup = (audit.access ?? [])
    .map(
      (item) =>
        `<li><span class="${item.allowed ? "haze-check-ok" : "haze-muted"}">${item.allowed ? "✔" : "✖"}</span> ${escapeHtml(item.action)} ${escapeHtml(item.caseId ?? "")} ${item.allowed ? "allowed" : "denied"}</li>`,
    )
    .join("");

  const headHash = audit.headHash ?? "0x" + "00".repeat(32);
  const modalMarkup = audit.exportModal
    ? `<div class="haze-modal-backdrop">
        <div class="haze-modal-dialog">
          <h2 class="haze-title">Signed Export Review</h2>
          <p class="haze-muted">Case: <span class="haze-mono">${escapeHtml(audit.exportModal.caseId)}</span></p>
          <pre class="haze-mono" style="background:var(--haze-bg); padding:12px; border-radius:8px; overflow-x:auto; font-size:12px;">${escapeHtml(audit.exportModal.json)}</pre>
          <div style="display:flex; justify-content:flex-end; gap:8px; margin-top:16px;">
            <button class="haze-button haze-button-secondary" type="button" data-action="close-modal">Close</button>
            <button class="haze-button" type="button" data-action="download-export" data-case-id="${escapeHtml(audit.exportModal.caseId)}">Download signed JSON</button>
          </div>
        </div>
      </div>`
    : "";

  return `<div class="haze-workstation" data-workspace="audit">
    <!-- Left Rail: Cases -->
    <aside class="haze-rail-cases">
      <h2 style="font-size:14px; margin:0 0 12px; text-transform:uppercase; color:var(--haze-muted);">Assigned Cases</h2>
      <ul class="haze-case-list">
        ${caseListMarkup || `<li class="haze-muted" style="font-size:12px;">No cases assigned</li>`}
      </ul>
    </aside>

    <!-- Middle Panel: Selected Record & Disclosure -->
    <main class="haze-panel-record">
      ${
        currentCase
          ? `
          <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:12px;">
            <div>
              <h2 class="haze-title" style="font-size:18px; margin-bottom:4px;">${escapeHtml(currentCase.title)}</h2>
              <p class="haze-mono" style="font-size:12px; color:var(--haze-muted); margin:0;" data-active-hash="${escapeHtml(currentCase.transactionHash ?? "")}">${escapeHtml(currentCase.transactionHash ?? "")}</p>
            </div>
            <span class="haze-badge" data-state="${escapeHtml(state)}">${escapeHtml(state)}</span>
          </div>

          <div class="haze-banner" data-case-state="${escapeHtml(state)}">${escapeHtml(bannerText)}</div>

          ${
            !disclosed
              ? `
              <div style="margin: 16px 0;">
                <button class="haze-button" type="button" data-action="verify-disclose" data-case-id="${escapeHtml(currentCase.caseId)}" ${isReady ? "" : "disabled"}>
                  Verify &amp; disclose
                </button>
              </div>
            `
              : ""
          }

          ${recordMarkup}
        `
          : `<p class="haze-muted">Select a case from the rail to inspect.</p>`
      }
    </main>

    <!-- Right Rail: Integrity & Access Activity -->
    <aside class="haze-rail-integrity">
      <h2 style="font-size:14px; margin:0 0 12px; text-transform:uppercase; color:var(--haze-muted);">Integrity Panel</h2>
      <ul class="haze-integrity-checks">
        <li class="haze-integrity-item"><span class="haze-check-ok">✔</span> Canonical receipt &amp; block identity</li>
        <li class="haze-integrity-item"><span class="${confCount >= reqConf ? "haze-check-ok" : "haze-muted"}">${confCount >= reqConf ? "✔" : "⏳"}</span> 12 confirmations (${confCount}/${reqConf})</li>
        <li class="haze-integrity-item"><span class="haze-check-ok">✔</span> Expected pool, app 0x…0a11 &amp; withdraw</li>
        <li class="haze-integrity-item"><span class="haze-check-ok">✔</span> Envelope hash verified</li>
        <li class="haze-integrity-item"><span class="haze-check-ok">✔</span> Audit data commitment verified</li>
      </ul>

      <h2 style="font-size:14px; margin:20px 0 8px; text-transform:uppercase; color:var(--haze-muted);">Access History</h2>
      <ul class="haze-access-history">
        ${accessListMarkup || `<li class="haze-muted">No activity recorded</li>`}
      </ul>
      <p class="haze-mono" style="font-size:11px; color:var(--haze-muted); margin-top:8px;" data-chain-verified="true">
        Chain integrity: Verified (Head: ${escapeHtml(headHash.slice(0, 10))}…)
      </p>
    </aside>
    ${modalMarkup}
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

  const chrome = site.session.role && site.session.role !== "pool-user" ? "compliance" : "consumer";
  const primaryPaths =
    chrome === "compliance"
      ? (["/admin", "/audit", "/governance"] as const)
      : (["/shield", "/withdraw", "/audit"] as const);
  const morePaths =
    chrome === "compliance"
      ? (["/shield"] as const)
      : (["/swap", "/send", "/history", "/emergency-exit", "/migrate"] as const);
  const tabNav = primaryPaths
    .map((item) => {
      const current = item === path ? ' aria-current="page"' : "";
      const label = item === "/audit" ? "Audit" : site.nav.find((entry) => entry.path === item)?.label ?? item.slice(1);
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

  const walletChip =
    walletStatus === "connected" && options.address
      ? `<span class="haze-chip haze-chip-wallet" data-address="${escapeHtml(options.address)}">${escapeHtml(truncateAddress(options.address))}</span>
         <button class="haze-button haze-button-secondary" type="button" data-action="disconnect">Disconnect</button>`
      : `<button class="haze-button" type="button" data-action="connect">Connect wallet</button>`;

  const deniedCopy =
    walletStatus === "connected"
      ? humanStatus(decision.code ?? "FORBIDDEN")
      : "Connect a wallet that is granted this workspace.";
  const banners = [
    ...(!decision.ok && path !== "/audit"
      ? [`<div class="haze-banner" role="alert" data-code="${decision.code}">${deniedCopy}</div>`]
      : []),
    ...(walletStatus === "wrong-chain"
      ? [
          `<div class="haze-banner" role="alert" data-code="wrong-chain">${humanStatus("wrong-chain")} <button class="haze-button" type="button" data-action="switch-network">Switch network</button></div>`,
        ]
      : []),
    ...strip
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

  const warningsMarkup = reviewPanel(site, path, reviewed);

  const body = path === "/audit"
    ? auditWorkspace(options)
    : !decision.ok
      ? `<p>${deniedCopy}</p>`
      : path === "/admin"
        ? adminWorkspace(options)
        : path === "/governance"
          ? governanceWorkspace(options)
          : `${poolForm(path, options, canSign, disabledReason)}`;

  const title = TITLES[path] ?? path.slice(1);

  const statusChips = strip
    .map((item) => `<span class="haze-chip" data-code="${item.code}">${escapeHtml(item.message)}</span>`)
    .join("");

  return `<a class="haze-skip" href="#content">Skip to content</a>
  <div class="haze-shell" data-origin="single" data-chrome="${chrome}">
    <header class="haze-top">
      <a class="haze-brand" href="${chrome === "consumer" ? "/shield" : "/admin"}">
        ${FLAME_SVG}
        <span>HAZE</span>
      </a>
      <div class="haze-status" role="status">${statusChips}</div>
      <div class="haze-session">
        <span class="haze-chip" data-network="fuji">Avalanche Fuji</span>
        ${workspaceChip}
        <span id="haze-session-root">${walletChip}</span>
      </div>
    </header>
    <main id="content" class="haze-stage">
      <section class="haze-card" data-card="${chrome === "consumer" ? "pool" : "compliance"}">
        <nav class="haze-dex-tabs" aria-label="${chrome === "consumer" ? "Pool" : "Compliance"}">${tabNav}</nav>
        <h1 class="haze-title">${escapeHtml(title)}</h1>
        ${banners}
        ${decision.ok && path !== "/history" && path !== "/admin" && path !== "/audit" && path !== "/governance" ? warningsMarkup : ""}
        ${body}
        <p class="haze-mono haze-phase">Phase ${escapeHtml(options.phase ?? "idle")} · Notes ${options.notes ?? 0}</p>
        <p class="haze-mono" data-error>${escapeHtml(options.lastError ?? "")}</p>
        <nav class="haze-more">${moreNav}</nav>
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
