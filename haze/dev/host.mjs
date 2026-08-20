#!/usr/bin/env node
import http from "node:http";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { assembleStack } from "./stack.mjs";
import { decodeHazeAddress } from "../sdk/typescript/src/address.ts";
import { encodeEnvelope } from "../sdk/typescript/src/envelope.ts";
import { intentStructHash } from "../sdk/typescript/src/eip712.ts";
import { SdkError } from "../sdk/typescript/src/errors.ts";
import { createGatekeeperClient } from "../sdk/typescript/src/gatekeeper.ts";
import { recipientAad, sealRecipientNote } from "../sdk/typescript/src/hpke.ts";
import { HAZE_PRODUCT_ID } from "../sdk/typescript/src/identity.ts";
import { hashManifest } from "../sdk/typescript/src/manifest.ts";
import { noteCommitment } from "../sdk/typescript/src/note.ts";
import { createStaticQuoteAdapter } from "../sdk/typescript/src/quote.ts";
import { deriveVaultAccount } from "../sdk/typescript/src/vault.ts";
import { createDexApp, renderDexHtml } from "../apps/privacy-pool-dex/src/index.ts";
import {
  authorizeRoute,
  copyFor,
  createAdminWorkspace,
  createAuditWorkspace,
  createGovernanceWorkspace,
  renderAdminHtml,
  renderAuditHtml,
  renderGovernanceHtml,
} from "../apps/compliance-portal/src/index.ts";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PROTOCOL = join(HAZE_ROOT, "circuits/vectors/v1/haze-protocol-v1.json");
const FUJI_PATH = join(HAZE_ROOT, "deployments/fuji-v1.json");
const APP_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const APP_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ZERO32 = `0x${"00".repeat(32)}`;
const WALLET = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf";
const SIGNING_KEY = "0x0000000000000000000000000000000000000000000000000000000000000001";
const AUDITOR = "0x2222222222222222222222222222222222222222";
const REGISTRY = "0x1111111111111111111111111111111111111111";
const TIMELOCK = "0x2222222222222222222222222222222222222222";
const CSP = "default-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self' 'unsafe-inline'";

const DEX_PATHS = new Set([
  "/swap",
  "/shield",
  "/send",
  "/withdraw",
  "/history",
  "/emergency-exit",
  "/migrate",
]);
const PORTAL_PATHS = new Set(["/admin", "/audit", "/governance"]);
const PATH_KIND = {
  "/swap": "swap-and-shield",
  "/shield": "direct-shield",
  "/send": "private-send",
  "/withdraw": "withdraw",
  "/emergency-exit": "emergency-exit",
  "/migrate": "exit-and-reshield",
};

function loadProtocol() {
  return JSON.parse(readFileSync(PROTOCOL, "utf8"));
}

function named(vectors, name) {
  return vectors.positive.find((vector) => vector.name === name);
}

function depositIntent() {
  return named(loadProtocol(), "haze_intent_deposit").fields;
}

function fixtureBinding(applicationId = APP_A) {
  const stack = assembleStack("local");
  return {
    chainId: 43113,
    pool: stack.deployments.HazePool,
    router: "0x4444444444444444444444444444444444444444",
    exit: "0x5555555555555555555555555555555555555555",
    applicationId,
    poolVersion: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  };
}

export function loadFujiDeployment() {
  return JSON.parse(readFileSync(FUJI_PATH, "utf8"));
}

export function fujiGate(deployment = loadFujiDeployment()) {
  const reasons = [];
  if (deployment.broadcast !== true) {
    reasons.push("broadcast:false");
  }
  if (deployment.spend_prove === "KEYS_MISSING") {
    reasons.push("KEYS_MISSING");
  }
  if (deployment.live_rpc === "operator-owned") {
    reasons.push("operator-owned-rpc");
  }
  const pool =
    deployment.addresses?.HazePool ??
    deployment.HazePool ??
    (typeof deployment.contracts === "object" && !Array.isArray(deployment.contracts)
      ? deployment.contracts.HazePool
      : undefined);
  if (typeof pool !== "string" || !/^0x[a-fA-F0-9]{40}$/.test(pool)) {
    reasons.push("missing-HazePool");
  }
  return { ready: reasons.length === 0, reasons, deployment };
}

function headers() {
  return { get: (name) => (name.toLowerCase() === "haze-api-version" ? "1" : null) };
}

function createAuthGatekeeper(options = {}) {
  let issued = 0;
  return createGatekeeperClient({
    endpoint: "/v1",
    fetch: async (url, init) => {
      if (!url.endsWith("/authorizations")) {
        throw new Error(`unexpected ${url}`);
      }
      if (options.deny) {
        return {
          ok: false,
          status: 403,
          headers: headers(),
          json: async () => ({ code: options.deny }),
          text: async () => options.deny,
        };
      }
      const body = JSON.parse(init.body);
      issued += 1;
      const template = depositIntent();
      const intent = {
        ...body.intent,
        auditDataCommitment: template.auditDataCommitment,
        auditCiphertextHash: template.auditCiphertextHash,
      };
      return {
        ok: true,
        status: 200,
        headers: headers(),
        json: async () => ({
          intent,
          authorization: {
            applicationId: intent.applicationId,
            user: intent.user,
            pool: intent.pool,
            poolVersion: intent.poolVersion,
            action: intent.action,
            intentHash: intentStructHash(intent),
            applicationPolicyVersion: intent.applicationPolicyVersion,
            hazePolicyVersion: intent.hazePolicyVersion,
            auditDataCommitment: intent.auditDataCommitment,
            auditCiphertextHash: intent.auditCiphertextHash,
            nonce: `0x${issued.toString(16).padStart(64, "0")}`,
            validAfter: 1,
            validUntil: 2_000_000_000,
          },
        }),
        text: async () => "",
      };
    },
  });
}

function createPolicy() {
  const intent = depositIntent();
  return {
    async snapshot() {
      return {
        noteTreeRoot: intent.noteTreeRoot,
        applicationPolicyVersion: intent.applicationPolicyVersion,
        hazePolicyVersion: intent.hazePolicyVersion,
        applicationMembershipRoot: intent.applicationMembershipRoot,
        hazeBlocklistRoot: intent.hazeBlocklistRoot,
      };
    },
  };
}

function createWallet() {
  return {
    async send() {
      return { hash: `0x${"11".repeat(32)}` };
    },
  };
}

function createFinality() {
  return {
    async wait() {
      return { status: "finalized", blockNumber: 20, events: [] };
    },
  };
}

function createClock(start = 1_700_000_000) {
  let now = start;
  return {
    now() {
      return now;
    },
    advance(seconds) {
      now += seconds;
    },
  };
}

function hex(bytes) {
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

function sealedEvent(account, applicationId = APP_A) {
  const binding = fixtureBinding(applicationId);
  const blinding = `0x${"00".repeat(31)}02`;
  const value = 1_000_000n;
  const commitment = noteCommitment({
    ...binding,
    value,
    ownerNotePublicKey: account.notePublicKey,
    ownerEncryptionKeyHash: account.encryptionKeyHash,
    blinding,
  });
  const plaintext = {
    value,
    blinding,
    notePublicKey: account.notePublicKey,
    encryptionKeyHash: account.encryptionKeyHash,
    applicationId: binding.applicationId,
    poolVersion: binding.poolVersion,
    commitment,
  };
  const aad = recipientAad({
    ...binding,
    outputIndex: 0,
    outputCommitment: commitment,
    envelopeVersion: 1,
  });
  const sealed = sealRecipientNote({
    recipientIkm: account.x25519Secret,
    senderSeed: `0x${"61".repeat(32)}`,
    aad,
    plaintext,
  });
  return {
    chainId: binding.chainId,
    pool: binding.pool,
    poolVersion: binding.poolVersion,
    applicationId: binding.applicationId,
    outputIndex: 0,
    commitment,
    envelope: hex(
      encodeEnvelope({
        purpose: "recipient",
        keyVersion: 0n,
        encapsulatedKey: sealed.encapsulatedKey,
        ciphertext: sealed.ciphertext,
      }),
    ),
    blockNumber: 42,
    finalized: true,
    txHash: `0x${"ab".repeat(32)}`,
    logIndex: 0,
  };
}

function fixtureManifest() {
  return {
    schemaVersion: 1,
    productId: HAZE_PRODUCT_ID,
    applicationId: APP_A,
    organizationName: "Haze Test Org",
    gatekeeperEndpoint: "https://gk.local.test/v1",
    portalEndpoint: "https://portal.local.test",
    auditorPolicy: { fields: ["commitment"] },
    kmsKeyRefs: ["dev-kms-aa"],
    auditKeys: [{ version: 1, publicKey: `0x${"11".repeat(32)}` }],
    sourceTokens: [{ token: "0x0000000000000000000000000000000000000001", decimals: 6 }],
    manifestVersion: 1,
  };
}

function jsonSafe(value) {
  return JSON.parse(JSON.stringify(value, (_, entry) => (typeof entry === "bigint" ? entry.toString() : entry)));
}

function asError(error) {
  if (error instanceof SdkError) {
    return error;
  }
  if (error && typeof error === "object" && "code" in error) {
    return error;
  }
  return { code: "UNAVAILABLE", message: String(error) };
}

function hostClientScript() {
  return `(() => {
  const ethereum = {
    chainId: "0xa869",
    request: async ({ method, params }) => {
      if (method === "eth_requestAccounts" || method === "eth_accounts") {
        return ["${WALLET}"];
      }
      if (method === "eth_chainId") {
        return ethereum.chainId;
      }
      if (method === "wallet_switchEthereumChain") {
        const next = params?.[0]?.chainId ?? "0xa869";
        ethereum.chainId = next;
        return null;
      }
      throw new Error("unsupported " + method);
    }
  };
  window.ethereum = ethereum;

  async function post(path, body) {
    const response = await fetch(path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body ?? {})
    });
    return response.json();
  }

  document.addEventListener("click", async (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) {
      return;
    }
    const action = target.getAttribute("data-action");
    if (!action) {
      return;
    }
    event.preventDefault();
    if (action === "connect") {
      const accounts = await window.ethereum.request({ method: "eth_requestAccounts" });
      const chainIdHex = await window.ethereum.request({ method: "eth_chainId" });
      await post("/api/connect", { address: accounts[0], chainId: Number.parseInt(chainIdHex, 16) });
    } else if (action === "wrong-chain") {
      await window.ethereum.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId: "0x1" }]
      });
      const accounts = await window.ethereum.request({ method: "eth_requestAccounts" });
      await post("/api/connect", { address: accounts[0], chainId: 1 });
    } else if (action === "preview") {
      await post("/api/preview", { kind: target.getAttribute("data-kind") });
    } else if (action === "run") {
      await post("/api/run", {
        kind: target.getAttribute("data-kind"),
        recipient: target.getAttribute("data-recipient") || undefined,
        step: target.getAttribute("data-step") || undefined
      });
    } else if (action === "wipe") {
      await post("/api/wipe", {});
    } else if (action === "recover") {
      await post("/api/recover", {});
    } else if (action === "signin") {
      await post("/api/portal/signin", { role: target.getAttribute("data-role") });
    } else if (action === "manifest") {
      await post("/api/portal/manifest", {});
    } else if (action === "delegate") {
      await post("/api/portal/delegate", {});
    } else if (action === "siwe") {
      const started = await post("/api/portal/siwe/start", {});
      await post("/api/portal/siwe/complete", { nonce: started.nonce });
    } else if (action === "export") {
      await post("/api/portal/export", { fields: [target.getAttribute("data-field") || "commitment"] });
    } else if (action === "gov-preview") {
      await post("/api/governance/preview", {});
    } else if (action === "gov-execute") {
      const state = await (await fetch("/api/state")).json();
      await post("/api/governance/execute", { id: state.governanceId });
    }
    window.location.reload();
  });
})();
`;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => {
    switch (char) {
      case "&":
        return "&amp;";
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case '"':
        return "&quot;";
      default:
        return "&#39;";
    }
  });
}

function chromeMarkup(state) {
  const notes = (state.notes ?? [])
    .map(
      (note) =>
        `<li data-visibility="${escapeHtml(note.visibility)}">${escapeHtml(note.visibility)} note ${escapeHtml(note.commitment ?? note.txHash ?? "")}</li>`,
    )
    .join("");
  const kind = state.kind ?? "direct-shield";
  return `
<aside id="haze-host-controls">
  <p>Profile: ${escapeHtml(state.profile)} · ${escapeHtml(state.networkLabel)}</p>
  <p>Wallet uses injected window.ethereum only.</p>
  <button type="button" data-action="connect">Connect wallet</button>
  <button type="button" data-action="wrong-chain">Connect wrong chain</button>
  <button type="button" data-action="preview" data-kind="${escapeHtml(kind)}">Acknowledge public facts</button>
  <button type="button" data-action="run" data-kind="${escapeHtml(kind)}">Run workflow</button>
  <button type="button" data-action="run" data-kind="private-send" data-recipient="foreign">Send to foreign application</button>
  <button type="button" data-action="run" data-kind="emergency-exit" data-step="request">Request emergency exit</button>
  <button type="button" data-action="run" data-kind="emergency-exit" data-step="execute">Execute emergency exit</button>
  <button type="button" data-action="wipe">Wipe notes</button>
  <button type="button" data-action="recover">Recover notes</button>
  <button type="button" data-action="signin" data-role="application-admin">Sign in as admin</button>
  <button type="button" data-action="signin" data-role="application-auditor">Sign in as auditor</button>
  <button type="button" data-action="signin" data-role="super-auditor">Sign in as super-auditor</button>
  <button type="button" data-action="manifest">Register manifest</button>
  <button type="button" data-action="delegate">Delegate auditor</button>
  <button type="button" data-action="siwe">Complete SIWE</button>
  <button type="button" data-action="export" data-field="commitment">Export scoped fields</button>
  <button type="button" data-action="gov-preview">Preview governance</button>
  <button type="button" data-action="gov-execute">Execute governance</button>
  <p id="haze-last-error">${escapeHtml(state.lastError ?? "")}</p>
  <section id="haze-notes">
    <h2>Local notes</h2>
    <ul>${notes}</ul>
    <p>Explorer hash (${escapeHtml(state.networkLabel)}): ${escapeHtml(state.txHash ?? "none")}</p>
  </section>
</aside>
<script src="/host.js"></script>`;
}

function injectChrome(html, state) {
  const kind = escapeHtml(state.kind ?? "direct-shield");
  const wired = html.replace(
    /(<button type="button"[^>]*)(>\s*Sign and submit)/,
    `$1 data-action="run" data-kind="${kind}"$2`,
  );
  if (wired.includes("</body>")) {
    return wired.replace("</body>", `${chromeMarkup(state)}\n</body>`);
  }
  return `${wired}${chromeMarkup(state)}`;
}

function glossaryHtml() {
  const facts = [
    "source-token-swap",
    "deposit-amount",
    "withdrawal-amount",
    "application-affiliation",
    "gas",
    "wallet-address",
    "version-migration",
    "shielded-note-amount",
  ];
  const items = facts
    .map((fact) => {
      const copy = copyFor(fact);
      return `<li data-visibility="${copy.visibility}"><strong>${escapeHtml(copy.label)}</strong> ${escapeHtml(copy.warning)}</li>`;
    })
    .join("");
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Haze privacy glossary</title>
  <style>
    body { margin: 0; font-family: "IBM Plex Sans", sans-serif; background: #16130f; color: #f3ece2; }
    .skip { position: absolute; left: -999px; }
    .skip:focus { left: 8px; top: 8px; }
  </style>
</head>
<body>
  <a class="skip" href="#haze-main">Skip to content</a>
  <main id="haze-main">
    <h1>Privacy glossary</h1>
    <ul>${items}</ul>
  </main>
</body>
</html>`;
}

function createLocalServices() {
  const binding = fixtureBinding();
  const account = deriveVaultAccount({
    ...binding,
    wallet: WALLET,
    signingKey: SIGNING_KEY,
  });
  const event = sealedEvent(account);
  const clock = createClock();
  let pendingConnect = { address: WALLET, chainId: 43113 };
  const dex = createDexApp({
    ...binding,
    expectedChainId: binding.chainId,
    connector: {
      async connect() {
        return { ...pendingConnect, signingKey: SIGNING_KEY };
      },
      async disconnect() {},
    },
    wallet: createWallet(),
    gatekeeper: createAuthGatekeeper(),
    quotes: createStaticQuoteAdapter({
      usdcOut: "1000000",
      adapter: "0x3333333333333333333333333333333333333333",
      data: "0xaabb",
      gasEstimate: 180000,
    }),
    policy: createPolicy(),
    finality: createFinality(),
    clock: clock.now.bind(clock),
    noteEvents: [event],
  });
  const emergencyDex = createDexApp({
    ...binding,
    expectedChainId: binding.chainId,
    connector: {
      async connect() {
        return { address: WALLET, chainId: 43113, signingKey: SIGNING_KEY };
      },
      async disconnect() {},
    },
    wallet: createWallet(),
    gatekeeper: createAuthGatekeeper({ deny: "USER_INELIGIBLE" }),
    policy: createPolicy(),
    finality: createFinality(),
    clock: clock.now.bind(clock),
  });

  const grants = [];
  const cases = [];
  const admin = createAdminWorkspace({
    applicationId: APP_A,
    auditAuth: {
      async delegate(input) {
        const grant = { grantId: `grant-${grants.length + 1}`, ...input, applicationId: APP_A, revoked: false };
        grants.push(grant);
        return grant;
      },
      async revoke({ grantId }) {
        const grant = grants.find((item) => item.grantId === grantId);
        grant.revoked = true;
        return grant;
      },
      async createCase(input) {
        const record = { caseId: `case-${cases.length + 1}`, ...input, applicationId: APP_A };
        cases.push(record);
        return record;
      },
      async listCases() {
        return [...cases];
      },
    },
    disclosure: {
      async export(input) {
        return { ...input, rows: [{ commitment: "0xcc" }] };
      },
    },
    indexer: {
      async queryApplication({ applicationId }) {
        return [{ applicationId, txHash: `0x${"11".repeat(32)}`, kind: "deposit" }];
      },
    },
    health: {
      async kms() {
        return { status: "ok", refs: ["dev-kms-aa"] };
      },
      async gatekeeper() {
        return { status: "ok", signer: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" };
      },
    },
  });

  const assigned = [
    {
      caseId: "case-1",
      title: "SAR-1",
      applicationId: APP_A,
      fields: ["commitment"],
      expiresAt: 1_900_000_000,
      revoked: false,
    },
  ];
  const access = [];
  const audit = createAuditWorkspace({
    applicationId: APP_A,
    auditor: AUDITOR,
    auditAuth: {
      async challenge({ address }) {
        return { nonce: "siwe-nonce", address };
      },
      async token({ address }) {
        return { token: "audience-cases", address };
      },
      async listAssigned() {
        return assigned;
      },
    },
    disclosure: {
      async query({ caseId, fields, grant }) {
        const extra = fields.find((field) => !grant.fields.includes(field));
        if (extra) {
          throw new SdkError("UNAUTHORIZED");
        }
        access.push({ action: "query", caseId, allowed: true });
        return { rows: [{ caseId, commitment: "0xcc" }] };
      },
      async export({ caseId, fields, applicationId, grant }) {
        const queried = await this.query({ caseId, fields, applicationId, grant });
        access.push({ action: "export", caseId, allowed: true });
        return { caseId, fields, applicationId, rows: queried.rows };
      },
      async accessLog() {
        return [...access];
      },
    },
  });

  const schedules = [];
  const governance = createGovernanceWorkspace({
    applicationId: APP_A,
    clock: clock.now.bind(clock),
    registry: {
      address: REGISTRY,
      timelock: TIMELOCK,
      delay: 86_400,
      async schedule(tx) {
        const item = { ...tx, executed: false };
        schedules.push(item);
        return item;
      },
      async execute(id) {
        const item = schedules.find((entry) => entry.id === id);
        item.executed = true;
        return item;
      },
      async list() {
        return [...schedules];
      },
    },
    status: {
      async snapshot() {
        return {
          suspended: [],
          emergency: { paused: false, exitOpen: true },
          versions: { pool: "1.0.0", artifactHash: `0x${"ab".repeat(32)}`, provenance: "development" },
          ceremony: { transcriptHash: `0x${"cd".repeat(32)}`, production: false },
        };
      },
    },
  });

  return { dex, emergencyDex, admin, audit, governance, clock, binding, setPendingConnect: (next) => {
    pendingConnect = next;
  } };
}

function shieldInput() {
  const intent = depositIntent();
  return {
    value: 1_000_000n,
    outputCommitment0: intent.outputCommitment0,
    outputCommitment1: intent.outputCommitment1,
    recipientCiphertextHash0: intent.recipientCiphertextHash0,
    recipientCiphertextHash1: intent.recipientCiphertextHash1,
  };
}

function workflowInput(kind, body, binding) {
  const intent = depositIntent();
  if (kind === "direct-shield") {
    return shieldInput();
  }
  if (kind === "swap-and-shield") {
    return {
      ...shieldInput(),
      tokenIn: "0x5425890298aed601595a70ab815c96711a31bc65",
      amountIn: "0x00000000000000000000000000000000000000000000000000000000000f4240",
      minUsdcOut: "900000",
      deadline: 2_000_000_000,
    };
  }
  if (kind === "private-send") {
    const recipient = decodeHazeAddress(named(loadProtocol(), "haze_address").text);
    return {
      value: 500_000n,
      recipientAddress:
        body.recipient === "foreign" ? { ...recipient, applicationId: APP_B } : recipient,
      outputCommitment0: intent.outputCommitment0,
      outputCommitment1: intent.outputCommitment1,
      recipientCiphertextHash0: intent.recipientCiphertextHash0,
      recipientCiphertextHash1: intent.recipientCiphertextHash1,
      inputNullifier0: `0x${"11".repeat(32)}`,
      inputNullifier1: ZERO32,
    };
  }
  if (kind === "withdraw") {
    return {
      value: 250_000n,
      publicRecipient: "0x6666666666666666666666666666666666666666",
      outputCommitment0: intent.outputCommitment0,
      outputCommitment1: ZERO32,
      recipientCiphertextHash0: intent.recipientCiphertextHash0,
      recipientCiphertextHash1: ZERO32,
      inputNullifier0: `0x${"33".repeat(32)}`,
      inputNullifier1: ZERO32,
    };
  }
  if (kind === "exit-and-reshield") {
    return {
      value: 1_000_000n,
      publicRecipient: WALLET,
      replacementPool: "0x7777777777777777777777777777777777777777",
      replacementPoolVersion: `0x${"cc".repeat(32)}`,
      outputCommitment0: intent.outputCommitment0,
      outputCommitment1: ZERO32,
      recipientCiphertextHash0: intent.recipientCiphertextHash0,
      recipientCiphertextHash1: ZERO32,
      inputNullifier0: `0x${"66".repeat(32)}`,
      inputNullifier1: ZERO32,
    };
  }
  if (kind === "emergency-exit") {
    return {
      value: 1_000_000n,
      publicRecipient: "0x6666666666666666666666666666666666666666",
      nullifier: `0x${"44".repeat(32)}`,
      requestSalt: `0x${"55".repeat(32)}`,
      step: body.step ?? "request",
    };
  }
  return { ...body, binding };
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      if (chunks.length === 0) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch (error) {
        reject(error);
      }
    });
    request.on("error", reject);
  });
}

function send(response, status, body, contentType = "application/json; charset=utf-8") {
  response.writeHead(status, {
    "content-type": contentType,
    "content-security-policy": CSP,
    "cache-control": "no-store",
  });
  response.end(body);
}

function sendJson(response, status, value) {
  send(response, status, `${JSON.stringify(jsonSafe(value))}\n`);
}

function sendHtml(response, status, html) {
  send(response, status, html, "text/html; charset=utf-8");
}

export async function createHost(options = {}) {
  const profile = options.profile ?? "local";
  if (profile === "fuji") {
    const gate = fujiGate();
    if (!gate.ready) {
      const error = new Error(`fuji profile fail-closed: ${gate.reasons.join(",")}`);
      error.code = "FUJI_NOT_READY";
      error.reasons = gate.reasons;
      throw error;
    }
  }
  if (profile !== "local") {
    throw new Error(`unsupported host profile: ${profile}`);
  }

  const services = createLocalServices();
  let lastError = "";
  let lastKind = "direct-shield";
  let lastResult = undefined;
  let governancePreview = undefined;
  let emergencyReady = false;

  function snapshot() {
    const screen = services.dex.screen();
    return {
      profile,
      networkLabel: "local in-process",
      walletStatus: services.dex.walletStatus(),
      role: services.dex.session().role,
      portalRole: services.admin.session().role ?? services.audit.session().role ?? services.governance.session().role,
      phase: services.dex.phase(),
      canSign: screen.canSign,
      warnings: screen.warnings,
      notes: services.dex.notes(),
      history: services.dex.history(),
      txHash: lastResult?.txHash ?? services.dex.history().at(-1)?.txHash,
      requestId: lastResult?.requestId,
      lastError,
      kind: lastKind,
      governanceId: governancePreview?.id,
      path: screen.path,
    };
  }

  async function handleApi(url, request, response) {
    const body = request.method === "GET" ? {} : await readBody(request);
    try {
      if (url.pathname === "/api/state") {
        sendJson(response, 200, snapshot());
        return;
      }
      if (url.pathname === "/api/connect") {
        services.setPendingConnect({
          address: body.address ?? WALLET,
          chainId: Number(body.chainId ?? 43113),
        });
        await services.dex.connect();
        lastError = services.dex.lastError()?.code ?? "";
        sendJson(response, 200, snapshot());
        return;
      }
      if (url.pathname === "/api/preview") {
        lastKind = body.kind ?? lastKind;
        const path = Object.entries(PATH_KIND).find(([, kind]) => kind === lastKind)?.[0];
        if (path) {
          services.dex.navigate(path);
        }
        services.dex.preview(lastKind);
        sendJson(response, 200, snapshot());
        return;
      }
      if (url.pathname === "/api/run") {
        lastKind = body.kind ?? lastKind;
        const path = Object.entries(PATH_KIND).find(([, kind]) => kind === lastKind)?.[0];
        if (path) {
          services.dex.navigate(path);
        }
        const target = lastKind === "emergency-exit" ? services.emergencyDex : services.dex;
        if (lastKind === "emergency-exit" && !emergencyReady) {
          await target.connect();
          emergencyReady = true;
        }
        target.preview(lastKind);
        lastResult = await target.run(lastKind, workflowInput(lastKind, body, services.binding));
        lastError = "";
        sendJson(response, 200, { ...snapshot(), ...lastResult });
        return;
      }
      if (url.pathname === "/api/wipe") {
        await services.dex.wipe();
        sendJson(response, 200, snapshot());
        return;
      }
      if (url.pathname === "/api/recover") {
        await services.dex.recover();
        sendJson(response, 200, snapshot());
        return;
      }
      if (url.pathname === "/api/portal/signin") {
        const session = { role: body.role, applicationId: APP_A };
        const path = body.role === "application-admin" ? "/admin" : body.role === "application-auditor" ? "/audit" : "/governance";
        const workspace =
          body.role === "application-admin"
            ? services.admin
            : body.role === "application-auditor"
              ? services.audit
              : services.governance;
        const decision = workspace.signIn(session);
        lastError = decision.ok ? "" : decision.code;
        sendJson(response, decision.ok ? 200 : 403, { ok: decision.ok, code: decision.code, path });
        return;
      }
      if (url.pathname === "/api/portal/manifest") {
        const manifest = fixtureManifest();
        const registered = await services.admin.registerManifest(manifest, hashManifest(manifest));
        await services.admin.registerKms(["dev-kms-aa"]);
        sendJson(response, 200, { ...registered, manifestHash: registered.hash });
        return;
      }
      if (url.pathname === "/api/portal/delegate") {
        const grant = await services.admin.delegateAuditor({
          auditor: AUDITOR,
          expiresAt: 1_900_000_000,
          capabilities: ["query"],
        });
        sendJson(response, 200, grant);
        return;
      }
      if (url.pathname === "/api/portal/siwe/start") {
        const challenge = await services.audit.startSiwe(AUDITOR);
        sendJson(response, 200, challenge);
        return;
      }
      if (url.pathname === "/api/portal/siwe/complete") {
        const bound = await services.audit.completeSiwe({
          address: AUDITOR,
          signature: "0xsig",
          nonce: body.nonce,
        });
        sendJson(response, 200, bound);
        return;
      }
      if (url.pathname === "/api/portal/export") {
        const exported = await services.audit.exportDisclosure({
          caseId: body.caseId ?? "case-1",
          fields: body.fields ?? ["commitment"],
        });
        sendJson(response, 200, exported);
        return;
      }
      if (url.pathname === "/api/governance/preview") {
        governancePreview = await services.governance.previewSchedule({
          kind: "policy-root",
          target: REGISTRY,
          calldata: "0xdead",
          eta: services.clock.now() + 86_400,
        });
        sendJson(response, 200, governancePreview);
        return;
      }
      if (url.pathname === "/api/governance/execute") {
        const executed = await services.governance.execute({ id: body.id ?? governancePreview?.id });
        sendJson(response, 200, executed);
        return;
      }
      sendJson(response, 404, { code: "NOT_FOUND" });
    } catch (error) {
      const parsed = asError(error);
      lastError = parsed.code ?? "UNAVAILABLE";
      sendJson(response, 409, { code: parsed.code ?? "UNAVAILABLE" });
    }
  }

  function handlePage(url, response) {
    const width = Number(url.searchParams.get("width") ?? 1080);
    if (url.pathname === "/glossary") {
      sendHtml(response, 200, injectChrome(glossaryHtml(), snapshot()));
      return;
    }
    if (url.pathname === "/" || DEX_PATHS.has(url.pathname)) {
      const path = url.pathname === "/" ? "/shield" : url.pathname;
      if (services.dex.walletStatus() === "connected") {
        services.dex.navigate(path);
      }
      const html = renderDexHtml({ ...services.dex.screen(), layout: { mode: width < 720 ? "stack" : "workspace", breakpoint: width < 720 ? "mobile" : "desktop" } });
      sendHtml(response, 200, injectChrome(html, { ...snapshot(), kind: PATH_KIND[path] ?? lastKind }));
      return;
    }
    if (PORTAL_PATHS.has(url.pathname)) {
      const workspace =
        url.pathname === "/admin" ? services.admin : url.pathname === "/audit" ? services.audit : services.governance;
      const current = workspace.session();
      const allowed = authorizeRoute(current, url.pathname, { applicationId: APP_A });
      if (!allowed.ok) {
        sendHtml(
          response,
          403,
          injectChrome(
            `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Forbidden</title></head><body><main id="haze-main"><h1>FORBIDDEN</h1><p>${escapeHtml(allowed.code)}</p></main></body></html>`,
            snapshot(),
          ),
        );
        return;
      }
      const screen = workspace.screen(width);
      const html =
        url.pathname === "/admin"
          ? renderAdminHtml(screen)
          : url.pathname === "/audit"
            ? renderAuditHtml(screen)
            : renderGovernanceHtml(screen);
      sendHtml(response, 200, injectChrome(html, snapshot()));
      return;
    }
    sendHtml(response, 404, "<!DOCTYPE html><title>Not found</title><h1>Not found</h1>");
  }

  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "127.0.0.1"}`);
    if (url.pathname === "/host.js") {
      send(response, 200, hostClientScript(), "text/javascript; charset=utf-8");
      return;
    }
    if (url.pathname === "/health") {
      sendJson(response, 200, { ok: true, profile, stack: assembleStack("local").hash });
      return;
    }
    if (url.pathname.startsWith("/api/")) {
      await handleApi(url, request, response);
      return;
    }
    handlePage(url, response);
  });

  const hostname = options.hostname ?? "127.0.0.1";
  const port = options.port ?? 8787;
  await new Promise((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(port, hostname, () => {
      server.off("error", rejectListen);
      resolveListen();
    });
  });
  const address = server.address();
  const url = `http://${hostname}:${address.port}/`;
  return {
    profile,
    url,
    port: address.port,
    close() {
      return new Promise((resolveClose, rejectClose) => {
        server.close((error) => (error ? rejectClose(error) : resolveClose()));
      });
    },
  };
}

async function main(argv) {
  const profile = argv[0] === "fuji" ? "fuji" : "local";
  if (profile === "fuji") {
    const gate = fujiGate();
    process.stdout.write(`${JSON.stringify({ profile, ...gate }, null, 2)}\n`);
    if (!gate.ready) {
      process.exitCode = 2;
      return;
    }
  }
  const host = await createHost({ profile, hostname: "127.0.0.1", port: Number(process.env.PORT ?? 8787) });
  process.stdout.write(`haze-host ${profile} ${host.url}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main(process.argv.slice(2));
}
