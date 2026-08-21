import { createServer } from "node:http";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  FIXTURE_ACCOUNTS,
  createHazeSite,
  grantForAddress,
  liveOperatorWithdrawAllowed,
  sessionFromAddress,
} from "../web/packages/ui/src/site.ts";
import { renderHazePage } from "../web/packages/ui/src/html.ts";
import {
  encodeLiveDeposit,
  fetchLiveErc20Balance,
  fetchLivePoolCommitmentExists,
  fetchLivePoolNextIndex,
  fetchLiveSnapshot,
  formatUsdc,
  planLiveOperatorShield,
  planLiveShieldDeposit,
} from "../web/packages/ui/src/live-deposit.ts";
import { encodeLiveWithdraw, planLiveOperatorWithdraw } from "../web/packages/ui/src/live-withdraw.ts";
import { DEFAULT_ZKEY } from "./operator-prove.mjs";
import {
  NOTE_SECRET_PATH,
  persistLiveCircuitNote,
  persistLiveCircuitWithdraw,
  planLiveCircuitTransact,
  planUnusedLiveCircuitDeposit,
  proveLiveCircuit,
} from "./operator-circuit-live.mjs";

const ROOT = dirname(fileURLToPath(import.meta.url));
const ROUTES = [
  "/swap",
  "/shield",
  "/send",
  "/withdraw",
  "/history",
  "/emergency-exit",
  "/migrate",
  "/admin",
  "/audit",
  "/governance",
];

const APP_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const EXPECTED_CHAIN = 31337;
const GRANTED_AUDIT_FIELDS = [
  "amount",
  "commitment",
  "user",
  "publicRecipient",
  "applicationPolicyVersion",
  "hazePolicyVersion",
];

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function sidecarOverlay() {
  const live = join(ROOT, "../deployments/fuji-v1.live.json");
  if (!existsSync(live)) {
    return null;
  }
  return readJson(live);
}

function cookieMap(header) {
  const map = new Map();
  for (const part of String(header ?? "").split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key) {
      map.set(key, decodeURIComponent(rest.join("=")));
    }
  }
  return map;
}

function setCookie(name, value) {
  return `${name}=${encodeURIComponent(value)}; Path=/; SameSite=Lax`;
}

export function planOperatorCommercial(input = {}) {
  if (input.productionCeremonyApproved === true) {
    throw Object.assign(new Error("production ceremony stays KEYS_MISSING"), { code: "KEYS_MISSING" });
  }
  if (input.writeCommittedFuji === true || input.flipFujiBroadcast === true) {
    throw Object.assign(new Error("committed fuji-v1.json is immutable"), { code: "SC-09" });
  }
  const zkeyPath = input.zkeyPath ?? DEFAULT_ZKEY;
  const zkeyExists = input.zkeyExists ?? existsSync(zkeyPath);
  if (zkeyExists !== true) {
    throw Object.assign(new Error("operator zkey is missing"), { code: "KEYS_MISSING" });
  }
  return {
    operatorProve: true,
    live: true,
    zkeyPath,
    env: { HAZE_OPERATOR_PROVE: "1" },
    script: "commercial:operator",
  };
}

function notePrivateUsdc(note) {
  if (note?.value == null) {
    return "0.00";
  }
  return formatUsdc(note.value);
}

function auditEnvelopeFromPlan(plan, note = plan?.note) {
  const rawAmount = plan?.intent?.publicAmount ?? plan?.circom?.publicAmount ?? note?.value;
  const amount = rawAmount == null ? "0.00" : formatUsdc(rawAmount);
  return {
    amount,
    commitment: note?.commitment ?? "",
    user: plan?.intent?.user ?? plan?.user ?? "",
    publicRecipient: plan?.intent?.publicRecipient ?? plan?.publicRecipient ?? "",
    applicationPolicyVersion: String(
      plan?.intent?.applicationPolicyVersion ?? plan?.circom?.applicationPolicyVersion ?? 1,
    ),
    hazePolicyVersion: String(plan?.intent?.hazePolicyVersion ?? plan?.circom?.hazePolicyVersion ?? 1),
  };
}

async function planUnusedLiveCircuitDepositFromChain({ overlay, user, amount }) {
  const leafIndex = await fetchLivePoolNextIndex(overlay);
  for (let blinding = 2; blinding < 10_000; blinding += 1) {
    const planned = planUnusedLiveCircuitDeposit({
      user,
      publicAmount: amount,
      leafIndex,
      startBlinding: blinding,
    });
    if (!(await fetchLivePoolCommitmentExists(overlay, planned.note.commitment))) {
      return planned;
    }
  }
  throw Object.assign(new Error("could not find an unused live note"), { code: "COMMITMENT_DUPLICATE" });
}

export function createCommercialHost({
  hostname = "127.0.0.1",
  port = 0,
  operatorProve = false,
  zkeyPath = DEFAULT_ZKEY,
  notePath = NOTE_SECRET_PATH,
  publicUsdc = "—",
  privateUsdc = "0.00",
  poolUsdc = "—",
  liveChainSync = false,
} = {}) {
  const theme = readFileSync(join(ROOT, "../web/packages/ui/src/theme.css"), "utf8");
  const shieldLive = readFileSync(join(ROOT, "../web/packages/ui/src/shield-live.js"), "utf8");
  const withdrawLive = readFileSync(join(ROOT, "../web/packages/ui/src/withdraw-live.js"), "utf8");
  const client = readFileSync(join(ROOT, "../web/packages/ui/src/client.js"), "utf8");
  const plex = readFileSync(join(ROOT, "../web/packages/ui/fonts/plex.css"), "utf8");
  const zkeyExists = existsSync(zkeyPath);
  let initialPrivate = privateUsdc;
  let initialNotes = 0;
  if (existsSync(notePath)) {
    try {
      const stored = JSON.parse(readFileSync(notePath, "utf8"));
      if (stored?.note) {
        if (stored.spent === true) {
          const remaining = BigInt(stored.note.value) - BigInt(stored.withdrawal?.amount ?? stored.note.value);
          initialPrivate = formatUsdc(remaining);
          initialNotes = remaining > 0n ? 1 : 0;
        } else {
          initialPrivate = notePrivateUsdc(stored.note);
          initialNotes = 1;
        }
      }
    } catch {
      /* ignore unreadable local vault */
    }
  }
  const hatchOpen = () =>
    liveOperatorWithdrawAllowed({
      path: "/withdraw",
      live: true,
      operatorProve,
      zkeyExists,
    });

  const state = {
    address: "",
    chainId: EXPECTED_CHAIN,
    reviewed: false,
    phase: "idle",
    notes: initialNotes,
    lastError: "",
    quote: "1.00",
    publicUsdc,
    privateUsdc: initialPrivate,
    poolUsdc,
    admin: {
      manifestHash: "none",
      kmsHealth: "ok",
      gatekeeperSigner: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      cases: [],
      grants: [],
    },
    audit: {
      boundWallet: "",
      cases: [{ caseId: "case-1", title: "SAR-1" }],
      access: [],
      rows: [],
      envelope: null,
    },
    governance: {
      previewTarget: "0x1111111111111111111111111111111111111111",
      timelock: "0x2222222222222222222222222222222222222222",
      ceremonyProduction: false,
      emergency: "inactive",
    },
  };

  function sessionFor(address, roleHint) {
    if (address) {
      return sessionFromAddress(address, { applicationId: APP_A });
    }
    if (roleHint) {
      return { role: roleHint, applicationId: APP_A };
    }
    return { role: null, applicationId: APP_A };
  }

  function walletStatus() {
    if (!state.address) {
      return "disconnected";
    }
    if (Number(state.chainId) !== EXPECTED_CHAIN && Number(state.chainId) !== 43113) {
      return "wrong-chain";
    }
    return "connected";
  }

  function pageHtml(path, live, requestAddress) {
    const address = requestAddress ?? state.address;
    const granted = grantForAddress(address);
    const session = granted
      ? { role: granted.role, applicationId: APP_A }
      : sessionFor(address);
    const effective = createHazeSite(
      session.role ? session : { role: "pool-user", applicationId: APP_A },
    );
    const status = !address
      ? "disconnected"
      : Number(state.chainId) !== EXPECTED_CHAIN && Number(state.chainId) !== 43113
        ? "wrong-chain"
        : "connected";
    return renderHazePage(effective, path, {
      live,
      operatorProve,
      zkeyExists,
      address: address || null,
      walletStatus: status,
      reviewed: state.reviewed,
      phase: state.phase,
      notes: state.notes,
      lastError: state.lastError,
      quote: state.quote,
      publicUsdc: state.publicUsdc,
      privateUsdc: state.privateUsdc,
      poolUsdc: state.poolUsdc,
      admin: state.admin,
      audit: state.audit,
      governance: state.governance,
    });
  }

  function readBody(request) {
    return new Promise((resolve) => {
      const chunks = [];
      request.on("data", (chunk) => chunks.push(chunk));
      request.on("end", () => {
        if (chunks.length === 0) {
          resolve({});
          return;
        }
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
        } catch {
          resolve({});
        }
      });
    });
  }

  function send(response, status, body, type, extra = {}) {
    response.writeHead(status, {
      "content-type": type,
      "content-security-policy":
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; font-src 'self'",
      ...extra,
    });
    response.end(body);
  }

  const server = createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", `http://${request.headers.host}`);
    const cookies = cookieMap(request.headers.cookie);
    const roleHint = url.searchParams.get("role");
    const roleAddress = roleHint
      ? (FIXTURE_ACCOUNTS.find((item) => item.role === roleHint)?.address ?? "")
      : "";
    const requestAddress =
      url.searchParams.get("address") || cookies.get("haze-address") || roleAddress;
    const apiAddress = cookies.get("haze-address") || requestAddress;
    if (url.searchParams.get("reviewed") === "1") {
      state.reviewed = true;
    }

    if (url.pathname === "/theme.css") {
      send(response, 200, theme, "text/css; charset=utf-8");
      return;
    }
    if (url.pathname === "/fonts/plex.css") {
      send(response, 200, plex, "text/css; charset=utf-8");
      return;
    }
    if (url.pathname.startsWith("/fonts/") && url.pathname.endsWith(".woff2")) {
      const name = url.pathname.slice("/fonts/".length);
      if (!/^[A-Za-z0-9-]+\.woff2$/.test(name)) {
        send(response, 404, "not found", "text/plain; charset=utf-8");
        return;
      }
      const fontPath = join(ROOT, "../web/packages/ui/fonts", name);
      try {
        send(response, 200, readFileSync(fontPath), "font/woff2");
      } catch {
        send(response, 404, "not found", "text/plain; charset=utf-8");
      }
      return;
    }
    if (url.pathname === "/client.js") {
      send(response, 200, client, "text/javascript; charset=utf-8");
      return;
    }
    if (url.pathname === "/shield-live.js") {
      send(response, 200, shieldLive, "text/javascript; charset=utf-8");
      return;
    }
    if (url.pathname === "/withdraw-live.js") {
      if (!hatchOpen()) {
        send(response, 404, "not found", "text/plain; charset=utf-8");
        return;
      }
      send(response, 200, withdrawLive, "text/javascript; charset=utf-8");
      return;
    }

    if (request.method === "POST" && url.pathname === "/api/connect") {
      const body = await readBody(request);
      state.address = body.address ?? "";
      state.chainId = Number(body.chainId ?? EXPECTED_CHAIN);
      state.lastError = walletStatus() === "wrong-chain" ? "CHAIN_MISMATCH" : "";
      send(response, 200, JSON.stringify({ ok: true, address: state.address, walletStatus: walletStatus() }), "application/json", {
        "set-cookie": setCookie("haze-address", state.address),
      });
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/disconnect") {
      state.address = "";
      state.reviewed = false;
      send(response, 200, JSON.stringify({ ok: true }), "application/json", {
        "set-cookie": setCookie("haze-address", ""),
      });
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/preview") {
      state.reviewed = true;
      state.phase = "preview";
      send(response, 200, JSON.stringify({ ok: true, reviewed: true }), "application/json");
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/run") {
      const body = await readBody(request);
      const grant = grantForAddress(apiAddress);
      if (grant?.role !== "pool-user" || !state.reviewed) {
        state.lastError = "REJECTED";
        send(response, 200, JSON.stringify({ ok: false, code: "REJECTED" }), "application/json");
        return;
      }
      if (body.kind && body.kind !== "direct-shield") {
        state.lastError = "KEYS_MISSING";
        state.phase = "failed";
        send(response, 200, JSON.stringify({ ok: false, code: "KEYS_MISSING" }), "application/json");
        return;
      }
      state.phase = "finalized";
      state.notes += 1;
      state.lastError = "";
      send(response, 200, JSON.stringify({ ok: true, phase: state.phase, notes: state.notes }), "application/json");
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/wipe") {
      state.notes = 0;
      send(response, 200, JSON.stringify({ ok: true, notes: 0 }), "application/json");
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/recover") {
      state.notes = Math.max(state.notes, 1);
      send(response, 200, JSON.stringify({ ok: true, notes: state.notes }), "application/json");
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/portal/manifest") {
      if (grantForAddress(apiAddress)?.role !== "application-admin") {
        send(response, 403, JSON.stringify({ code: "UNAUTHORIZED" }), "application/json");
        return;
      }
      state.admin.manifestHash = "0xmanifest";
      send(response, 200, JSON.stringify({ ok: true }), "application/json");
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/portal/delegate") {
      if (grantForAddress(apiAddress)?.role !== "application-admin") {
        send(response, 403, JSON.stringify({ code: "UNAUTHORIZED" }), "application/json");
        return;
      }
      state.admin.grants.push({
        grantId: `grant-${state.admin.grants.length + 1}`,
        auditor: FIXTURE_ACCOUNTS[2].address,
        revoked: false,
      });
      send(response, 200, JSON.stringify({ ok: true }), "application/json");
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/portal/revoke") {
      const grant = state.admin.grants.at(-1);
      if (grant) {
        grant.revoked = true;
      }
      send(response, 200, JSON.stringify({ ok: true }), "application/json");
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/portal/case") {
      state.admin.cases.push({ caseId: `case-${state.admin.cases.length + 1}`, title: "Review" });
      send(response, 200, JSON.stringify({ ok: true }), "application/json");
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/portal/siwe/start") {
      send(response, 200, JSON.stringify({ nonce: "siwe-nonce" }), "application/json");
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/portal/siwe/complete") {
      if (grantForAddress(apiAddress)?.role !== "application-auditor") {
        send(response, 403, JSON.stringify({ code: "UNAUTHORIZED" }), "application/json");
        return;
      }
      state.audit.boundWallet = state.address;
      send(response, 200, JSON.stringify({ ok: true }), "application/json");
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/portal/export") {
      const body = await readBody(request);
      const allowed = grantForAddress(apiAddress)?.role === "application-auditor" ||
        grantForAddress(apiAddress)?.role === "application-admin";
      const fields = Array.isArray(body.fields) ? body.fields : ["commitment"];
      const overreach = fields.some((field) => !GRANTED_AUDIT_FIELDS.includes(field));
      if (!allowed || overreach) {
        state.audit.access.push({ action: "export", allowed: false });
        send(response, 403, JSON.stringify({ code: "UNAUTHORIZED" }), "application/json");
        return;
      }
      const envelope = state.audit.envelope ?? { commitment: "0xcc" };
      const row = {};
      for (const field of fields) {
        row[field] = envelope[field] ?? (field === "commitment" ? "0xcc" : "");
      }
      state.audit.rows = fields.map((field) => ({ field, value: String(row[field] ?? "") }));
      state.audit.access.push({ action: "export", allowed: true });
      send(response, 200, JSON.stringify({ ok: true, rows: [row] }), "application/json");
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/live-balances") {
      const overlay = sidecarOverlay();
      try {
        if (overlay?.broadcast === true) {
          const holder = overlay.addresses?.HazePool;
          if (holder) {
            const pool = await fetchLiveErc20Balance(overlay, holder);
            state.poolUsdc = pool.formatted;
          }
          if (state.address) {
            const pub = await fetchLiveErc20Balance(overlay, state.address);
            state.publicUsdc = pub.formatted;
          }
        }
      } catch {
        /* fail-closed display stays at last known figures */
      }
      send(
        response,
        200,
        JSON.stringify({
          publicUsdc: state.publicUsdc,
          privateUsdc: state.privateUsdc,
          poolUsdc: state.poolUsdc,
        }),
        "application/json",
      );
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/governance/preview") {
      if (grantForAddress(apiAddress)?.role !== "super-auditor") {
        send(response, 403, JSON.stringify({ code: "UNAUTHORIZED" }), "application/json");
        return;
      }
      send(response, 200, JSON.stringify({ ok: true, target: state.governance.previewTarget }), "application/json");
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/governance/execute") {
      send(response, 403, JSON.stringify({ code: "TIMELOCK" }), "application/json");
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/live-deposit/plan") {
      const body = await readBody(request);
      const overlay = sidecarOverlay();
      if (!overlay) {
        send(response, 200, JSON.stringify({ allowed: false, reason: "SIDECAR_MISSING" }), "application/json");
        return;
      }
      try {
        if (hatchOpen()) {
          const planned = liveChainSync
            ? await planUnusedLiveCircuitDepositFromChain({
                overlay,
                user: body.user,
                amount: Number(body.amount ?? 1_000_000),
              })
            : planUnusedLiveCircuitDeposit({
                user: body.user,
                publicAmount: Number(body.amount ?? 1_000_000),
              });
          const plan = planLiveOperatorShield({
            path: "/shield",
            live: true,
            operatorProve,
            zkeyExists,
            sidecar: overlay,
            user: body.user,
            amount: Number(body.amount ?? 1_000_000),
            now: Math.floor(Date.now() / 1000),
            witness: planned,
          });
          send(response, 200, JSON.stringify({ ...plan, circuitPlan: planned }), "application/json");
          return;
        }
        const snapshot = await fetchLiveSnapshot(overlay);
        const plan = planLiveShieldDeposit({
          path: "/shield",
          live: true,
          sidecar: overlay,
          user: body.user,
          amount: Number(body.amount ?? 1_000_000),
          now: Math.floor(Date.now() / 1000),
          snapshot,
        });
        send(response, 200, JSON.stringify(plan), "application/json");
      } catch {
        send(response, 200, JSON.stringify({ allowed: false, reason: "SNAPSHOT_MISSING" }), "application/json");
      }
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/live-deposit/prove") {
      if (!hatchOpen()) {
        send(response, 200, JSON.stringify({ allowed: false, reason: "KEYS_MISSING" }), "application/json");
        return;
      }
      const body = await readBody(request);
      const overlay = sidecarOverlay();
      try {
        const result = await proveLiveCircuit({
          action: "deposit",
          user: body.user,
          publicAmount: Number(body.amount ?? 1_000_000),
          leafIndex: body.leafIndex,
          blinding: body.blinding,
          zkeyPath,
          notePath,
          skipPersist: true,
        });
        send(
          response,
          200,
          JSON.stringify({
            allowed: true,
            proofBytes: result.artifact.proofBytes,
            publicSignals: result.artifact.publicSignals,
          }),
          "application/json",
        );
      } catch (error) {
        send(
          response,
          200,
          JSON.stringify({ allowed: false, reason: error?.code ?? "KEYS_MISSING" }),
          "application/json",
        );
      }
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/live-deposit/persist") {
      if (!hatchOpen()) {
        send(response, 200, JSON.stringify({ allowed: false, reason: "KEYS_MISSING" }), "application/json");
        return;
      }
      const body = await readBody(request);
      try {
        persistLiveCircuitNote({ plan: body.plan, notePath });
        state.notes = Math.max(state.notes, 1);
        state.privateUsdc = notePrivateUsdc(body.plan?.note);
        state.audit.envelope = auditEnvelopeFromPlan(body.plan);
        if (!state.audit.cases.some((item) => item.caseId === "case-live-1")) {
          state.audit.cases.push({ caseId: "case-live-1", title: "Fuji operator shield" });
        }
        send(response, 200, JSON.stringify({ allowed: true, privateUsdc: state.privateUsdc }), "application/json");
      } catch (error) {
        send(
          response,
          200,
          JSON.stringify({ allowed: false, reason: error?.code ?? "WITNESS_INVALID" }),
          "application/json",
        );
      }
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/live-deposit/encode") {
      const body = await readBody(request);
      send(response, 200, JSON.stringify(encodeLiveDeposit(body)), "application/json");
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/live-withdraw/plan") {
      if (!hatchOpen()) {
        send(response, 200, JSON.stringify({ allowed: false, reason: "KEYS_MISSING" }), "application/json");
        return;
      }
      const body = await readBody(request);
      const overlay = sidecarOverlay();
      if (!overlay || !existsSync(notePath)) {
        send(response, 200, JSON.stringify({ allowed: false, reason: "SIDECAR_MISSING" }), "application/json");
        return;
      }
      try {
        const stored = JSON.parse(readFileSync(notePath, "utf8"));
        if (stored?.spent === true) {
          throw Object.assign(new Error("circuit note has already been withdrawn"), { code: "NOTE_SPENT" });
        }
        const planned = planLiveCircuitTransact({
          action: "withdraw",
          note: stored.note,
          treeLeaves: stored.treeLeaves,
          user: body.user,
          publicAmount: Number(body.amount ?? stored.note.value),
          publicRecipient: body.recipient || body.user,
        });
        const plan = planLiveOperatorWithdraw({
          path: "/withdraw",
          live: true,
          operatorProve,
          zkeyExists,
          sidecar: overlay,
          user: body.user,
          amount: Number(body.amount ?? stored.note.value),
          recipient: body.recipient || body.user,
          now: Math.floor(Date.now() / 1000),
          witness: planned,
        });
        send(response, 200, JSON.stringify(plan), "application/json");
      } catch (error) {
        send(
          response,
          200,
          JSON.stringify({ allowed: false, reason: error?.code ?? "WITNESS_INVALID" }),
          "application/json",
        );
      }
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/live-withdraw/prove") {
      if (!hatchOpen()) {
        send(response, 200, JSON.stringify({ allowed: false, reason: "KEYS_MISSING" }), "application/json");
        return;
      }
      const body = await readBody(request);
      if (!existsSync(notePath)) {
        send(response, 200, JSON.stringify({ allowed: false, reason: "KEYS_MISSING" }), "application/json");
        return;
      }
      try {
        const stored = JSON.parse(readFileSync(notePath, "utf8"));
        const result = await proveLiveCircuit({
          action: "withdraw",
          note: stored.note,
          treeLeaves: stored.treeLeaves,
          user: body.user,
          publicAmount: Number(body.amount ?? stored.note.value),
          publicRecipient: body.recipient || body.user,
          zkeyPath,
        });
        send(
          response,
          200,
          JSON.stringify({
            allowed: true,
            proofBytes: result.artifact.proofBytes,
            publicSignals: result.artifact.publicSignals,
          }),
          "application/json",
        );
      } catch (error) {
        send(
          response,
          200,
          JSON.stringify({ allowed: false, reason: error?.code ?? "KEYS_MISSING" }),
          "application/json",
        );
      }
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/live-withdraw/encode") {
      if (!hatchOpen()) {
        send(response, 200, JSON.stringify({ allowed: false, reason: "KEYS_MISSING" }), "application/json");
        return;
      }
      const body = await readBody(request);
      send(response, 200, JSON.stringify(encodeLiveWithdraw(body)), "application/json");
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/live-withdraw/persist") {
      if (!hatchOpen()) {
        send(response, 200, JSON.stringify({ allowed: false, reason: "KEYS_MISSING" }), "application/json");
        return;
      }
      const body = await readBody(request);
      try {
        const stored = persistLiveCircuitWithdraw({
          plan: body.plan,
          receipt: body.receipt,
          notePath,
        });
        state.privateUsdc = "0.00";
        state.notes = 0;
        state.audit.envelope = auditEnvelopeFromPlan(body.plan, stored.note);
        if (!state.audit.cases.some((item) => item.caseId === "case-live-1")) {
          state.audit.cases.push({ caseId: "case-live-1", title: "Fuji operator withdraw" });
        }
        send(response, 200, JSON.stringify({ allowed: true, privateUsdc: state.privateUsdc }), "application/json");
      } catch (error) {
        send(
          response,
          200,
          JSON.stringify({ allowed: false, reason: error?.code ?? "WITNESS_INVALID" }),
          "application/json",
        );
      }
      return;
    }

    let path = url.pathname;
    if (path === "/") {
      const site = createHazeSite(sessionFor(requestAddress, roleHint));
      path = site.homePath();
      response.writeHead(302, { location: path });
      response.end();
      return;
    }
    if (!ROUTES.includes(path)) {
      send(response, 404, "not found", "text/plain");
      return;
    }
    const htmlHeaders = requestAddress
      ? { "set-cookie": setCookie("haze-address", requestAddress) }
      : {};
    send(
      response,
      200,
      pageHtml(path, url.searchParams.get("live") === "1", requestAddress),
      "text/html; charset=utf-8",
      htmlHeaders,
    );
  });

  if (operatorProve) {
    server.timeout = 30 * 60 * 1000;
    server.headersTimeout = 31 * 60 * 1000;
    server.requestTimeout = 30 * 60 * 1000;
  }

  return new Promise((resolve) => {
    server.listen(port, hostname, () => {
      const address = server.address();
      const actualPort = typeof address === "object" && address ? address.port : port;
      resolve({
        url: `http://${hostname}:${actualPort}`,
        close: () =>
          new Promise((done) => {
            state.address = "";
            state.reviewed = false;
            server.close(() => done());
          }),
      });
    });
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const operatorProve = process.env.HAZE_OPERATOR_PROVE === "1";
  if (operatorProve) {
    planOperatorCommercial({ zkeyPath: DEFAULT_ZKEY });
  }
  const host = await createCommercialHost({
    port: Number(process.env.PORT ?? 3010),
    operatorProve,
    liveChainSync: operatorProve,
  });
  console.log(`haze commercial ${host.url}`);
}
