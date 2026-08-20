#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { assembleStack } from "./stack.mjs";
import { decodeHazeAddress } from "../sdk/typescript/src/address.ts";
import { EMERGENCY_EXIT_COOLDOWN } from "../sdk/typescript/src/emergency.ts";
import { encodeEnvelope } from "../sdk/typescript/src/envelope.ts";
import { intentStructHash } from "../sdk/typescript/src/eip712.ts";
import { SdkError } from "../sdk/typescript/src/errors.ts";
import { createGatekeeperClient } from "../sdk/typescript/src/gatekeeper.ts";
import { recipientAad, sealRecipientNote } from "../sdk/typescript/src/hpke.ts";
import { HAZE_PRODUCT_ID } from "../sdk/typescript/src/identity.ts";
import { hashManifest } from "../sdk/typescript/src/manifest.ts";
import { noteCommitment } from "../sdk/typescript/src/note.ts";
import { createStaticQuoteAdapter, createUnavailableQuoteAdapter } from "../sdk/typescript/src/quote.ts";
import { deriveVaultAccount } from "../sdk/typescript/src/vault.ts";
import { createDexApp } from "../apps/privacy-pool-dex/src/index.ts";
import {
  authorizeApi,
  authorizeRoute,
  createAdminWorkspace,
  createAuditWorkspace,
  createGovernanceWorkspace,
  lintPrivacyCopy,
  renderAdminHtml,
  renderAuditHtml,
  renderGovernanceHtml,
} from "../apps/compliance-portal/src/index.ts";
import { renderDexHtml } from "../apps/privacy-pool-dex/src/app.ts";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PROTOCOL = join(HAZE_ROOT, "circuits/vectors/v1/haze-protocol-v1.json");
const APP_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const APP_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ZERO32 = `0x${"00".repeat(32)}`;
const WALLET = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf";
const SIGNING_KEY = "0x0000000000000000000000000000000000000000000000000000000000000001";
const AUDITOR = "0x2222222222222222222222222222222222222222";
const REGISTRY = "0x1111111111111111111111111111111111111111";
const TIMELOCK = "0x2222222222222222222222222222222222222222";

export const SCENARIO_IDS = [
  "E2E-01",
  "E2E-02",
  "E2E-03",
  "E2E-04",
  "E2E-05",
  "E2E-06",
  "E2E-07",
  "E2E-08",
  "E2E-09",
  "E2E-10",
  "E2E-11",
  "E2E-12",
  "E2E-13",
];

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
  return {
    chainId: 43113,
    pool: "0x1111111111111111111111111111111111111111",
    router: "0x4444444444444444444444444444444444444444",
    exit: "0x5555555555555555555555555555555555555555",
    applicationId,
    poolVersion: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  };
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
  const current = {
    noteTreeRoot: intent.noteTreeRoot,
    applicationPolicyVersion: intent.applicationPolicyVersion,
    hazePolicyVersion: intent.hazePolicyVersion,
    applicationMembershipRoot: intent.applicationMembershipRoot,
    hazeBlocklistRoot: intent.hazeBlocklistRoot,
  };
  return {
    async snapshot() {
      return { ...current };
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

function createConnector() {
  return {
    async connect() {
      return { address: WALLET, chainId: 43113, signingKey: SIGNING_KEY };
    },
    async disconnect() {},
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

function createApp(overrides = {}) {
  const binding = fixtureBinding(overrides.applicationId ?? APP_A);
  const clock = overrides.clock ?? createClock();
  return {
    clock,
    app: createDexApp({
      ...binding,
      expectedChainId: binding.chainId,
      connector: overrides.connector ?? createConnector(),
      wallet: overrides.wallet ?? createWallet(),
      gatekeeper: overrides.gatekeeper ?? createAuthGatekeeper(overrides.gatekeeperOptions),
      quotes: overrides.quotes,
      policy: overrides.policy ?? createPolicy(),
      finality: overrides.finality ?? createFinality(),
      clock: clock.now.bind(clock),
      noteEvents: overrides.noteEvents ?? [],
    }),
  };
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

function expect(condition, code, detail) {
  if (!condition) {
    const error = new Error(detail ?? code);
    error.code = code;
    throw error;
  }
}

async function expectRejects(fn, code) {
  try {
    await fn();
  } catch (error) {
    expect(error.code === code, code, `expected ${code}, got ${error.code}`);
    return;
  }
  expect(false, code, `expected rejection ${code}`);
}

const SECRET_KEYS = /signingKey|x25519Secret|secret|privateKey|ikm/i;
const SECRET_VALUES = /0x0000000000000000000000000000000000000000000000000000000000000001/;

export function redactEvidence(value) {
  if (Array.isArray(value)) {
    return value.map(redactEvidence);
  }
  if (value && typeof value === "object") {
    const out = {};
    for (const [key, entry] of Object.entries(value)) {
      out[key] = SECRET_KEYS.test(key) ? "[redacted]" : redactEvidence(entry);
    }
    return out;
  }
  if (typeof value === "string" && SECRET_VALUES.test(value)) {
    return "[redacted]";
  }
  return value;
}

async function e2e01() {
  const { app } = createApp();
  await app.connect();
  app.navigate("/shield");
  const preview = app.preview("direct-shield");
  expect(preview.warnings.some((item) => item.fact === "deposit-amount"), "PUBLIC_WARNING");
  const result = await app.run("direct-shield", shieldInput());
  expect(result.phase === "finalized", "FINALITY");
  expect(app.notes()[0]?.visibility === "private", "PRIVATE_NOTE");
}

async function e2e02() {
  const quotes = createStaticQuoteAdapter({
    usdcOut: "1000000",
    adapter: "0x3333333333333333333333333333333333333333",
    data: "0xaabb",
    gasEstimate: 180000,
  });
  const { app } = createApp({ quotes });
  await app.connect();
  app.navigate("/swap");
  await app.quote({
    tokenIn: "0x5425890298aed601595a70ab815c96711a31bc65",
    amountIn: "0x00000000000000000000000000000000000000000000000000000000000f4240",
    minUsdcOut: "900000",
    deadline: 2_000_000_000,
  });
  const preview = app.preview("swap-and-shield");
  expect(preview.warnings.some((item) => item.fact === "source-token-swap"), "PUBLIC_WARNING");
  const result = await app.run("swap-and-shield", {
    ...shieldInput(),
    tokenIn: "0x5425890298aed601595a70ab815c96711a31bc65",
    amountIn: "0x00000000000000000000000000000000000000000000000000000000000f4240",
    minUsdcOut: "900000",
    deadline: 2_000_000_000,
  });
  expect(result.phase === "finalized", "FINALITY");
  expect(app.notes()[0]?.visibility === "private", "PRIVATE_NOTE");
}

async function e2e03() {
  const recipientAccount = deriveVaultAccount({
    ...fixtureBinding(),
    wallet: WALLET,
    signingKey: SIGNING_KEY,
  });
  const event = sealedEvent(recipientAccount);
  const sender = createApp();
  const recipient = createApp({ noteEvents: [event] });
  await sender.app.connect();
  await recipient.app.connect();
  sender.app.navigate("/send");
  sender.app.preview("private-send");
  const sent = await sender.app.run("private-send", {
    value: 500_000n,
    recipientAddress: decodeHazeAddress(named(loadProtocol(), "haze_address").text),
    outputCommitment0: depositIntent().outputCommitment0,
    outputCommitment1: depositIntent().outputCommitment1,
    recipientCiphertextHash0: depositIntent().recipientCiphertextHash0,
    recipientCiphertextHash1: depositIntent().recipientCiphertextHash1,
    inputNullifier0: `0x${"11".repeat(32)}`,
    inputNullifier1: ZERO32,
  });
  expect(sent.phase === "finalized", "FINALITY");
  await recipient.app.recover();
  expect(recipient.app.notes().some((note) => note.commitment === event.commitment), "RECIPIENT_NOTE");
  expect(sender.app.notes().every((note) => note.commitment !== event.commitment), "SENDER_BLIND");
}

async function e2e04() {
  const { app } = createApp();
  await app.connect();
  app.navigate("/withdraw");
  const preview = app.preview("withdraw");
  expect(preview.warnings.some((item) => item.fact === "withdrawal-amount"), "PUBLIC_WARNING");
  const result = await app.run("withdraw", {
    value: 250_000n,
    publicRecipient: "0x6666666666666666666666666666666666666666",
    outputCommitment0: depositIntent().outputCommitment0,
    outputCommitment1: ZERO32,
    recipientCiphertextHash0: depositIntent().recipientCiphertextHash0,
    recipientCiphertextHash1: ZERO32,
    inputNullifier0: `0x${"33".repeat(32)}`,
    inputNullifier1: ZERO32,
  });
  expect(result.phase === "finalized", "FINALITY");
}

async function e2e05() {
  const userA = { role: "pool-user", applicationId: APP_A };
  expect(authorizeRoute("compliance-portal", userA, "/admin").ok === false, "PORTAL_NAV");
  expect(
    authorizeApi("compliance-portal", userA, "GET", "/v1/disclosures/query", { applicationId: APP_B })
      .code === "APPLICATION_MISMATCH" ||
      authorizeApi("compliance-portal", userA, "GET", "/v1/disclosures/query").ok === false,
    "ISOLATION",
  );
  const { app } = createApp();
  await app.connect();
  app.preview("private-send");
  const recipient = decodeHazeAddress(named(loadProtocol(), "haze_address").text);
  await expectRejects(
    () =>
      app.run("private-send", {
        value: 1n,
        recipientAddress: { ...recipient, applicationId: APP_B },
        outputCommitment0: depositIntent().outputCommitment0,
        inputNullifier0: `0x${"22".repeat(32)}`,
      }),
    "APPLICATION_MISMATCH",
  );
}

async function e2e06() {
  const manifest = {
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
  const grants = [];
  const cases = [];
  const workspace = createAdminWorkspace({
    applicationId: APP_A,
    auditAuth: {
      async delegate(input) {
        const grant = { grantId: "grant-1", ...input, revoked: false };
        grants.push(grant);
        return grant;
      },
      async revoke({ grantId }) {
        const grant = grants.find((item) => item.grantId === grantId);
        grant.revoked = true;
        return grant;
      },
      async createCase(input) {
        const record = { caseId: "case-1", ...input, applicationId: APP_A };
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
        return [{ applicationId, txHash: "0xaaa1", kind: "deposit" }].filter(
          (item) => item.applicationId === applicationId,
        );
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
  expect(workspace.signIn({ role: "application-admin", applicationId: APP_A }).ok, "ADMIN_AUTH");
  await workspace.registerManifest(manifest, hashManifest(manifest));
  await workspace.registerKms(["dev-kms-aa"]);
  const grant = await workspace.delegateAuditor({
    auditor: AUDITOR,
    expiresAt: 1_900_000_000,
    capabilities: ["query"],
  });
  const reports = await workspace.transactionReports();
  expect(reports.every((item) => item.applicationId === APP_A), "APP_SCOPE");
  await workspace.revokeAccess({ grantId: grant.grantId });
  expect(grants[0].revoked === true, "REVOKE");
}

async function e2e07() {
  const log = [];
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
  const workspace = createAuditWorkspace({
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
        log.push({ action: "query", caseId, allowed: true });
        return { rows: [{ caseId, commitment: "0xcc" }] };
      },
      async export({ caseId, fields, applicationId, grant }) {
        const queried = await this.query({ caseId, fields, applicationId, grant });
        log.push({ action: "export", caseId, allowed: true });
        return { caseId, fields, applicationId, rows: queried.rows };
      },
      async accessLog() {
        return [...log];
      },
    },
  });
  const challenge = await workspace.startSiwe(AUDITOR);
  await workspace.completeSiwe({ address: AUDITOR, signature: "0xsig", nonce: challenge.nonce });
  expect(workspace.signIn({ role: "application-auditor", applicationId: APP_A }).ok, "AUDITOR_AUTH");
  await workspace.search({ caseId: "case-1", fields: ["commitment"] });
  await expectRejects(() => workspace.search({ caseId: "case-1", fields: ["plaintext"] }), "UNAUTHORIZED");
  await workspace.exportDisclosure({ caseId: "case-1", fields: ["commitment"] });
  const history = await workspace.accessHistory();
  expect(history.some((item) => item.allowed), "ACCESS_ALLOWED");
  expect(history.some((item) => item.allowed === false), "ACCESS_DENIED");
}

async function e2e08() {
  const schedules = [];
  let now = 1_000;
  const workspace = createGovernanceWorkspace({
    applicationId: APP_A,
    clock: () => now,
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
          versions: {
            pool: "1.0.0",
            artifactHash: `0x${"ab".repeat(32)}`,
            provenance: "development",
          },
          ceremony: { transcriptHash: `0x${"cd".repeat(32)}`, production: false },
        };
      },
    },
  });
  expect(workspace.signIn({ role: "super-auditor", applicationId: APP_A }).ok, "GOV_AUTH");
  const preview = await workspace.previewSchedule({
    kind: "policy-root",
    target: REGISTRY,
    calldata: "0xdead",
    eta: 86_400,
  });
  expect(preview.target === REGISTRY && preview.timelock === TIMELOCK, "PREVIEW");
  const scheduled = await workspace.schedule();
  await expectRejects(() => workspace.execute({ id: scheduled.id }), "TIMELOCK");
  now = 86_400;
  const executed = await workspace.execute({ id: scheduled.id });
  expect(executed.executed === true, "EXECUTE");
  const status = await workspace.protocolStatus();
  expect(status.versions.provenance === "development", "PROVENANCE");
  const grant = await workspace.grantSuperAuditor({ wallet: AUDITOR });
  expect(grant.custody === false, "NO_CUSTODY");
}

async function e2e09() {
  const { app, clock } = createApp({ gatekeeperOptions: { deny: "USER_INELIGIBLE" } });
  await app.connect();
  app.navigate("/emergency-exit");
  app.preview("emergency-exit");
  const input = {
    value: 1_000_000n,
    publicRecipient: "0x6666666666666666666666666666666666666666",
    nullifier: `0x${"44".repeat(32)}`,
    requestSalt: `0x${"55".repeat(32)}`,
  };
  const requested = await app.run("emergency-exit", { ...input, step: "request" });
  expect(Boolean(requested.requestId), "REQUEST");
  await expectRejects(() => app.run("emergency-exit", { ...input, step: "execute" }), "TIMELOCK");
  clock.advance(EMERGENCY_EXIT_COOLDOWN);
  const executed = await app.run("emergency-exit", { ...input, step: "execute" });
  expect(executed.phase === "finalized", "FINALITY");
}

async function e2e10() {
  const account = deriveVaultAccount({
    ...fixtureBinding(),
    wallet: WALLET,
    signingKey: SIGNING_KEY,
  });
  const event = sealedEvent(account);
  const { app } = createApp({ noteEvents: [event] });
  await app.connect();
  await app.recover();
  expect(app.notes().length === 1, "RECOVERED");
  await app.wipe();
  expect(app.notes().length === 0, "WIPED");
  await app.recover();
  expect(app.notes().length === 1 && app.notes()[0].commitment === event.commitment, "REPLAY");
}

async function e2e11() {
  const quotes = createStaticQuoteAdapter({
    usdcOut: "1000000",
    adapter: "0x3333333333333333333333333333333333333333",
    data: "0xaabb",
    gasEstimate: 180000,
  });
  const stale = createApp({ quotes });
  await stale.app.connect();
  stale.app.preview("swap-and-shield");
  await expectRejects(
    () =>
      stale.app.run("swap-and-shield", {
        ...shieldInput(),
        tokenIn: "0x5425890298aed601595a70ab815c96711a31bc65",
        amountIn: `0x${"00".repeat(32)}`,
        minUsdcOut: "2000000",
        deadline: 2_000_000_000,
      }),
    "QUOTE_STALE",
  );
  const down = createApp({ quotes: createUnavailableQuoteAdapter() });
  await down.app.connect();
  await expectRejects(
    () =>
      down.app.quote({
        tokenIn: "0x5425890298aed601595a70ab815c96711a31bc65",
        amountIn: `0x${"00".repeat(31)}01`,
        minUsdcOut: "1",
        deadline: 1,
      }),
    "UNAVAILABLE",
  );
}

async function e2e12() {
  const { app } = createApp();
  await app.connect();
  app.navigate("/shield");
  app.preview("direct-shield");
  const html = renderDexHtml(app.screen());
  expect(lintPrivacyCopy(html).length === 0, "DEX_COPY");
  const admin = createAdminWorkspace({
    applicationId: APP_A,
    auditAuth: {
      async delegate() {
        return {};
      },
      async revoke() {
        return {};
      },
      async createCase() {
        return {};
      },
      async listCases() {
        return [];
      },
    },
    disclosure: {
      async export() {
        return {};
      },
    },
    indexer: {
      async queryApplication() {
        return [];
      },
    },
    health: {
      async kms() {
        return { status: "ok", refs: [] };
      },
      async gatekeeper() {
        return { status: "ok", signer: REGISTRY };
      },
    },
  });
  admin.signIn({ role: "application-admin", applicationId: APP_A });
  expect(lintPrivacyCopy(renderAdminHtml(admin.screen())).length === 0, "ADMIN_COPY");
  expect(lintPrivacyCopy("private swap across applications").includes("source-token-swap"), "LINT");
}

async function e2e13() {
  const { app } = createApp();
  await app.connect();
  app.navigate("/migrate");
  const preview = app.preview("exit-and-reshield");
  expect(preview.warnings.some((item) => item.fact === "version-migration"), "PUBLIC_LINKAGE");
  const migrated = await app.run("exit-and-reshield", {
    value: 1_000_000n,
    publicRecipient: WALLET,
    replacementPool: "0x7777777777777777777777777777777777777777",
    replacementPoolVersion: `0x${"cc".repeat(32)}`,
    outputCommitment0: depositIntent().outputCommitment0,
    outputCommitment1: ZERO32,
    recipientCiphertextHash0: depositIntent().recipientCiphertextHash0,
    recipientCiphertextHash1: ZERO32,
    inputNullifier0: `0x${"66".repeat(32)}`,
    inputNullifier1: ZERO32,
  });
  expect(migrated.linkage === true && migrated.phase === "finalized", "MIGRATE");
}

const RUNNERS = {
  "E2E-01": e2e01,
  "E2E-02": e2e02,
  "E2E-03": e2e03,
  "E2E-04": e2e04,
  "E2E-05": e2e05,
  "E2E-06": e2e06,
  "E2E-07": e2e07,
  "E2E-08": e2e08,
  "E2E-09": e2e09,
  "E2E-10": e2e10,
  "E2E-11": e2e11,
  "E2E-12": e2e12,
  "E2E-13": e2e13,
};

export async function runE2eSuite(options = {}) {
  const stack = assembleStack(options.profile ?? "ci");
  const results = [];
  for (const id of SCENARIO_IDS) {
    if (options.injectFailure === id) {
      results.push({
        ok: false,
        id,
        evidence: redactEvidence({
          scenario: id,
          code: "INJECTED_FAILURE",
          signingKey: SIGNING_KEY,
        }),
      });
      continue;
    }
    try {
      await RUNNERS[id]();
      results.push({ ok: true, id });
    } catch (error) {
      results.push({
        ok: false,
        id,
        evidence: redactEvidence({
          scenario: id,
          code: error.code ?? "E2E_FAILED",
          message: error.message,
        }),
      });
    }
  }
  return {
    ok: results.every((item) => item.ok),
    results,
    stackHash: stack.hash,
    notForProduction: true,
    profile: stack.profile,
  };
}

async function main() {
  const report = await runE2eSuite({ profile: "ci" });
  if (!report.ok) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    process.exitCode = 1;
    return;
  }
  process.stdout.write(`e2e-suite ok ${SCENARIO_IDS.join(" ")}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
