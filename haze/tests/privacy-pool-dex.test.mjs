import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { decodeHazeAddress, encodeHazeAddress } from "../sdk/typescript/src/address.ts";
import { SdkError } from "../sdk/typescript/src/errors.ts";
import { encodeEnvelope } from "../sdk/typescript/src/envelope.ts";
import { recipientAad, sealRecipientNote } from "../sdk/typescript/src/hpke.ts";
import { intentStructHash } from "../sdk/typescript/src/eip712.ts";
import { EMERGENCY_EXIT_COOLDOWN } from "../sdk/typescript/src/emergency.ts";
import { noteCommitment } from "../sdk/typescript/src/note.ts";
import { createGatekeeperClient } from "../sdk/typescript/src/gatekeeper.ts";
import { createStaticQuoteAdapter, createUnavailableQuoteAdapter } from "../sdk/typescript/src/quote.ts";
import { deriveVaultAccount } from "../sdk/typescript/src/vault.ts";
import { createDexApp } from "../apps/privacy-pool-dex/src/index.ts";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PROTOCOL = join(HAZE_ROOT, "circuits/vectors/v1/haze-protocol-v1.json");

function loadProtocol() {
  return JSON.parse(readFileSync(PROTOCOL, "utf8"));
}

function named(vectors, name) {
  return vectors.positive.find((vector) => vector.name === name);
}

const ZERO32 = `0x${"00".repeat(32)}`;

function fixtureBinding() {
  return {
    chainId: 43113,
    pool: "0x1111111111111111111111111111111111111111",
    router: "0x4444444444444444444444444444444444444444",
    exit: "0x5555555555555555555555555555555555555555",
    applicationId: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    poolVersion: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  };
}

function depositIntent() {
  return named(loadProtocol(), "haze_intent_deposit").fields;
}

function headers(version = "1") {
  return { get: (name) => (name.toLowerCase() === "haze-api-version" ? version : null) };
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
      const authorization = {
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
        validUntil: options.validUntil ?? 2_000_000_000,
      };
      return {
        ok: true,
        status: 200,
        headers: headers(),
        json: async () => ({ intent, authorization }),
        text: async () => "",
      };
    },
  });
}

function createPolicy(initial) {
  let current = { ...initial };
  return {
    replace(next) {
      current = { ...next };
    },
    async snapshot() {
      return { ...current };
    },
  };
}

function createWallet(options = {}) {
  const sent = [];
  return {
    sent,
    async send(request) {
      sent.push(request);
      if (options.reject) {
        throw new SdkError("REJECTED");
      }
      return { hash: `0x${sent.length.toString(16).padStart(64, "0")}` };
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

function defaultPolicy() {
  const intent = depositIntent();
  return {
    noteTreeRoot: intent.noteTreeRoot,
    applicationPolicyVersion: intent.applicationPolicyVersion,
    hazePolicyVersion: intent.hazePolicyVersion,
    applicationMembershipRoot: intent.applicationMembershipRoot,
    hazeBlocklistRoot: intent.hazeBlocklistRoot,
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

function fixtureRecipient() {
  return decodeHazeAddress(named(loadProtocol(), "haze_address").text);
}

function accountRequest(address = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf") {
  return {
    ...fixtureBinding(),
    wallet: address,
    signingKey: "0x0000000000000000000000000000000000000000000000000000000000000001",
  };
}

function hex(bytes) {
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

function sealedEvent(account, overrides = {}) {
  const binding = fixtureBinding();
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
    ...overrides,
  };
}

function createConnector(options = {}) {
  return {
    async connect() {
      if (options.reject) {
        throw new SdkError("REJECTED");
      }
      return {
        address: options.address ?? "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
        chainId: options.chainId ?? 43113,
        signingKey: options.signingKey ?? accountRequest().signingKey,
      };
    },
    async disconnect() {},
  };
}

function createApp(overrides = {}) {
  const binding = fixtureBinding();
  const clock = overrides.clock ?? createClock();
  return createDexApp({
    ...binding,
    expectedChainId: binding.chainId,
    connector: overrides.connector ?? createConnector(),
    wallet: overrides.wallet ?? createWallet(),
    gatekeeper: overrides.gatekeeper ?? createAuthGatekeeper(),
    quotes: overrides.quotes,
    policy: overrides.policy ?? createPolicy(defaultPolicy()),
    finality: overrides.finality ?? createFinality(),
    clock: typeof clock === "function" ? clock : clock.now.bind(clock),
    prover: overrides.prover,
    noteEvents: overrides.noteEvents ?? [],
    ...overrides.config,
  });
}

function warningFacts(screen) {
  return screen.warnings.map((item) => item.fact);
}

test("wallet onboarding connects, rejects, disconnects, and refuses the wrong chain", async () => {
  const app = createApp();
  assert.equal(app.walletStatus(), "disconnected");
  assert.equal(app.session().role, null);
  assert.equal(app.navigate("/shield").ok, false);

  await app.connect();
  assert.equal(app.walletStatus(), "connected");
  assert.equal(app.session().role, "pool-user");
  assert.equal(app.session().applicationId, fixtureBinding().applicationId);
  assert.equal(app.navigate("/shield").ok, true);

  app.disconnect();
  assert.equal(app.walletStatus(), "disconnected");
  assert.equal(app.session().role, null);
  assert.equal(app.navigate("/shield").ok, false);

  const rejected = createApp({ connector: createConnector({ reject: true }) });
  await rejected.connect();
  assert.equal(rejected.walletStatus(), "rejected");
  assert.equal(rejected.session().role, null);
  assert.equal(rejected.lastError()?.code, "REJECTED");

  const wrong = createApp({ connector: createConnector({ chainId: 1 }) });
  await wrong.connect();
  assert.equal(wrong.walletStatus(), "wrong-chain");
  assert.equal(wrong.navigate("/swap").ok, false);
});

test("public warnings appear on preview and must be acknowledged before a signature", async () => {
  const app = createApp();
  await app.connect();
  app.navigate("/shield");
  const before = app.screen();
  assert.equal(before.canSign, false);
  assert.ok(warningFacts(before).includes("deposit-amount"));
  assert.ok(warningFacts(before).includes("gas"));
  assert.ok(warningFacts(before).includes("wallet-address"));
  assert.ok(before.warnings.every((item) => item.visibility === "public"));
  assert.ok(before.warnings.every((item) => !item.acknowledged));

  await assert.rejects(() => app.run("direct-shield", shieldInput()), (error) => {
    assert.equal(error instanceof SdkError, true);
    assert.equal(error.code, "REJECTED");
    return true;
  });
  assert.equal(app.phase(), "failed");

  const preview = app.preview("direct-shield");
  assert.equal(preview.canSign, true);
  assert.ok(preview.warnings.every((item) => item.acknowledged));
  assert.match(preview.warnings.find((item) => item.fact === "deposit-amount").warning, /visible on chain/i);
});

test("direct shield finalizes and lists the private note after finality", async () => {
  const app = createApp();
  await app.connect();
  app.navigate("/shield");
  app.preview("direct-shield");
  const result = await app.run("direct-shield", shieldInput());
  assert.equal(result.kind, "direct-shield");
  assert.equal(result.phase, "finalized");
  assert.equal(app.phase(), "finalized");
  const notes = app.notes();
  assert.equal(notes.length, 1);
  assert.equal(notes[0].value, 1_000_000n);
  assert.equal(notes[0].visibility, "private");
  const history = app.history();
  assert.equal(history[0].kind, "direct-shield");
  assert.ok(history[0].txHash);
  assert.ok(app.screen().warnings.some((item) => item.fact === "deposit-amount"));
});

test("swap-and-shield reviews a public quote and fails closed on stale or missing quotes", async () => {
  const quotes = createStaticQuoteAdapter({
    usdcOut: "1000000",
    adapter: "0x3333333333333333333333333333333333333333",
    data: "0xaabb",
    gasEstimate: 180000,
  });
  const app = createApp({ quotes });
  await app.connect();
  app.navigate("/swap");
  const quoted = await app.quote({
    tokenIn: "0x5425890298aed601595a70ab815c96711a31bc65",
    amountIn: "0x00000000000000000000000000000000000000000000000000000000000f4240",
    minUsdcOut: "900000",
    deadline: 2_000_000_000,
  });
  assert.equal(quoted.usdcOut, "1000000");
  const screen = app.preview("swap-and-shield");
  assert.ok(warningFacts(screen).includes("source-token-swap"));
  assert.match(screen.warnings.find((item) => item.fact === "source-token-swap").label, /public/i);
  const result = await app.run("swap-and-shield", {
    ...shieldInput(),
    tokenIn: "0x5425890298aed601595a70ab815c96711a31bc65",
    amountIn: "0x00000000000000000000000000000000000000000000000000000000000f4240",
    minUsdcOut: "900000",
    deadline: 2_000_000_000,
  });
  assert.equal(result.kind, "swap-and-shield");
  assert.equal(result.phase, "finalized");
  assert.equal(app.notes()[0].visibility, "private");

  const stale = createApp({ quotes });
  await stale.connect();
  stale.preview("swap-and-shield");
  await assert.rejects(
    () =>
      stale.run("swap-and-shield", {
        ...shieldInput(),
        tokenIn: "0x5425890298aed601595a70ab815c96711a31bc65",
        amountIn: `0x${"00".repeat(32)}`,
        minUsdcOut: "2000000",
        deadline: 2_000_000_000,
      }),
    (error) => error.code === "QUOTE_STALE",
  );

  const down = createApp({ quotes: createUnavailableQuoteAdapter() });
  await down.connect();
  await assert.rejects(
    () =>
      down.quote({
        tokenIn: "0x5425890298aed601595a70ab815c96711a31bc65",
        amountIn: `0x${"00".repeat(31)}01`,
        minUsdcOut: "1",
        deadline: 2_000_000_000,
      }),
    (error) => error.code === "UNAVAILABLE",
  );
});

test("private send binds an app-scoped Haze address and rejects a foreign application", async () => {
  const app = createApp();
  await app.connect();
  app.navigate("/send");
  const encoded = app.hazeAddress();
  assert.match(encoded, /^haze1:/);
  const decoded = decodeHazeAddress(encoded);
  assert.equal(decoded.applicationId, fixtureBinding().applicationId);
  assert.equal(decoded.chainId, 43113);
  assert.equal(encodeHazeAddress(decoded), encoded);

  const recipient = fixtureRecipient();
  app.preview("private-send");
  const result = await app.run("private-send", {
    value: 500_000n,
    recipientAddress: recipient,
    outputCommitment0: depositIntent().outputCommitment0,
    outputCommitment1: depositIntent().outputCommitment1,
    recipientCiphertextHash0: depositIntent().recipientCiphertextHash0,
    recipientCiphertextHash1: depositIntent().recipientCiphertextHash1,
    inputNullifier0: `0x${"11".repeat(32)}`,
    inputNullifier1: ZERO32,
  });
  assert.equal(result.kind, "private-send");
  assert.equal(result.phase, "finalized");

  await assert.rejects(
    () =>
      app.run("private-send", {
        value: 1n,
        recipientAddress: { ...recipient, applicationId: `0x${"11".repeat(32)}` },
        outputCommitment0: depositIntent().outputCommitment0,
        inputNullifier0: `0x${"22".repeat(32)}`,
      }),
    (error) => {
      assert.equal(error instanceof SdkError, true);
      assert.equal(error.code, "APPLICATION_MISMATCH");
      return true;
    },
  );
});

test("withdrawal and migrate screens keep public amount and version-migration copy", async () => {
  const app = createApp();
  await app.connect();
  app.navigate("/withdraw");
  const withdraw = app.preview("withdraw");
  assert.ok(warningFacts(withdraw).includes("withdrawal-amount"));
  const withdrawn = await app.run("withdraw", {
    value: 250_000n,
    publicRecipient: "0x6666666666666666666666666666666666666666",
    outputCommitment0: depositIntent().outputCommitment0,
    outputCommitment1: ZERO32,
    recipientCiphertextHash0: depositIntent().recipientCiphertextHash0,
    recipientCiphertextHash1: ZERO32,
    inputNullifier0: `0x${"33".repeat(32)}`,
    inputNullifier1: ZERO32,
  });
  assert.equal(withdrawn.kind, "withdraw");
  assert.equal(withdrawn.phase, "finalized");

  app.navigate("/migrate");
  const migrate = app.preview("exit-and-reshield");
  assert.ok(warningFacts(migrate).includes("version-migration"));
  assert.equal(migrate.warnings.find((item) => item.fact === "version-migration").visibility, "public");
  const migrated = await app.run("exit-and-reshield", {
    value: 1_000_000n,
    publicRecipient: "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
    replacementPool: "0x7777777777777777777777777777777777777777",
    replacementPoolVersion: `0x${"cc".repeat(32)}`,
    outputCommitment0: depositIntent().outputCommitment0,
    outputCommitment1: ZERO32,
    recipientCiphertextHash0: depositIntent().recipientCiphertextHash0,
    recipientCiphertextHash1: ZERO32,
    inputNullifier0: `0x${"66".repeat(32)}`,
    inputNullifier1: ZERO32,
  });
  assert.equal(migrated.linkage, true);
  assert.equal(migrated.phase, "finalized");
});

test("emergency exit waits the seven-day timelock before execute", async () => {
  const clock = createClock();
  const app = createApp({
    clock,
    gatekeeper: createAuthGatekeeper({ deny: "USER_INELIGIBLE" }),
  });
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
  assert.equal(requested.kind, "emergency-exit");
  assert.ok(requested.requestId);
  await assert.rejects(
    () => app.run("emergency-exit", { ...input, step: "execute" }),
    (error) => error.code === "TIMELOCK",
  );
  clock.advance(EMERGENCY_EXIT_COOLDOWN);
  const executed = await app.run("emergency-exit", { ...input, step: "execute" });
  assert.equal(executed.phase, "finalized");
});

test("history, wipe, and replay recover the same spendable notes", async () => {
  const account = deriveVaultAccount(accountRequest());
  const event = sealedEvent(account);
  const app = createApp({ noteEvents: [event] });
  await app.connect();
  await app.recover();
  assert.equal(app.notes().length, 1);
  assert.equal(app.notes()[0].value, 1_000_000n);
  assert.equal(app.notes()[0].commitment, event.commitment);
  app.navigate("/history");
  assert.equal(app.history().length, 1);
  assert.equal(app.history()[0].txHash, event.txHash);

  await app.wipe();
  assert.equal(app.notes().length, 0);
  assert.equal(app.history().length, 0);

  await app.recover();
  assert.equal(app.notes().length, 1);
  assert.equal(app.notes()[0].commitment, event.commitment);
});

test("DEX routes stay isolated from the portal and never treat hidden nav as authorization", async () => {
  const app = createApp();
  await app.connect();
  for (const path of ["/admin", "/audit", "/governance"]) {
    const decision = app.navigate(path);
    assert.equal(decision.ok, false);
    assert.equal(decision.code, "FORBIDDEN");
    assert.notEqual(decision.code, "NOT_FOUND");
  }
  const screen = app.screen();
  assert.ok(screen.nav.every((item) => !item.path.startsWith("/admin")));
  assert.deepEqual(
    screen.nav.map((item) => item.path).sort(),
    ["/emergency-exit", "/history", "/migrate", "/overview", "/send", "/shield", "/swap", "/withdraw"].sort(),
  );
});

test("wallet rejection and proof cancel surface as failed or cancelled without a note", async () => {
  const rejected = createApp({ wallet: createWallet({ reject: true }) });
  await rejected.connect();
  rejected.preview("direct-shield");
  await assert.rejects(() => rejected.run("direct-shield", shieldInput()), (error) => error.code === "REJECTED");
  assert.equal(rejected.phase(), "failed");
  assert.equal(rejected.notes().length, 0);

  const inner = { cancelled: false, cancel() { this.cancelled = true; }, async proveDevelopment() {} };
  const cancelled = createApp({ prover: inner });
  await cancelled.connect();
  cancelled.preview("direct-shield");
  cancelled.cancel();
  assert.equal(inner.cancelled, true);
  assert.equal(cancelled.phase(), "cancelled");
});

test("rendered DEX shell uses alpine-volcanic tokens and accessible keyboard contracts", async () => {
  const app = createApp();
  await app.connect();
  app.navigate("/shield");
  app.preview("direct-shield");
  const html = app.renderHtml(390);
  assert.match(html, /IBM Plex Sans/);
  assert.match(html, /#16130f/i);
  assert.match(html, /#1f6b62/i);
  assert.doesNotMatch(html, /#fdbe2c/i);
  assert.doesNotMatch(html, /#3f8aff/i);
  assert.doesNotMatch(html, /stellar|soroban|freighter/i);
  assert.match(html, /role="button"/);
  assert.match(html, /role="status"/);
  assert.match(html, /aria-live="polite"/);
  assert.match(html, /role="alert"/);
  assert.match(html, /tabindex="0"/);
  assert.match(html, /Skip to content/);
  assert.match(html, /visible on chain/i);
  assert.doesNotMatch(html, /href="\/admin"/);
  assert.match(html, /data-layout="stack"/);
});
