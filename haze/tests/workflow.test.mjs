import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { decodeHazeAddress, encodeHazeAddress } from "../sdk/typescript/src/address.ts";
import {
  EMERGENCY_SELECTORS,
  POOL_SELECTORS,
  ROUTER_SELECTORS,
  functionSelector,
} from "../sdk/typescript/src/bindings.ts";
import { intentStructHash } from "../sdk/typescript/src/eip712.ts";
import { EMERGENCY_EXIT_COOLDOWN, emergencyExitRequestId } from "../sdk/typescript/src/emergency.ts";
import { SdkError } from "../sdk/typescript/src/errors.ts";
import { createGatekeeperClient } from "../sdk/typescript/src/gatekeeper.ts";
import { ProverError, createProverSession } from "../sdk/typescript/src/prover.ts";
import { createStaticQuoteAdapter, createUnavailableQuoteAdapter } from "../sdk/typescript/src/quote.ts";
import { createWorkflowClient } from "../sdk/typescript/src/workflow.ts";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PROTOCOL = join(HAZE_ROOT, "circuits/vectors/v1/haze-protocol-v1.json");

function loadProtocol() {
  return JSON.parse(readFileSync(PROTOCOL, "utf8"));
}

function named(vectors, name) {
  return vectors.positive.find((vector) => vector.name === name);
}

const ZERO32 = `0x${"00".repeat(32)}`;
const ZERO20 = "0x0000000000000000000000000000000000000000";

function fixtureBinding() {
  return {
    chainId: 43113,
    pool: "0x1111111111111111111111111111111111111111",
    router: "0x4444444444444444444444444444444444444444",
    exit: "0x5555555555555555555555555555555555555555",
    applicationId: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    poolVersion: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    user: "0x2222222222222222222222222222222222222222",
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
      if (options.failFirst === "POLICY_STALE" && sent.length === 1) {
        throw new SdkError("POLICY_STALE");
      }
      return { hash: `0x${sent.length.toString(16).padStart(64, "0")}` };
    },
  };
}

function createFinality(options = {}) {
  let waits = 0;
  return {
    async wait() {
      waits += 1;
      if (options.reorgFirst && waits === 1) {
        return { status: "reorged", blockNumber: 9, events: [] };
      }
      return { status: "finalized", blockNumber: 20, events: options.events ?? [] };
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

function createClient(overrides = {}) {
  const binding = fixtureBinding();
  const clock = overrides.clock ?? createClock();
  return createWorkflowClient({
    ...binding,
    session: "app-session",
    gatekeeper: overrides.gatekeeper ?? createAuthGatekeeper(),
    quotes: overrides.quotes,
    wallet: overrides.wallet ?? createWallet(),
    policy: overrides.policy ?? createPolicy(defaultPolicy()),
    finality: overrides.finality ?? createFinality(),
    clock: typeof clock === "function" ? clock : clock.now.bind(clock),
    prover: overrides.prover,
    vault: overrides.vault,
    ...overrides.config,
  });
}

function fixtureRecipient() {
  const file = loadProtocol();
  const address = named(file, "haze_address");
  return decodeHazeAddress(address.text);
}

test("workflow public warnings mark swap, deposit, withdrawal, wallet, and gas as public", () => {
  const client = createClient();
  assert.deepEqual(client.publicWarnings("direct-shield"), ["deposit-amount", "wallet-address", "gas"]);
  assert.deepEqual(client.publicWarnings("swap-and-shield"), [
    "source-token-swap",
    "deposit-amount",
    "wallet-address",
    "gas",
  ]);
  assert.deepEqual(client.publicWarnings("private-send"), ["wallet-address", "gas"]);
  assert.deepEqual(client.publicWarnings("withdraw"), ["withdrawal-amount", "wallet-address", "gas"]);
  assert.deepEqual(client.publicWarnings("emergency-exit"), ["withdrawal-amount", "wallet-address", "gas"]);
  assert.deepEqual(client.publicWarnings("exit-and-reshield"), [
    "withdrawal-amount",
    "deposit-amount",
    "wallet-address",
    "gas",
  ]);
});

test("direct shield authorizes, proves, submits deposit, and finalizes", async () => {
  const wallet = createWallet();
  const client = createClient({ wallet });
  const result = await client.run("direct-shield", shieldInput());
  assert.equal(result.kind, "direct-shield");
  assert.equal(result.phase, "finalized");
  assert.equal(result.action, 1);
  assert.equal(result.nonceConsumed, true);
  assert.equal(client.phase(), "finalized");
  assert.equal(client.authorizationCount(), 1);
  assert.equal(wallet.sent.length, 1);
  assert.equal(wallet.sent[0].to, fixtureBinding().pool);
  assert.equal(wallet.sent[0].data.slice(0, 10), POOL_SELECTORS.deposit);
  const intent = client.lastIntent();
  const auth = client.lastAuthorization();
  assert.equal(intent.action, 1);
  assert.equal(intent.noteTreeRoot, ZERO32);
  assert.equal(intent.inputNullifier0, ZERO32);
  assert.equal(intent.publicAmount, 1_000_000);
  assert.equal(auth.intentHash, intentStructHash(intent));
  assert.ok(result.publicWarnings.includes("deposit-amount"));
});

test("swap-and-shield quotes then submits the router; slippage and expiry fail closed", async () => {
  const wallet = createWallet();
  const adapter = "0x3333333333333333333333333333333333333333";
  const quotes = createStaticQuoteAdapter({
    usdcOut: "1000000",
    adapter,
    data: "0xaabb",
    gasEstimate: 180000,
  });
  const client = createClient({ wallet, quotes });
  const result = await client.run("swap-and-shield", {
    ...shieldInput(),
    tokenIn: "0x5425890298aed601595a70ab815c96711a31bc65",
    amountIn: "0x00000000000000000000000000000000000000000000000000000000000f4240",
    minUsdcOut: "900000",
    deadline: 2_000_000_000,
  });
  assert.equal(result.action, 4);
  assert.equal(result.phase, "finalized");
  assert.equal(wallet.sent[0].to, fixtureBinding().router);
  assert.equal(wallet.sent[0].data.slice(0, 10), ROUTER_SELECTORS.swapAndShield);
  assert.equal(client.lastIntent().tokenIn, "0x5425890298aed601595a70ab815c96711a31bc65");
  assert.equal(client.lastQuote().adapter, adapter);
  assert.ok(result.publicWarnings.includes("source-token-swap"));

  const stale = createClient({ quotes });
  await assert.rejects(
    () =>
      stale.run("swap-and-shield", {
        ...shieldInput(),
        tokenIn: "0x5425890298aed601595a70ab815c96711a31bc65",
        amountIn: `0x${"00".repeat(32)}`,
        minUsdcOut: "2000000",
        deadline: 2_000_000_000,
      }),
    (error) => {
      assert.equal(error instanceof SdkError, true);
      assert.equal(error.code, "QUOTE_STALE");
      return true;
    },
  );

  const clock = createClock(3_000_000_000);
  const expired = createClient({ quotes, clock });
  await assert.rejects(
    () =>
      expired.run("swap-and-shield", {
        ...shieldInput(),
        tokenIn: "0x5425890298aed601595a70ab815c96711a31bc65",
        amountIn: `0x${"00".repeat(31)}01`,
        minUsdcOut: "900000",
        deadline: 2_000_000_000,
      }),
    (error) => error.code === "QUOTE_STALE",
  );

  await assert.rejects(
    () =>
      createClient({ quotes: createUnavailableQuoteAdapter() }).run("swap-and-shield", {
        ...shieldInput(),
        tokenIn: "0x5425890298aed601595a70ab815c96711a31bc65",
        amountIn: `0x${"00".repeat(31)}01`,
        minUsdcOut: "1",
        deadline: 2_000_000_000,
      }),
    (error) => error.code === "UNAVAILABLE",
  );
});

test("private send binds the recipient Haze address and rejects a cross-application recipient", async () => {
  const wallet = createWallet();
  const recipient = fixtureRecipient();
  const client = createClient({ wallet });
  const result = await client.run("private-send", {
    value: 500_000n,
    recipientAddress: recipient,
    outputCommitment0: depositIntent().outputCommitment0,
    outputCommitment1: depositIntent().outputCommitment1,
    recipientCiphertextHash0: depositIntent().recipientCiphertextHash0,
    recipientCiphertextHash1: depositIntent().recipientCiphertextHash1,
    inputNullifier0: `0x${"11".repeat(32)}`,
    inputNullifier1: ZERO32,
  });
  assert.equal(result.action, 2);
  assert.equal(result.phase, "finalized");
  assert.equal(wallet.sent[0].data.slice(0, 10), POOL_SELECTORS.transact);
  assert.equal(client.lastIntent().publicAmount, 0);
  assert.equal(client.lastIntent().publicRecipient, ZERO20);

  await assert.rejects(
    () =>
      client.run("private-send", {
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

test("withdraw submits a public recipient amount and keeps change private", async () => {
  const wallet = createWallet();
  const client = createClient({ wallet });
  const result = await client.run("withdraw", {
    value: 250_000n,
    publicRecipient: "0x6666666666666666666666666666666666666666",
    outputCommitment0: depositIntent().outputCommitment0,
    outputCommitment1: ZERO32,
    recipientCiphertextHash0: depositIntent().recipientCiphertextHash0,
    recipientCiphertextHash1: ZERO32,
    inputNullifier0: `0x${"33".repeat(32)}`,
    inputNullifier1: ZERO32,
  });
  assert.equal(result.action, 3);
  assert.equal(client.lastIntent().publicAmount, 250_000);
  assert.equal(client.lastIntent().publicRecipient, "0x6666666666666666666666666666666666666666");
  assert.equal(wallet.sent[0].data.slice(0, 10), POOL_SELECTORS.transact);
  assert.ok(result.publicWarnings.includes("withdrawal-amount"));
});

test("emergency exit skips the gatekeeper and enforces the seven-day cooldown", async () => {
  const wallet = createWallet();
  const clock = createClock();
  const client = createClient({ wallet, clock, gatekeeper: createAuthGatekeeper({ deny: "USER_INELIGIBLE" }) });
  const input = {
    value: 1_000_000n,
    publicRecipient: "0x6666666666666666666666666666666666666666",
    nullifier: `0x${"44".repeat(32)}`,
    requestSalt: `0x${"55".repeat(32)}`,
  };
  const requested = await client.run("emergency-exit", { ...input, step: "request" });
  assert.equal(requested.action, 5);
  assert.equal(client.authorizationCount(), 0);
  assert.equal(wallet.sent[0].to, fixtureBinding().exit);
  assert.equal(wallet.sent[0].data.slice(0, 10), EMERGENCY_SELECTORS.requestEmergencyExit);
  const expectedId = emergencyExitRequestId({
    chainId: fixtureBinding().chainId,
    pool: fixtureBinding().pool,
    poolVersion: fixtureBinding().poolVersion,
    applicationId: fixtureBinding().applicationId,
    nullifier: input.nullifier,
    recipient: input.publicRecipient,
    requestSalt: input.requestSalt,
  });
  assert.equal(requested.requestId, expectedId);

  await assert.rejects(() => client.run("emergency-exit", { ...input, step: "execute" }), (error) => {
    assert.equal(error instanceof SdkError, true);
    assert.equal(error.code, "TIMELOCK");
    return true;
  });

  clock.advance(EMERGENCY_EXIT_COOLDOWN);
  const executed = await client.run("emergency-exit", { ...input, step: "execute" });
  assert.equal(executed.phase, "finalized");
  assert.equal(wallet.sent[1].data.slice(0, 10), EMERGENCY_SELECTORS.executeEmergencyExit);
  assert.equal(
    wallet.sent[1].data.slice(0, 10),
    functionSelector(
      "executeEmergencyExit((bytes32,uint256,uint64,uint256,uint256,uint64,address,address,bytes32,uint256,bytes32,bytes,bytes))",
    ),
  );
});

test("exit-and-reshield is a public withdraw then a separately authorized shield", async () => {
  const wallet = createWallet();
  const client = createClient({ wallet });
  const result = await client.run("exit-and-reshield", {
    value: 1_000_000n,
    publicRecipient: fixtureBinding().user,
    replacementPool: "0x7777777777777777777777777777777777777777",
    replacementPoolVersion: `0x${"cc".repeat(32)}`,
    outputCommitment0: depositIntent().outputCommitment0,
    outputCommitment1: ZERO32,
    recipientCiphertextHash0: depositIntent().recipientCiphertextHash0,
    recipientCiphertextHash1: ZERO32,
    inputNullifier0: `0x${"66".repeat(32)}`,
    inputNullifier1: ZERO32,
  });
  assert.equal(result.kind, "exit-and-reshield");
  assert.equal(result.linkage, true);
  assert.equal(result.phase, "finalized");
  assert.equal(client.authorizationCount(), 2);
  assert.equal(wallet.sent.length, 2);
  assert.equal(wallet.sent[0].data.slice(0, 10), POOL_SELECTORS.transact);
  assert.equal(wallet.sent[1].to, "0x7777777777777777777777777777777777777777");
  assert.equal(wallet.sent[1].data.slice(0, 10), POOL_SELECTORS.deposit);
  assert.notEqual(client.lastIntent().pool, fixtureBinding().pool);
  assert.ok(result.publicWarnings.includes("withdrawal-amount"));
  assert.ok(result.publicWarnings.includes("deposit-amount"));
});

test("cancelling proof generation does not consume the authorization nonce", async () => {
  const inner = createProverSession();
  const prover = {
    cancel: inner.cancel.bind(inner),
    async proveDevelopment(value) {
      inner.cancel();
      return inner.proveDevelopment(value);
    },
  };
  const client = createClient({ prover });
  await assert.rejects(() => client.run("direct-shield", shieldInput()), (error) => {
    assert.equal(error instanceof ProverError, true);
    assert.equal(error.code, "CANCELLED");
    return true;
  });
  assert.equal(client.nonceConsumed(), false);
  assert.equal(client.authorizationCount(), 1);
  assert.equal(client.phase(), "cancelled");
});

test("wallet rejection fails closed without consuming a nonce", async () => {
  const client = createClient({ wallet: createWallet({ reject: true }) });
  await assert.rejects(() => client.run("direct-shield", shieldInput()), (error) => {
    assert.equal(error instanceof SdkError, true);
    assert.equal(error.code, "REJECTED");
    return true;
  });
  assert.equal(client.nonceConsumed(), false);
  assert.equal(client.phase(), "failed");
});

test("an expired authorization is rejected before submit", async () => {
  const wallet = createWallet();
  const client = createClient({
    wallet,
    gatekeeper: createAuthGatekeeper({ validUntil: 10 }),
    clock: createClock(11),
  });
  await assert.rejects(() => client.run("direct-shield", shieldInput()), (error) => {
    assert.equal(error instanceof SdkError, true);
    assert.equal(error.code, "AUTHORIZATION_EXPIRED");
    return true;
  });
  assert.equal(wallet.sent.length, 0);
  assert.equal(client.nonceConsumed(), false);
});

test("a stale policy resyncs and re-proves instead of substituting roots on the old authorization", async () => {
  const wallet = createWallet({ failFirst: "POLICY_STALE" });
  const policy = createPolicy(defaultPolicy());
  const original = await policy.snapshot();
  const client = createClient({
    wallet,
    policy: {
      async snapshot() {
        const snap = await policy.snapshot();
        if (wallet.sent.length >= 1) {
          return {
            ...snap,
            applicationPolicyVersion: original.applicationPolicyVersion + 1,
            applicationMembershipRoot: `0x${"77".repeat(32)}`,
          };
        }
        return snap;
      },
    },
  });
  const result = await client.run("direct-shield", shieldInput());
  assert.equal(result.resynced, true);
  assert.equal(result.phase, "finalized");
  assert.equal(client.authorizationCount(), 2);
  assert.equal(wallet.sent.length, 2);
  const firstNonce = `0x${"1".padStart(64, "0")}`;
  const secondNonce = `0x${"2".padStart(64, "0")}`;
  assert.equal(wallet.sent[0].data.slice(10, 74), firstNonce.slice(2));
  assert.equal(wallet.sent[1].data.slice(10, 74), secondNonce.slice(2));
  assert.equal(client.lastAuthorization().nonce, secondNonce);
  assert.equal(client.lastIntent().applicationPolicyVersion, original.applicationPolicyVersion + 1);
  assert.equal(client.lastAuthorization().intentHash, intentStructHash(client.lastIntent()));
  assert.notEqual(client.lastIntent().applicationMembershipRoot, original.applicationMembershipRoot);
});

test("a reorg retries the same authorized submission and then finalizes", async () => {
  const wallet = createWallet();
  const client = createClient({ wallet, finality: createFinality({ reorgFirst: true }) });
  const result = await client.run("direct-shield", shieldInput());
  assert.equal(result.retried, true);
  assert.equal(result.phase, "finalized");
  assert.equal(wallet.sent.length, 2);
  assert.equal(client.authorizationCount(), 1);
  assert.equal(wallet.sent[0].data, wallet.sent[1].data);
});

test("gatekeeper denial fails closed before proving or submitting", async () => {
  const wallet = createWallet();
  const client = createClient({
    wallet,
    gatekeeper: createAuthGatekeeper({ deny: "USER_INELIGIBLE" }),
  });
  await assert.rejects(() => client.run("direct-shield", shieldInput()), (error) => {
    assert.equal(error.code, "USER_INELIGIBLE");
    return true;
  });
  assert.equal(wallet.sent.length, 0);
  assert.equal(client.authorizationCount(), 0);
});
