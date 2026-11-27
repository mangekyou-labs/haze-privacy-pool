import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import test from "node:test";
import {
  ensureFujiMembershipRoot,
  extractFujiRpcError,
  executeFujiBrowserTransaction,
  updateFujiMembershipRoot,
} from "../sdk/typescript/src/browser-fuji-flow.ts";
import {
  encodeBrowserSwapAndShield,
  encodeEmergencyExitRequest,
  encodeEmergencyExitExecute,
  encodeBrowserGroth16Proof,
  deriveDevelopmentSpendProof,
  planBrowserFujiSpend,
  swapRouteHash,
} from "../sdk/typescript/src/browser-fuji-contracts.ts";
import { generateBrowserSecrets } from "../sdk/typescript/src/browser-prover.ts";
import {
  buildSealedBrowserTransferWitness,
  buildSealedBrowserWitness,
} from "../sdk/typescript/src/browser-witness-flow.ts";
import { planFujiWithdrawalDisclosure } from "../sdk/typescript/src/render-disclosure.ts";
import {
  buildLiveDepositWitness,
  buildLiveSwapWitness,
  buildLiveTransferWitness,
  buildLiveWithdrawWitness,
} from "../dev/operator-circuit-witness.mjs";
import { toHex } from "../sdk/typescript/src/abi.ts";
import { encodeHazeAddress } from "../sdk/typescript/src/address.ts";
import { deriveBrowserX25519PublicKey } from "../sdk/typescript/src/browser-crypto.ts";
import { ROUTER_SELECTORS } from "../sdk/typescript/src/bindings.ts";
import { parseEnvelope } from "../sdk/typescript/src/envelope.ts";
import { openRecipientNote, parseRecipientPlaintext, recipientAad } from "../sdk/typescript/src/hpke.ts";
import { parseHex } from "../sdk/typescript/src/field.ts";
import { noteCommitment, notePublicKey } from "../sdk/typescript/src/note.ts";
import { deriveShieldedAccount } from "../sdk/typescript/src/prover.ts";

const HAZE = resolve(import.meta.dirname, "..");

test("extractFujiRpcError preserves a nested MetaMask revert reason", () => {
  const nested = {
    code: -32603,
    message: "Internal JSON-RPC error.",
    data: {
      originalError: {
        code: 3,
        data: "0x08c379a0",
        message: "execution reverted: POLICY_INVALID",
      },
    },
  };
  assert.equal(extractFujiRpcError(nested), "execution reverted: POLICY_INVALID");
});

function source(path) {
  return readFileSync(join(HAZE, path), "utf8");
}

test("the deployed route mounts the browser Fuji client without a live query hatch", () => {
  const route = source("web/apps/haze/app/[route]/page.tsx");
  assert.match(route, /FujiBrowserClient/);
  assert.doesNotMatch(route, /query\.live|live:\s*query\.live|\?live=1/);
  assert.match(route, /renderHazeFragment/);
  assert.doesNotMatch(route, /renderHazePage/);
});

test("the deployed client portals into the single Fuji renderer mount slot", () => {
  const client = source("web/apps/haze/app/[route]/fuji-browser-client.tsx");
  assert.match(client, /createPortal/);
  assert.match(client, /getElementById\("fuji-browser-transaction-root"\)/);
  assert.match(client, /return createPortal\(/);
});

test("the deployed client composes browser proving, vault, reconciliation, and audit encryption", () => {
  const client = source("web/apps/haze/app/[route]/fuji-browser-client.tsx");
  assert.match(client, /browser-prover/);
  assert.match(client, /browser-operation-vault/);
  assert.match(client, /fuji-reconciliation/);
  assert.match(client, /DEFAULT_HAZE_AUDIT_PUBLIC_KEY/);
  // User routes never act on disclosure: no render-disclosure API calls, no disclosure CTA.
  assert.doesNotMatch(client, /requestFujiDisclosure|planFujiWithdrawalDisclosure|Request wallet-scoped disclosure|data-disclosure-status/);
  assert.match(client, /new Worker\(new URL\([^)]*prover-worker/);
  assert.doesNotMatch(client, /\/api\/live-|localhost|127\.0\.0\.1|node:|\bBuffer\b|\bfs\b/);
  assert.match(client, /NEXT_PUBLIC_HAZE_AUDIT_PUBLIC_KEY/);
});

test("the Next worker graph pins web-worker to its browser implementation", () => {
  const config = source("web/apps/haze/next.config.ts");
  assert.match(config, /web-worker.*cjs\/browser\.js/s);
  assert.doesNotMatch(config, /cjs\/node\.js/);
});

test("the browser flow exposes transaction state and never disclosure state on user routes", () => {
  const client = source("web/apps/haze/app/[route]/fuji-browser-client.tsx");
  assert.match(client, /data-transaction-status/);
  assert.doesNotMatch(client, /data-disclosure-status/);
  assert.match(client, /recoverFujiOperation/);
  assert.match(client, /markSubmittedBeforeBroadcast/);
});

test("the deployed client recovers spendable notes from chain and seals Shield to the wallet x25519 key", () => {
  const client = source("web/apps/haze/app/[route]/fuji-browser-client.tsx");
  assert.match(client, /recoverSpendableNotesFromLogs/);
  assert.match(client, /recipientPublicKey/);
  assert.match(client, /data-spendable-note-count/);
});

test("the deployed client persists recovered notes as confirmed and surfaces recover errors", () => {
  const client = source("web/apps/haze/app/[route]/fuji-browser-client.tsx");
  assert.match(client, /persistRecoveredSpendableNotes/);
  assert.match(client, /x25519:\s*account\.x25519PublicKey/);
  assert.doesNotMatch(client, /transition\(opId,\s*"confirmed"/);
  assert.doesNotMatch(client, /Ignore log scan errors/);
  assert.match(client, /membershipStore\.current\?\.add/);
});

test("executeSpendWorkflow and spendableNotes share the confirmed spendable input predicate", () => {
  const client = source("web/apps/haze/app/[route]/fuji-browser-client.tsx");
  const vaultSource = source("sdk/typescript/src/browser-operation-vault.ts");
  const executeStart = client.indexOf("const executeSpendWorkflow");
  const migrateStart = client.indexOf("const migratePool", executeStart);
  const executeBody = client.slice(executeStart, migrateStart);

  assert.match(client, /import\s*\{[^}]*isConfirmedSpendableInput[^}]*\}\s*from\s*["'][^"']*browser-operation-vault\.ts["']/s);
  assert.match(executeBody, /findLast\(isConfirmedSpendableInput\)/);
  assert.doesNotMatch(executeBody, /findLast\(\(item\)\s*=>\s*item\.kind\s*===\s*["']deposit["']/);
  assert.match(client, /const spendableNotes\s*=\s*vaultNotes\.filter\(isConfirmedSpendableInput\)/);
  assert.match(vaultSource, /isConfirmedSpendableInput[\s\S]*item\.kind\s*===\s*["']deposit["'][\s\S]*item\.kind\s*===\s*["']transfer["']/);
  assert.doesNotMatch(vaultSource, /isConfirmedSpendableInput[\s\S]{0,300}item\.kind\s*===\s*["']swap["']/);
});

test("the deployed client POSTs the union of stored and current in/out membership leaves", () => {
  const client = source("web/apps/haze/app/[route]/fuji-browser-client.tsx");
  assert.match(client, /unionMembershipLeaves/);
  assert.doesNotMatch(client, /\.\.\.payload,\s*membershipLeaves:\s*storedMembers/);
});

test("browser Send codecs do not call Node Buffer.readBigUInt64BE", () => {
  assert.doesNotMatch(source("sdk/typescript/src/address.ts"), /readBigUInt64BE/);
  assert.doesNotMatch(source("sdk/typescript/src/hpke.ts"), /readBigUInt64BE/);
});

test("membership update waits for success and binds the refetched policy version", async () => {
  const calls = [];
  const result = await updateFujiMembershipRoot({
    membershipRoot: `0x${"12".repeat(32)}`,
    applicationId: `0x${"34".repeat(32)}`,
    policyAuthority: "0xed37fd0d6f0f69236e7472b36796e133d20ecc32",
    wallet: "0xeD37FD0d6F0f69236E7472B36796e133D20EcC32",
    readApplication: async () => ({ membershipVersion: calls.length === 0 ? 7n : 8n, membershipRoot: calls.length === 0 ? "0xold" : `0x${"12".repeat(32)}` }),
    sendUpdate: async () => { calls.push("send"); return "0xupdate"; },
    waitReceipt: async () => { calls.push("receipt"); return { status: "0x1" }; },
  });
  assert.deepEqual(calls, ["send", "receipt"]);
  assert.equal(result.membershipVersion, 8n);
});

test("membership update polls readApplication through temporary RPC replication lag", async () => {
  let reads = 0;
  const result = await updateFujiMembershipRoot({
    membershipRoot: `0x${"12".repeat(32)}`,
    applicationId: `0x${"34".repeat(32)}`,
    policyAuthority: "0xed37fd0d6f0f69236e7472b36796e133d20ecc32",
    wallet: "0xeD37FD0d6F0f69236E7472B36796e133D20EcC32",
    readApplication: async () => {
      reads += 1;
      // First read is 'before' (reads=1).
      // Second and third reads simulate RPC lag returning old version.
      // Fourth read returns updated version.
      if (reads <= 3) return { membershipVersion: 7n, membershipRoot: "0xold" };
      return { membershipVersion: 8n, membershipRoot: `0x${"12".repeat(32)}` };
    },
    sendUpdate: async () => "0xupdate",
    waitReceipt: async () => ({ status: "0x1" }),
    sleep: async () => {},
  });
  assert.equal(result.membershipVersion, 8n);
  assert.ok(reads >= 4);
});

test("membership update accepts a newer version when the pre-update read was stale", async () => {
  let reads = 0;
  const result = await updateFujiMembershipRoot({
    membershipRoot: `0x${"12".repeat(32)}`,
    applicationId: `0x${"34".repeat(32)}`,
    policyAuthority: "0xed37fd0d6f0f69236e7472b36796e133d20ecc32",
    wallet: "0xeD37FD0d6F0f69236E7472B36796e133D20EcC32",
    readApplication: async () => {
      reads += 1;
      // A lagging node reports v2 before the send; the chain was really at v3,
      // so the confirmed update lands as v4, not before + 1.
      if (reads === 1) return { membershipVersion: 2n, membershipRoot: "0xold" };
      return { membershipVersion: 4n, membershipRoot: `0x${"12".repeat(32)}` };
    },
    sendUpdate: async () => "0xupdate",
    waitReceipt: async () => ({ status: "0x1" }),
    sleep: async () => {},
  });
  assert.equal(result.membershipVersion, 4n);
});

test("membership update keeps polling through replication lag longer than 15 reads", async () => {
  let reads = 0;
  const result = await updateFujiMembershipRoot({
    membershipRoot: `0x${"12".repeat(32)}`,
    applicationId: `0x${"34".repeat(32)}`,
    policyAuthority: "0xed37fd0d6f0f69236e7472b36796e133d20ecc32",
    wallet: "0xeD37FD0d6F0f69236E7472B36796e133D20EcC32",
    readApplication: async () => {
      reads += 1;
      if (reads <= 30) return { membershipVersion: 7n, membershipRoot: "0xold" };
      return { membershipVersion: 8n, membershipRoot: `0x${"12".repeat(32)}` };
    },
    sendUpdate: async () => "0xupdate",
    waitReceipt: async () => ({ status: "0x1" }),
    sleep: async () => {},
  });
  assert.equal(result.membershipVersion, 8n);
});

test("membership update still rejects when the root never appears", async () => {
  await assert.rejects(updateFujiMembershipRoot({
    membershipRoot: `0x${"12".repeat(32)}`,
    applicationId: `0x${"34".repeat(32)}`,
    policyAuthority: "0xed37fd0d6f0f69236e7472b36796e133d20ecc32",
    wallet: "0xeD37FD0d6F0f69236E7472B36796e133D20EcC32",
    readApplication: async () => ({ membershipVersion: 7n, membershipRoot: "0xold" }),
    sendUpdate: async () => "0xupdate",
    waitReceipt: async () => ({ status: "0x1" }),
    sleep: async () => {},
  }), /MEMBERSHIP_UPDATE_MISMATCH/);
});

test("membership update returns existing snapshot without sending transaction when root matches", async () => {
  let sent = false;
  const result = await updateFujiMembershipRoot({
    membershipRoot: `0x${"12".repeat(32)}`,
    applicationId: `0x${"34".repeat(32)}`,
    policyAuthority: "0xed37fd0d6f0f69236e7472b36796e133d20ecc32",
    wallet: "0xeD37FD0d6F0f69236E7472B36796e133D20EcC32",
    readApplication: async () => ({ membershipVersion: 9n, membershipRoot: `0x${"12".repeat(32)}` }),
    sendUpdate: async () => { sent = true; return "0xupdate"; },
    waitReceipt: async () => ({ status: "0x1" }),
  });
  assert.equal(sent, false);
  assert.equal(result.membershipVersion, 9n);
});


test("updateFujiMembershipRoot strictly refuses non-authority wallets", async () => {
  await assert.rejects(
    async () => {
      await updateFujiMembershipRoot({
        membershipRoot: `0x${"12".repeat(32)}`,
        applicationId: `0x${"34".repeat(32)}`,
        policyAuthority: "0xed37fd0d6f0f69236e7472b36796e133d20ecc32",
        wallet: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        readApplication: async () => ({ membershipVersion: 1n, membershipRoot: "0x0" }),
        sendUpdate: async () => "0xhash",
        waitReceipt: async () => ({ status: "0x1" }),
      });
    },
    /POLICY_AUTHORITY_REQUIRED/,
  );
});

test("ensureFujiMembershipRoot uses direct authority transaction when connected wallet is policy authority", async () => {
  let onChainSent = false;
  let relayerCalled = false;
  const result = await ensureFujiMembershipRoot({
    membershipRoot: `0x${"aa".repeat(32)}`,
    applicationId: `0x${"bb".repeat(32)}`,
    policyAuthority: "0xed37fd0d6f0f69236e7472b36796e133d20ecc32",
    wallet: "0xeD37FD0d6F0f69236E7472B36796e133D20EcC32",
    readApplication: async () => ({ membershipVersion: onChainSent ? 5n : 4n, membershipRoot: onChainSent ? `0x${"aa".repeat(32)}` : "0xold" }),
    sendUpdate: async () => { onChainSent = true; return "0xtx"; },
    waitReceipt: async () => ({ status: "0x1" }),
    relayUpdate: async () => { relayerCalled = true; return { membershipVersion: 5n, membershipRoot: `0x${"aa".repeat(32)}` }; },
  });
  assert.equal(onChainSent, true);
  assert.equal(relayerCalled, false);
  assert.equal(result.membershipVersion, 5n);
});

test("ensureFujiMembershipRoot calls relayer BFF for consumer wallets", async () => {
  let relayerPayload = null;
  const result = await ensureFujiMembershipRoot({
    membershipRoot: `0x${"aa".repeat(32)}`,
    applicationId: `0x${"bb".repeat(32)}`,
    policyAuthority: "0xed37fd0d6f0f69236e7472b36796e133d20ecc32",
    wallet: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    readApplication: async () => ({ membershipVersion: 4n, membershipRoot: "0xold" }),
    relayUpdate: async (payload) => {
      relayerPayload = payload;
      return { membershipVersion: 5n, membershipRoot: payload.membershipRoot };
    },
  });
  assert.deepEqual(relayerPayload, {
    applicationId: `0x${"bb".repeat(32)}`,
    membershipRoot: `0x${"aa".repeat(32)}`,
  });
  assert.equal(result.membershipVersion, 5n);
});

test("ensureFujiMembershipRoot throws MEMBERSHIP_RELAYER_UNAVAILABLE when consumer wallet has no relayer", async () => {
  await assert.rejects(
    async () => {
      await ensureFujiMembershipRoot({
        membershipRoot: `0x${"aa".repeat(32)}`,
        applicationId: `0x${"bb".repeat(32)}`,
        policyAuthority: "0xed37fd0d6f0f69236e7472b36796e133d20ecc32",
        wallet: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        readApplication: async () => ({ membershipVersion: 4n, membershipRoot: "0xold" }),
      });
    },
    /MEMBERSHIP_RELAYER_UNAVAILABLE/,
  );
});
test("each browser operation generates eight independent random values", () => {
  let value = 0;
  const secrets = generateBrowserSecrets({ getRandomValues(bytes) { bytes.fill(++value); return bytes; } });
  assert.deepEqual(Object.keys(secrets), ["noteSecret", "blinding", "actionReference", "auditSalt", "recipientHpkeSeed", "auditHpkeSeed", "recipientNoteSecret", "recipientBlinding"]);
  assert.equal(new Set(Object.values(secrets).map((bytes) => bytes[0])).size, 8);
});

test("browser witness seals real recipient and canonical audit envelopes with one action reference", () => {
  let random = 0;
  const result = buildSealedBrowserWitness({
    buildWitness: buildLiveDepositWitness,
    witnessInput: { pool: "0x00BEB0A5D709d0F093952fD374Dbbf3d0d21d550", user: "0xeD37FD0d6F0f69236E7472B36796e133D20EcC32", applicationId: `0x${"00".repeat(30)}0a11`, poolVersion: `0x${"00".repeat(30)}b001`, publicAmount: 1_000_000, applicationPolicyVersion: 8, hazePolicyVersion: 1 },
    chainId: 43113,
    pool: "0x00BEB0A5D709d0F093952fD374Dbbf3d0d21d550",
    poolVersion: `0x${"00".repeat(30)}b001`, applicationId: `0x${"00".repeat(30)}0a11`,
    auditPublicKey: Uint8Array.from("2a082bd0a097bda77158deadbecf043d15e5d09845bf8cfcd2d294d0b0a4ed04".match(/../g), (byte) => Number.parseInt(byte, 16)),
    auditKeyVersion: 1n, caseTag: new TextEncoder().encode("D7-BROWSER"),
    browserCrypto: { getRandomValues(bytes) { bytes.fill(++random); return bytes; } },
  });
  assert.equal(result.witness.actionReference, result.witness.auditFacts.actionReference);
  assert.equal(result.witness.envelopes.recipientCiphertextHash0, result.recipientEnvelope.hash);
  assert.equal(result.witness.envelopes.auditCiphertextHash, result.auditEnvelope.hash);
  assert.notEqual(result.witness.circom.auditDataCommitment, `0x${"00".repeat(32)}`);
});

test("browser witness seals withdrawal without output notes", () => {
  let random = 0;
  const depositWitness = buildSealedBrowserWitness({
    buildWitness: buildLiveDepositWitness,
    witnessInput: { pool: "0x00BEB0A5D709d0F093952fD374Dbbf3d0d21d550", user: "0xeD37FD0d6F0f69236E7472B36796e133D20EcC32", applicationId: `0x${"00".repeat(30)}0a11`, poolVersion: `0x${"00".repeat(30)}b001`, publicAmount: 1_000_000, applicationPolicyVersion: 8, hazePolicyVersion: 1 },
    chainId: 43113,
    pool: "0x00BEB0A5D709d0F093952fD374Dbbf3d0d21d550",
    poolVersion: `0x${"00".repeat(30)}b001`, applicationId: `0x${"00".repeat(30)}0a11`,
    auditPublicKey: Uint8Array.from("2a082bd0a097bda77158deadbecf043d15e5d09845bf8cfcd2d294d0b0a4ed04".match(/../g), (byte) => Number.parseInt(byte, 16)),
    auditKeyVersion: 1n, caseTag: new TextEncoder().encode("D7-DEPOSIT"),
    browserCrypto: { getRandomValues(bytes) { bytes.fill(++random); return bytes; } },
  });

  const result = buildSealedBrowserWitness({
    buildWitness: buildLiveWithdrawWitness,
    witnessInput: {
      pool: "0x00BEB0A5D709d0F093952fD374Dbbf3d0d21d550",
      user: "0xeD37FD0d6F0f69236E7472B36796e133D20EcC32",
      applicationId: `0x${"00".repeat(30)}0a11`,
      poolVersion: `0x${"00".repeat(30)}b001`,
      publicAmount: 1_000_000,
      applicationPolicyVersion: 8,
      hazePolicyVersion: 1,
      publicRecipient: "0xeD37FD0d6F0f69236E7472B36796e133D20EcC32",
      note: depositWitness.witness.note,
      treeLeaves: [{ leafIndex: 0, commitment: depositWitness.witness.note.commitment }],
    },
    chainId: 43113,
    pool: "0x00BEB0A5D709d0F093952fD374Dbbf3d0d21d550",
    poolVersion: `0x${"00".repeat(30)}b001`,
    applicationId: `0x${"00".repeat(30)}0a11`,
    auditPublicKey: Uint8Array.from("2a082bd0a097bda77158deadbecf043d15e5d09845bf8cfcd2d294d0b0a4ed04".match(/../g), (byte) => Number.parseInt(byte, 16)),
    auditKeyVersion: 1n,
    caseTag: new TextEncoder().encode("D7-WITHDRAWAL"),
    browserCrypto: { getRandomValues(bytes) { bytes.fill(++random); return bytes; } },
  });

  assert.equal(result.witness.actionReference, result.witness.auditFacts.actionReference);
  assert.equal(result.witness.envelopes.recipientCiphertextHash0, `0x${"00".repeat(32)}`);
  assert.equal(result.witness.envelopes.auditCiphertextHash, result.auditEnvelope.hash);
  assert.notEqual(result.witness.circom.auditDataCommitment, `0x${"00".repeat(32)}`);
});

test("browser transfer seals envelope opened by recipient and computes matching commitment", () => {
  let random = 0;
  const POOL = "0x00BEB0A5D709d0F093952fD374Dbbf3d0d21d550";
  const APP = `0x${"00".repeat(30)}0a11`;
  const POOL_VERSION = `0x${"00".repeat(30)}b001`;
  const OPERATOR = "0xeD37FD0d6F0f69236E7472B36796e133D20EcC32";
  const AUDIT_PK = Uint8Array.from("2a082bd0a097bda77158deadbecf043d15e5d09845bf8cfcd2d294d0b0a4ed04".match(/../g), (byte) => Number.parseInt(byte, 16));

  const depositWitness = buildSealedBrowserWitness({
    buildWitness: buildLiveDepositWitness,
    witnessInput: { pool: POOL, user: OPERATOR, applicationId: APP, poolVersion: POOL_VERSION, publicAmount: 1_000_000, applicationPolicyVersion: 8, hazePolicyVersion: 1 },
    chainId: 43113,
    pool: POOL,
    poolVersion: POOL_VERSION,
    applicationId: APP,
    auditPublicKey: AUDIT_PK,
    auditKeyVersion: 1n,
    caseTag: new TextEncoder().encode("D7-DEPOSIT"),
    browserCrypto: { getRandomValues(bytes) { bytes.fill(++random); return bytes; } },
  });

  const recipientAccount = deriveShieldedAccount({
    wallet: "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
    signingKey: `0x${"00".repeat(31)}01`,
    chainId: 43113,
    pool: POOL,
    applicationId: APP,
    poolVersion: POOL_VERSION,
  });
  const recipientHazeAddress = encodeHazeAddress({
    chainId: 43113,
    applicationId: APP,
    poolVersion: POOL_VERSION,
    notePublicKey: notePublicKey(recipientAccount.spendingSecret),
    x25519PublicKey: recipientAccount.x25519PublicKey,
  });

  const ownerPublicKey = deriveBrowserX25519PublicKey(Uint8Array.from({ length: 32 }, (_, i) => i + 7));

  const transferResult = buildSealedBrowserTransferWitness({
    buildWitness: buildLiveTransferWitness,
    witnessInput: {
      user: OPERATOR,
      applicationPolicyVersion: 8,
      hazePolicyVersion: 1,
    },
    note: depositWitness.witness.note,
    sendAmount: 400_000,
    recipientAddress: recipientHazeAddress,
    ownerPublicKey,
    chainId: 43113,
    pool: POOL,
    poolVersion: POOL_VERSION,
    applicationId: APP,
    auditPublicKey: AUDIT_PK,
    auditKeyVersion: 1n,
    caseTag: new TextEncoder().encode("D7-TRANSFER"),
    browserCrypto: { getRandomValues(bytes) { bytes.fill(++random); return bytes; } },
  });

  assert.equal(transferResult.witness.circom.action, "2");
  assert.notEqual(transferResult.witness.circom.outputCommitment0, `0x${"00".repeat(32)}`);
  assert.notEqual(transferResult.witness.circom.outputCommitment1, `0x${"00".repeat(32)}`);
  assert.equal(transferResult.witness.note.x25519.toLowerCase(), toHex(ownerPublicKey).toLowerCase());

  const parsedEnvelope = parseEnvelope(parseHex(transferResult.recipientEnvelope0.bytes));
  const aad = recipientAad({
    chainId: 43113,
    pool: POOL,
    poolVersion: POOL_VERSION,
    applicationId: APP,
    outputIndex: 0,
    outputCommitment: transferResult.witness.circom.outputCommitment0,
    envelopeVersion: 1,
  });
  const opened = openRecipientNote({
    recipientIkm: recipientAccount.x25519Secret,
    encapsulatedKey: parsedEnvelope.encapsulatedKey,
    ciphertext: parsedEnvelope.ciphertext,
    info: "haze/avalanche/v1/recipient-note",
    aad,
  });
  const plaintext = parseRecipientPlaintext(opened);
  assert.equal(plaintext.value, 400_000n);
  assert.ok(plaintext.spendingSecret);
  assert.equal(notePublicKey(plaintext.spendingSecret), plaintext.notePublicKey);

  const recomputedCommitment = noteCommitment({
    chainId: 43113,
    pool: POOL,
    poolVersion: POOL_VERSION,
    applicationId: APP,
    value: plaintext.value,
    ownerNotePublicKey: plaintext.notePublicKey,
    ownerEncryptionKeyHash: plaintext.encryptionKeyHash,
    blinding: plaintext.blinding,
  });
  assert.equal(recomputedCommitment, transferResult.witness.circom.outputCommitment0);
});


test("browser transaction persists before broadcast, waits approval, preflights, and matches its event", async () => {
  const calls = [];
  const operation = { id: "op-1", kind: "deposit", state: "ready_to_submit", note: {}, transaction: {} };
  const result = await executeFujiBrowserTransaction({
    operation,
    approvalTransaction: { to: "0xusdc" },
    poolTransaction: { to: "0xpool" },
    send: async (transaction) => { calls.push(transaction.to === "0xusdc" ? "approval-send" : "pool-send"); return transaction.to === "0xusdc" ? "0xapproval" : "0xpool"; },
    waitReceipt: async (hash) => { calls.push(hash === "0xapproval" ? "approval-receipt" : "pool-receipt"); return { status: "0x1", logs: hash === "0xpool" ? [{}] : [] }; },
    preflight: async () => { calls.push("preflight"); },
    markSubmittedBeforeBroadcast: async (_id, transaction, broadcast) => { calls.push(`persist:${transaction.hash}`); return broadcast(); },
    recordSubmittedHash: async (_id, hash) => { calls.push(`hash:${hash}`); },
    reconcile: () => ({ confirmed: true, event: {} }),
  });
  assert.equal(result.confirmed, true);
  assert.deepEqual(calls, ["approval-send", "approval-receipt", "preflight", "persist:pending", "pool-send", "hash:0xpool", "pool-receipt"]);
});

test("executeFujiBrowserTransaction retries preflight through temporary RPC replication lag", async () => {
  let preflightAttempts = 0;
  const sleepCalls = [];
  const operation = { id: "op-2", kind: "deposit", state: "ready_to_submit", note: {}, transaction: {} };
  const result = await executeFujiBrowserTransaction({
    operation,
    poolTransaction: { to: "0xpool" },
    send: async () => "0xpool",
    waitReceipt: async () => ({ status: "0x1", logs: [{}] }),
    preflight: async () => {
      preflightAttempts += 1;
      if (preflightAttempts < 3) {
        throw new Error("REPLICATION_LAG");
      }
    },
    markSubmittedBeforeBroadcast: async (_id, _tx, broadcast) => broadcast(),
    reconcile: () => ({ confirmed: true, event: {} }),
    sleep: async (ms) => { sleepCalls.push(ms); },
  });
  assert.equal(result.confirmed, true);
  assert.equal(preflightAttempts, 3);
  assert.deepEqual(sleepCalls, [2_000, 2_000]);
});

test("browser withdrawal remains spendable when receipt or event reconciliation fails", async () => {
  for (const receipt of [undefined, { status: "0x0", logs: [] }, { status: "0x1", logs: [] }]) {
    const result = await executeFujiBrowserTransaction({
      operation: { id: "op-w", kind: "withdrawal", state: "ready_to_submit", note: { secret: "kept" }, transaction: {} },
      poolTransaction: { to: "0xpool" },
      send: async () => "0xpool",
      waitReceipt: async () => receipt,
      preflight: async () => {},
      markSubmittedBeforeBroadcast: async (_id, _transaction, broadcast) => broadcast(),
      reconcile: () => ({ confirmed: false, noteSpendable: true }),
    });
    assert.equal(result.noteSpendable, true);
  }
});

test("wallet disclosure uses only Rust-supported fields and binds their canonical hash", () => {
  const plan = planFujiWithdrawalDisclosure({
    transactionHash: `0x${"12".repeat(32)}`,
    applicationId: `0x${"34".repeat(32)}`,
    pool: "0x00BEB0A5D709d0F093952fD374Dbbf3d0d21d550",
    chainId: 43113,
    expiresAt: 1_800_000_000,
  });
  assert.deepEqual(plan.requestedFields, ["user", "amount", "counterparty", "tx_hash", "policy_version"]);
  assert.equal(plan.typedData.message.requestedFieldsHash, "0x4ffe502c8216dceb08eb87ea2edb4ee202c3afb1aac2ccaf6e4dcffae1a80853");
  assert.equal(plan.typedData.message.transactionHash, `0x${"12".repeat(32)}`);
});

test("encodeBrowserSwapAndShield encodes swapAndShield with dynamic tuple offsets and validates route", () => {
  const fakeWitness = {
    actionReference: "0x" + "11".repeat(32),
    circom: {
      noteTreeRoot: "0x" + "00".repeat(32),
      applicationPolicyVersion: "1",
      hazePolicyVersion: "1",
      applicationMembershipRoot: "0x" + "00".repeat(32),
      hazeBlocklistRoot: "0x" + "00".repeat(32),
      inputNullifier0: "0x" + "00".repeat(32),
      inputNullifier1: "0x" + "00".repeat(32),
      outputCommitment0: "0x" + "22".repeat(32),
      outputCommitment1: "0x" + "00".repeat(32),
      publicAmount: "1000000",
      auditDataCommitment: "0x" + "33".repeat(32),
    },
    envelopes: {
      recipientCiphertextHash0: "0x" + "44".repeat(32),
      recipientCiphertextHash1: "0x" + "00".repeat(32),
      auditCiphertextHash: "0x" + "55".repeat(32),
      recipientCiphertext0: "0x" + "66".repeat(32),
      recipientCiphertext1: "0x",
      auditCiphertext: "0x" + "77".repeat(64),
    },
  };
  const plan = planBrowserFujiSpend({
    witness: fakeWitness,
    user: "0x" + "88".repeat(20),
    pool: "0x" + "99".repeat(20),
    poolVersion: "0x" + "aa".repeat(32),
    applicationId: "0x" + "bb".repeat(32),
    action: 4,
    now: 1700000000,
    proof: "0x" + "cc".repeat(256),
    tokenIn: "0x" + "dd".repeat(20),
    amountIn: "0x" + "ee".repeat(32),
    minUsdcOut: 1000000n,
    routeHash: "0x" + "ff".repeat(32),
    deadline: 1700003600n,
  });
  const signature = "0x" + "12".repeat(65);
  const route = {
    adapter: "0x" + "34".repeat(20),
    data: "0x" + "56".repeat(64),
    expectedRouteHash: "0x" + "ff".repeat(32),
  };
  const routerAddress = "0x" + "ab".repeat(20);

  const encoded = encodeBrowserSwapAndShield({
    router: routerAddress,
    plan,
    signature,
    route,
  });

  assert.equal(encoded.to, routerAddress);
  assert.ok(encoded.data.startsWith("0x"));
  assert.equal(encoded.data.slice(0, 10), ROUTER_SELECTORS.swapAndShield);
  assert.ok(encoded.data.length > 200);

  // Rejects incomplete inputs
  assert.throws(() => encodeBrowserSwapAndShield({ router: "", plan, signature, route }), /ENCODING_INVALID/);
  assert.throws(() => encodeBrowserSwapAndShield({ router: routerAddress, plan, signature, route: { ...route, adapter: "" } }), /ENCODING_INVALID/);
});

test("planBrowserFujiSpend canonicalizes every supported uint256 amountIn representation", () => {
  const witness = {
    actionReference: "0x" + "11".repeat(32),
    circom: {
      noteTreeRoot: "0x" + "00".repeat(32), applicationPolicyVersion: "1", hazePolicyVersion: "1",
      applicationMembershipRoot: "0x" + "00".repeat(32), hazeBlocklistRoot: "0x" + "00".repeat(32),
      inputNullifier0: "0x" + "00".repeat(32), inputNullifier1: "0x" + "00".repeat(32),
      outputCommitment0: "0x" + "22".repeat(32), outputCommitment1: "0x" + "00".repeat(32),
      publicAmount: "1500000", auditDataCommitment: "0x" + "33".repeat(32),
    },
    envelopes: {
      recipientCiphertextHash0: "0x" + "44".repeat(32), recipientCiphertextHash1: "0x" + "00".repeat(32),
      auditCiphertextHash: "0x" + "55".repeat(32), recipientCiphertext0: "0x" + "66".repeat(32),
      recipientCiphertext1: "0x", auditCiphertext: "0x" + "77".repeat(64),
    },
  };
  const common = {
    witness, user: "0x" + "88".repeat(20), pool: "0x" + "99".repeat(20),
    poolVersion: "0x" + "aa".repeat(32), applicationId: "0x" + "bb".repeat(32),
    action: 4, now: 1700000000, proof: "0x" + "cc".repeat(256),
  };
  const canonical = `0x${(2_000_000n).toString(16).padStart(64, "0")}`;
  for (const amountIn of ["2000000", 2_000_000, 2_000_000n, canonical]) {
    assert.equal(planBrowserFujiSpend({ ...common, amountIn }).intent.amountIn, canonical);
  }
});

test("planBrowserFujiSpend rejects malformed and out-of-range uint256 amountIn", () => {
  const witness = {
    actionReference: "0x" + "11".repeat(32),
    circom: {
      noteTreeRoot: "0x" + "00".repeat(32), applicationPolicyVersion: "1", hazePolicyVersion: "1",
      applicationMembershipRoot: "0x" + "00".repeat(32), hazeBlocklistRoot: "0x" + "00".repeat(32),
      inputNullifier0: "0x" + "00".repeat(32), inputNullifier1: "0x" + "00".repeat(32),
      outputCommitment0: "0x" + "22".repeat(32), outputCommitment1: "0x" + "00".repeat(32),
      publicAmount: "1500000", auditDataCommitment: "0x" + "33".repeat(32),
    },
    envelopes: {
      recipientCiphertextHash0: "0x" + "44".repeat(32), recipientCiphertextHash1: "0x" + "00".repeat(32),
      auditCiphertextHash: "0x" + "55".repeat(32), recipientCiphertext0: "0x", recipientCiphertext1: "0x", auditCiphertext: "0x",
    },
  };
  const common = {
    witness, user: "0x" + "88".repeat(20), pool: "0x" + "99".repeat(20),
    poolVersion: "0x" + "aa".repeat(32), applicationId: "0x" + "bb".repeat(32),
    action: 4, now: 1700000000, proof: "0x",
  };
  for (const amountIn of ["2.5", "-1", "0x12", Number.MAX_SAFE_INTEGER + 1, -1n, 1n << 256n]) {
    assert.throws(() => planBrowserFujiSpend({ ...common, amountIn }), /ENCODING_INVALID/);
  }
});

test("sealed non-1:1 swap flows through proof, planner, and router calldata", () => {
  let random = 0;
  const pool = "0x00BEB0A5D709d0F093952fD374Dbbf3d0d21d550";
  const user = "0xeD37FD0d6F0f69236E7472B36796e133D20EcC32";
  const applicationId = `0x${"00".repeat(30)}0a11`;
  const poolVersion = `0x${"00".repeat(30)}b001`;
  const tokenIn = "0x4fAB93a23313CC032D8310Cf0f34A9BDF4E19c72";
  const adapter = "0x30d94144722582BCDbcB030dDa274d9CE7ab4baB";
  const data = "0x12345678";
  const routeHash = swapRouteHash(adapter, data);
  const sealed = buildSealedBrowserWitness({
    buildWitness: buildLiveSwapWitness,
    witnessInput: {
      pool, user, applicationId, poolVersion, tokenIn, amountIn: "2000000", value: "1500000",
      minUsdcOut: 1_490_000, routeHash, deadline: 1_700_003_600,
      applicationPolicyVersion: 8, hazePolicyVersion: 1,
    },
    chainId: 43113, pool, poolVersion, applicationId,
    auditPublicKey: Uint8Array.from("2a082bd0a097bda77158deadbecf043d15e5d09845bf8cfcd2d294d0b0a4ed04".match(/../g), (byte) => Number.parseInt(byte, 16)),
    auditKeyVersion: 1n, caseTag: new TextEncoder().encode("SWAP"),
    browserCrypto: { getRandomValues(bytes) { bytes.fill(++random); return bytes; } },
  });
  const proof = deriveDevelopmentSpendProof(sealed.witness.circom);
  const plan = planBrowserFujiSpend({
    witness: sealed.witness, user, pool, poolVersion, applicationId, action: 4,
    now: 1_700_000_000, proof, tokenIn, amountIn: "2000000", minUsdcOut: 1_490_000,
    routeHash, deadline: 1_700_003_600,
  });
  const encoded = encodeBrowserSwapAndShield({
    router: "0xdb386aeAd1C0b859903702454a7ECDfC306800F6", plan,
    signature: `0x${"12".repeat(65)}`, route: { adapter, data, expectedRouteHash: routeHash },
  });
  assert.equal(sealed.witness.circom.publicAmount, "1500000");
  assert.equal(sealed.witness.note.value, 1_500_000);
  assert.equal(plan.intent.amountIn, `0x${(2_000_000n).toString(16).padStart(64, "0")}`);
  assert.equal(plan.intent.minUsdcOut, 1_490_000);
  assert.match(proof, /^0x[0-9a-f]{64}$/);
  assert.ok(encoded.data.length > 200);
});

test("encodeEmergencyExitRequest and encodeEmergencyExitExecute encode emergency exit functions and validate inputs", () => {
  const emergencyContract = "0x" + "ee".repeat(20);
  const requestId = "0x" + "11".repeat(32);

  const req = encodeEmergencyExitRequest(emergencyContract, requestId);
  assert.equal(req.to, emergencyContract);
  assert.equal(req.data.length, 10 + 64); // 4 bytes selector (8 hex + 0x) + 32 bytes requestId (64 hex)

  assert.throws(() => encodeEmergencyExitRequest("", requestId), /ENCODING_INVALID/);
  assert.throws(() => encodeEmergencyExitRequest(emergencyContract, "0x00"), /ENCODING_INVALID/);

  const exec = encodeEmergencyExitExecute(emergencyContract, {
    applicationId: "0x" + "22".repeat(32),
    noteTreeRoot: "0x" + "33".repeat(32),
    hazePolicyVersion: 1n,
    hazeBlocklistRoot: "0x" + "44".repeat(32),
    nullifier: "0x" + "55".repeat(32),
    publicAmount: 1000000n,
    recipient: "0x" + "66".repeat(20),
    requester: "0x" + "77".repeat(20),
    requestSalt: "0x" + "88".repeat(32),
    auditDataCommitment: "0x" + "99".repeat(32),
    auditCiphertextHash: "0x" + "aa".repeat(32),
    auditCiphertext: "0x" + "bb".repeat(64),
    proof: "0x" + "cc".repeat(256),
  });
  assert.equal(exec.to, emergencyContract);
  assert.ok(exec.data.startsWith("0x"));

  assert.throws(() => encodeEmergencyExitExecute("", {}), /ENCODING_INVALID/);
});
