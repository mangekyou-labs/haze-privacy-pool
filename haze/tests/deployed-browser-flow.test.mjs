import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  executeFujiBrowserTransaction,
  updateFujiMembershipRoot,
} from "../sdk/typescript/src/browser-fuji-flow.ts";
import {
  encodeBrowserSwapAndShield,
  encodeEmergencyExitExecute,
  encodeEmergencyExitRequest,
} from "../sdk/typescript/src/browser-fuji-contracts.ts";
import { generateBrowserSecrets } from "../sdk/typescript/src/browser-prover.ts";
import {
  buildSealedBrowserTransferWitness,
  buildSealedBrowserWitness,
} from "../sdk/typescript/src/browser-witness-flow.ts";
import {
  buildLiveDepositWitness,
  buildLiveTransferWitness,
  buildLiveWithdrawWitness,
} from "../dev/operator-circuit-witness.mjs";
import {
  decodeBrowserEnvelope,
  openBrowserHpke,
  parseBrowserRecipientPlaintext,
} from "../sdk/typescript/src/browser-crypto.ts";
import { noteCommitment } from "../sdk/typescript/src/note.ts";

const HAZE = resolve(dirname(fileURLToPath(import.meta.url)), "..");

test("membership update waits for success and binds the refetched policy version", async () => {
  const calls = [];
  const result = await updateFujiMembershipRoot({
    membershipRoot: `0x${"12".repeat(32)}`,
    applicationId: `0x${"34".repeat(32)}`,
    policyAuthority: "0xed37fd0d6f0f69236e7472b36796e133d20ecc32",
    wallet: "0xeD37FD0d6F0f69236E7472B36796e133D20EcC32",
    readApplication: async () => ({
      membershipVersion: calls.length === 0 ? 7n : 8n,
      membershipRoot: calls.length === 0 ? "0xold" : `0x${"12".repeat(32)}`,
    }),
    sendUpdate: async () => {
      calls.push("send");
      return "0xupdate";
    },
    waitReceipt: async () => {
      calls.push("receipt");
      return { status: "0x1" };
    },
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

test("membership update returns existing snapshot without sending transaction when root matches", async () => {
  let sent = false;
  const result = await updateFujiMembershipRoot({
    membershipRoot: `0x${"12".repeat(32)}`,
    applicationId: `0x${"34".repeat(32)}`,
    policyAuthority: "0xed37fd0d6f0f69236e7472b36796e133d20ecc32",
    wallet: "0xeD37FD0d6F0f69236E7472B36796e133D20EcC32",
    readApplication: async () => ({
      membershipVersion: 9n,
      membershipRoot: `0x${"12".repeat(32)}`,
    }),
    sendUpdate: async () => {
      sent = true;
      return "0xupdate";
    },
    waitReceipt: async () => ({ status: "0x1" }),
  });
  assert.equal(sent, false);
  assert.equal(result.membershipVersion, 9n);
});

test("membership update throws MEMBERSHIP_UPDATE_FAILED if receipt status is not 0x1", async () => {
  await assert.rejects(
    async () => {
      await updateFujiMembershipRoot({
        membershipRoot: `0x${"12".repeat(32)}`,
        applicationId: `0x${"34".repeat(32)}`,
        policyAuthority: "0xed37fd0d6f0f69236e7472b36796e133d20ecc32",
        wallet: "0xeD37FD0d6F0f69236E7472B36796e133D20EcC32",
        readApplication: async () => ({ membershipVersion: 1n, membershipRoot: "0xold" }),
        sendUpdate: async () => "0xhash",
        waitReceipt: async () => ({ status: "0x0" }),
      });
    },
    /MEMBERSHIP_UPDATE_FAILED/,
  );
});

test("membership update throws POLICY_AUTHORITY_REQUIRED if caller is not policy authority", async () => {
  await assert.rejects(
    async () => {
      await updateFujiMembershipRoot({
        membershipRoot: `0x${"12".repeat(32)}`,
        applicationId: `0x${"34".repeat(32)}`,
        policyAuthority: "0xed37fd0d6f0f69236e7472b36796e133d20ecc32",
        wallet: "0x1111111111111111111111111111111111111111",
        readApplication: async () => ({ membershipVersion: 1n, membershipRoot: "0xold" }),
        sendUpdate: async () => "0xhash",
        waitReceipt: async () => ({ status: "0x1" }),
      });
    },
    /POLICY_AUTHORITY_REQUIRED/,
  );
});

test("executeFujiBrowserTransaction preflights, submits and reconciles receipt", async () => {
  const calls = [];
  const result = await executeFujiBrowserTransaction({
    operation: { id: "op_test", kind: "deposit", transaction: {} },
    approvalTransaction: { to: "0xusdc", data: "0xapprove" },
    poolTransaction: { to: "0xpool", data: "0xpooltx" },
    send: async (tx) => {
      calls.push(`send:${tx.to}`);
      return "0xhash";
    },
    waitReceipt: async () => {
      calls.push("receipt");
      return { status: "0x1" };
    },
    preflight: async () => {
      calls.push("preflight");
    },
    markSubmittedBeforeBroadcast: async (_id, _tx, broadcast) => broadcast(),
    reconcile: () => ({ confirmed: true }),
  });

  assert.equal(result.confirmed, true);
  assert.equal(result.transactionHash, "0xhash");
  assert.deepEqual(calls, ["send:0xusdc", "receipt", "preflight", "send:0xpool", "receipt"]);
});
