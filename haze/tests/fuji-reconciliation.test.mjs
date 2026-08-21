import assert from "node:assert/strict";
import test from "node:test";
import { keccak_256 } from "@noble/hashes/sha3";
import {
  PRIVATE_TRANSACTION_TOPIC,
  broadcastFujiTransaction,
  reconcileFujiOperation,
  recoverFujiOperation,
} from "../sdk/typescript/src/fuji-reconciliation.ts";

const hex = (byte, bytes = 32) => `0x${byte.repeat(bytes)}`;
const word = (value) => BigInt(value).toString(16).padStart(64, "0");
const addressTopic = (value) => `0x${"0".repeat(24)}${value.slice(2).toLowerCase()}`;
const config = {
  chainId: 43113,
  pool: hex("11", 20),
  poolVersion: hex("22"),
  applicationId: hex("33"),
  user: hex("44", 20),
  action: 2,
  commitment: hex("55"),
  nullifier: hex("66"),
};

function event(overrides = {}) {
  const values = { nullifier0: config.nullifier, output0: config.commitment, ...overrides };
  const data = [1, 2, 3, values.nullifier0, 0, values.output0, 0, 100, BigInt(config.user), 7, 8, 9, 10, 448, 480, 512]
    .map(word).join("");
  return {
    address: config.pool,
    topics: [PRIVATE_TRANSACTION_TOPIC, config.applicationId, `0x${word(config.action)}`, addressTopic(config.user)],
    data: `0x${data}`,
  };
}

test("PrivateTransaction topic is derived from the deployed event signature", () => {
  const signature = "PrivateTransaction(bytes32,uint8,address,uint64,uint64,uint256,uint256,uint256,uint256,uint256,uint64,address,bytes32,bytes32,uint256,bytes32,bytes,bytes,bytes)";
  assert.equal(PRIVATE_TRANSACTION_TOPIC, `0x${Buffer.from(keccak_256(signature)).toString("hex")}`);
});

test("deposit approval must succeed before the final eth_call and broadcast", async () => {
  const calls = [];
  const rpc = async (method) => {
    calls.push(method);
    if (method === "eth_getTransactionReceipt") return { status: "0x0" };
    throw new Error("must not continue");
  };
  await assert.rejects(() => broadcastFujiTransaction({ rpc, transaction: { to: config.pool, data: "0x12" }, approvalHash: hex("aa") }), /APPROVAL_NOT_SUCCESSFUL/);
  assert.deepEqual(calls, ["eth_getTransactionReceipt"]);
});

test("every broadcast performs a final Fuji eth_call immediately before send", async () => {
  const calls = [];
  const rpc = async (method) => {
    calls.push(method);
    if (method === "eth_getTransactionReceipt") return { status: "0x1" };
    if (method === "eth_call") return "0x";
    if (method === "eth_sendTransaction") return hex("77");
  };
  assert.equal(await broadcastFujiTransaction({ rpc, transaction: { to: config.pool, data: "0x12" }, approvalHash: hex("aa") }), hex("77"));
  assert.deepEqual(calls, ["eth_getTransactionReceipt", "eth_call", "eth_sendTransaction"]);
});

test("receipt and matching event are both required; failed withdrawals remain spendable", () => {
  const cases = [
    [undefined, "RECEIPT_MISSING"],
    [{ status: "0x0", logs: [event()] }, "RECEIPT_REVERTED"],
    [{ status: "0x1", logs: [] }, "EVENT_MISSING"],
    [{ status: "0x1", logs: [event({ output0: hex("99") })] }, "EVENT_MISMATCH"],
  ];
  for (const [receipt, reason] of cases) {
    const result = reconcileFujiOperation({ ...config, kind: "withdrawal", receipt });
    assert.equal(result.confirmed, false);
    assert.equal(result.noteSpendable, true);
    assert.equal(result.reason, reason);
    assert.equal(result.disclosureState, "not_requested");
  }
  const success = reconcileFujiOperation({ ...config, kind: "withdrawal", receipt: { status: "0x1", logs: [event()] } });
  assert.equal(success.confirmed, true);
  assert.equal(success.noteSpendable, false);
  assert.equal(success.disclosureState, "not_requested");
});

test("submitted operations recover by transaction hash and commitment/nullifier log scans", async () => {
  const receipt = { status: "0x1", transactionHash: hex("77"), logs: [event()] };
  const rpc = async (method) => method === "eth_getTransactionReceipt" ? receipt : [event()];
  assert.equal((await recoverFujiOperation({ rpc, ...config, kind: "withdrawal", transactionHash: hex("77") })).confirmed, true);
  assert.equal((await recoverFujiOperation({ rpc, ...config, kind: "deposit" })).confirmed, true);
});
