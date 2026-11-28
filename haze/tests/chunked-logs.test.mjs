import assert from "node:assert/strict";
import test from "node:test";
import { createChunkedLogReader, blockWindows } from "../sdk/typescript/src/chunked-logs.ts";
import { FUJI_V2 } from "../sdk/typescript/src/fuji-v2-defaults.ts";
import live from "../deployments/fuji-v2.live.json" with { type: "json" };

const hex = (n) => `0x${n.toString(16)}`;

// Fake RPC that enforces the Fuji 100-block limit and serves one log per block in a set.
function fakeRpc({ head, logBlocks, failOnce = new Set() }) {
  const calls = [];
  const failed = new Set();
  let current = head;
  const rpc = async (method, params) => {
    calls.push({ method, params });
    if (method === "eth_blockNumber") return hex(current);
    if (method !== "eth_getLogs") throw new Error(`unexpected ${method}`);
    const { fromBlock, toBlock, address, topics } = params[0];
    const from = Number(BigInt(fromBlock));
    const to = Number(BigInt(toBlock));
    if (to - from + 1 > 100) throw { code: -32602, message: "block range too large" };
    if (failOnce.has(from) && !failed.has(from)) { failed.add(from); throw new Error("flaky"); }
    return logBlocks.filter((b) => b >= from && b <= to).map((b) => ({ blockNumber: hex(b), logIndex: "0x0", address, topics, data: "0x" }));
  };
  return { rpc, calls, setHead: (h) => { current = h; } };
}

test("FUJI_V2 carries the live deployment block", () => {
  assert.equal(FUJI_V2.deploymentBlock, live.deploymentBlock);
});

test("blockWindows splits an inclusive range into <=100-block windows", () => {
  assert.deepEqual(blockWindows(10, 259, 100), [[10, 109], [110, 209], [210, 259]]);
  assert.deepEqual(blockWindows(5, 5, 100), [[5, 5]]);
  assert.deepEqual(blockWindows(6, 5, 100), []);
});

test("reads every log from the start block to head without any range over 100", async () => {
  const logBlocks = [1000, 1099, 1100, 1555, 3999];
  const fake = fakeRpc({ head: 4000, logBlocks, failOnce: new Set([1100]) });
  const reader = createChunkedLogReader({ rpc: fake.rpc, startBlock: 1000, concurrency: 4, retries: 2 });
  const logs = await reader.read({ address: "0xpool", topics: ["0xt"] });
  assert.deepEqual(logs.map((l) => Number(BigInt(l.blockNumber))), logBlocks);
  for (const c of fake.calls.filter((c) => c.method === "eth_getLogs")) {
    assert.ok(Number(BigInt(c.params[0].toBlock)) - Number(BigInt(c.params[0].fromBlock)) < 100);
  }
});

test("caches fetched ranges and only fetches new blocks on the next read", async () => {
  const fake = fakeRpc({ head: 1500, logBlocks: [1200, 1600] });
  const reader = createChunkedLogReader({ rpc: fake.rpc, startBlock: 1000 });
  const filter = { address: "0xpool", topics: ["0xt"] };
  assert.equal((await reader.read(filter)).length, 1);
  fake.calls.length = 0;
  fake.setHead(1650);
  const logs = await reader.read(filter);
  assert.deepEqual(logs.map((l) => Number(BigInt(l.blockNumber))), [1200, 1600]);
  const ranges = fake.calls.filter((c) => c.method === "eth_getLogs").map((c) => c.params[0].fromBlock);
  assert.deepEqual(ranges, [hex(1501), hex(1601)]);
});

test("a window that keeps failing rejects the read instead of returning partial logs", async () => {
  const rpc = async (method) => { if (method === "eth_blockNumber") return hex(1300); throw new Error("down"); };
  const reader = createChunkedLogReader({ rpc, startBlock: 1000, retries: 1 });
  await assert.rejects(reader.read({ address: "0xpool", topics: [] }), /down/);
});
