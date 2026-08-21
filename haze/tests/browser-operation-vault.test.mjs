import assert from "node:assert/strict";
import test from "node:test";
import { createBrowserOperationVault, createMemoryIndexedDb, deriveBrowserVaultKey } from "../sdk/typescript/src/browser-operation-vault.ts";

const binding = { chainId: 43113, applicationId: `0x${"aa".repeat(32)}`, pool: `0x${"11".repeat(20)}`, wallet: `0x${"22".repeat(20)}` };
const signature = `0x${"33".repeat(65)}`;

test("wallet signature derivation is stable and bound to wallet, app, pool, and chain", async () => {
  const a = await deriveBrowserVaultKey(signature, binding);
  const b = await deriveBrowserVaultKey(signature, binding);
  assert.deepEqual([...a], [...b]);
  assert.notDeepEqual([...a], [...await deriveBrowserVaultKey(signature, { ...binding, wallet: `0x${"44".repeat(20)}` })]);
});

test("encrypted IndexedDB operation state recovers after a browser restart", async () => {
  const database = createMemoryIndexedDb();
  const first = await createBrowserOperationVault({ database, signature, binding });
  await first.create({ id: "op-1", kind: "withdrawal", note: { commitment: `0x${"55".repeat(32)}`, blinding: `0x${"66".repeat(32)}` }, transaction: { to: binding.pool, data: "0x1234" } });
  await first.transition("op-1", "ready_to_submit");
  await first.transition("op-1", "submitted", { transactionHash: `0x${"77".repeat(32)}` });
  const stored = await database.get(first.storageKey);
  assert.equal(new TextDecoder().decode(stored).includes("55555555"), false);
  assert.equal(new TextDecoder().decode(stored).includes("66666666"), false);

  const restarted = await createBrowserOperationVault({ database, signature, binding });
  assert.deepEqual(await restarted.get("op-1"), {
    id: "op-1", kind: "withdrawal", state: "submitted",
    note: { commitment: `0x${"55".repeat(32)}`, blinding: `0x${"66".repeat(32)}` },
    transaction: { to: binding.pool, data: "0x1234", transactionHash: `0x${"77".repeat(32)}` },
  });
});

test("operation states follow proving to terminal transitions and persist before broadcast", async () => {
  const database = createMemoryIndexedDb();
  const vault = await createBrowserOperationVault({ database, signature, binding });
  await vault.create({ id: "op-2", kind: "deposit", note: { commitment: "0x01" }, transaction: { to: binding.pool, data: "0x" } });
  assert.equal((await vault.get("op-2")).state, "proving");
  await assert.rejects(() => vault.transition("op-2", "submitted"), /INVALID_STATE/);
  await vault.transition("op-2", "ready_to_submit");
  let broadcastObservedPersisted = false;
  await vault.markSubmittedBeforeBroadcast("op-2", { transactionHash: `0x${"88".repeat(32)}` }, async () => {
    broadcastObservedPersisted = (await vault.get("op-2")).state === "submitted";
  });
  assert.equal(broadcastObservedPersisted, true);
  await vault.transition("op-2", "confirmed");
  await assert.rejects(() => vault.transition("op-2", "failed"), /INVALID_STATE/);
});
