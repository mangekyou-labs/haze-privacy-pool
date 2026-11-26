import assert from "node:assert/strict";
import test from "node:test";
import { createBrowserOperationVault, createMemoryIndexedDb, deriveBrowserVaultKey, isConfirmedSpendableInput } from "../sdk/typescript/src/browser-operation-vault.ts";
import * as operationVault from "../sdk/typescript/src/browser-operation-vault.ts";

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
  await vault.transition("op-2", "pending_finality");
  await vault.transition("op-2", "confirmed");
  await assert.rejects(() => vault.transition("op-2", "failed"), /INVALID_STATE/);
});

test("vault.wipe requires strictly WIPE confirmation and deletes storage key", async () => {
  const database = createMemoryIndexedDb();
  const vault = await createBrowserOperationVault({ database, signature, binding });
  await vault.create({ id: "op-wipe", kind: "deposit", note: { commitment: "0x01" }, transaction: { to: binding.pool, data: "0x" } });
  assert.equal((await vault.list()).length, 1);
  assert.ok(await database.get(vault.storageKey));

  // Rejects invalid confirmation
  await assert.rejects(() => vault.wipe("wipe"), /INVALID_CONFIRMATION/);
  await assert.rejects(() => vault.wipe(""), /INVALID_CONFIRMATION/);

  // Succeeds with exact "WIPE"
  await vault.wipe("WIPE");
  assert.equal((await vault.list()).length, 0);
  assert.equal(await database.get(vault.storageKey), undefined);
});

test("vault.delete removes a single operation", async () => {
  const database = createMemoryIndexedDb();
  const vault = await createBrowserOperationVault({ database, signature, binding });
  await vault.create({ id: "op-del-1", kind: "deposit", note: { commitment: "0x01" }, transaction: { to: binding.pool, data: "0x" } });
  await vault.create({ id: "op-del-2", kind: "withdrawal", note: { commitment: "0x02" }, transaction: { to: binding.pool, data: "0x" } });
  assert.equal((await vault.list()).length, 2);

  const deleted = await vault.delete("op-del-1");
  assert.equal(deleted, true);
  assert.equal((await vault.list()).length, 1);
  assert.equal(await vault.get("op-del-1"), undefined);
  assert.ok(await vault.get("op-del-2"));
});

test("vault stores rich transaction metadata and guards note consumption until confirmed finality", async () => {
  const database = createMemoryIndexedDb();
  const vault = await createBrowserOperationVault({ database, signature, binding });
  await vault.create({
    id: "op-meta",
    kind: "migration",
    note: { commitment: "0x01", spendable: true },
    transaction: {
      to: binding.pool,
      target: binding.pool,
      action: 3,
      workflowGroupId: "wf-123",
      migrationStep: "b002_withdraw",
      emergencyRequestState: {
        salt: "0x" + "aa".repeat(32),
        requestId: "0x" + "bb".repeat(32),
        requestedAtBlock: 100,
        eligibleAtBlock: 200,
      },
    },
  });

  await vault.transition("op-meta", "ready_to_submit");
  await vault.transition("op-meta", "submitted", { hash: "0x" + "99".repeat(32) });

  // Note CANNOT be consumed while submitted
  await assert.rejects(() => vault.consumeConfirmedNote("op-meta"), /INVALID_STATE/);

  await vault.transition("op-meta", "pending_finality", {
    finalityProvenance: {
      inclusionBlock: 100,
      confirmationCount: 6,
      canonicalBlockHash: "0x" + "cc".repeat(32),
      verifiedAtBlock: 105,
    },
  });

  // Note CANNOT be consumed while pending_finality
  await assert.rejects(() => vault.consumeConfirmedNote("op-meta"), /INVALID_STATE/);

  await vault.transition("op-meta", "confirmed", {
    finalityProvenance: {
      inclusionBlock: 100,
      confirmationCount: 12,
      canonicalBlockHash: "0x" + "cc".repeat(32),
      verifiedAtBlock: 111,
    },
  });

  // Now note can be consumed
  const consumed = await vault.consumeConfirmedNote("op-meta");
  assert.equal(consumed.note.spendable, false);
  assert.equal(consumed.transaction.workflowGroupId, "wf-123");
  assert.equal(consumed.transaction.migrationStep, "b002_withdraw");
  assert.equal(consumed.transaction.finalityProvenance.confirmationCount, 12);
  assert.equal(consumed.transaction.emergencyRequestState.requestId, "0x" + "bb".repeat(32));
});

const recoveredNote = {
  commitment: `0x${"aa".repeat(32)}`,
  value: 1_000_000,
  secret: `0x${"11".repeat(32)}`,
  blinding: `0x${"22".repeat(32)}`,
  npk: `0x${"33".repeat(32)}`,
  enc: `0x${"44".repeat(32)}`,
  x25519: `0x${"77".repeat(32)}`,
  nullifier: `0x${"55".repeat(32)}`,
  leafIndex: 24,
  spendable: true,
  transactionHash: `0x${"66".repeat(32)}`,
};

test("confirmed spendable recovered deposit and transfer notes are eligible inputs while other operations are excluded", () => {
  const candidate = (kind, state = "confirmed", spendable = true) => ({
    id: `op-${kind}-${state}-${String(spendable)}`,
    kind,
    state,
    note: { spendable },
    transaction: {},
  });

  assert.equal(operationVault.isConfirmedSpendableInput(candidate("deposit")), true);
  assert.equal(operationVault.isConfirmedSpendableInput(candidate("transfer")), true);
  assert.equal(operationVault.isConfirmedSpendableInput(candidate("swap")), false);
  assert.equal(operationVault.isConfirmedSpendableInput(candidate("withdrawal")), false);
  assert.equal(operationVault.isConfirmedSpendableInput(candidate("deposit", "proving")), false);
  assert.equal(operationVault.isConfirmedSpendableInput(candidate("transfer", "confirmed", false)), false);
});

test("persistRecoveredSpendableNotes writes confirmed spendable deposits", async () => {
  const database = createMemoryIndexedDb();
  const vault = await createBrowserOperationVault({ database, signature, binding });
  const [op] = await vault.persistRecoveredSpendableNotes([recoveredNote]);
  assert.equal(op.state, "confirmed");
  assert.equal(op.kind, "deposit");
  assert.equal(op.note.spendable, true);
  assert.equal(op.note.commitment, recoveredNote.commitment);
  assert.equal(op.note.npk, recoveredNote.npk);
  assert.equal(op.note.enc, recoveredNote.enc);
  assert.equal(op.note.nullifier, recoveredNote.nullifier);
  assert.equal(op.note.leafIndex, 24);
  assert.equal(op.note.value, 1_000_000);
  assert.equal(op.note.secret, recoveredNote.secret);
  assert.equal(op.note.x25519, recoveredNote.x25519);
  assert.equal((await vault.list()).filter(isConfirmedSpendableInput).length, 1);
});

test("persistRecoveredSpendableNotes retains Swap provenance and keeps it out of the deposit spend path", async () => {
  const database = createMemoryIndexedDb();
  const vault = await createBrowserOperationVault({ database, signature, binding });
  const [op] = await vault.persistRecoveredSpendableNotes([{ ...recoveredNote, action: 4 }]);
  assert.equal(op.kind, "swap");
  assert.equal(op.transaction.action, 4);
  assert.equal((await vault.list()).filter(isConfirmedSpendableInput).length, 0);
});

test("persistRecoveredSpendableNotes updates existing confirmed notes when recover marks them unspendable", async () => {
  const database = createMemoryIndexedDb();
  const vault = await createBrowserOperationVault({ database, signature, binding });
  await vault.persistRecoveredSpendableNotes([recoveredNote]);
  const [op] = await vault.persistRecoveredSpendableNotes([{ ...recoveredNote, spendable: false }]);
  assert.equal(op.note.spendable, false);
  assert.equal((await vault.list()).filter(isConfirmedSpendableInput).length, 0);
});

test("create still starts proving and cannot jump to confirmed", async () => {
  const database = createMemoryIndexedDb();
  const vault = await createBrowserOperationVault({ database, signature, binding });
  await vault.create({
    id: "op-live",
    kind: "deposit",
    note: { commitment: recoveredNote.commitment, spendable: true },
    transaction: {},
  });
  assert.equal((await vault.get("op-live")).state, "proving");
  await assert.rejects(() => vault.transition("op-live", "confirmed"), /INVALID_STATE/);
  assert.equal((await vault.list()).filter(isConfirmedSpendableInput).length, 0);
});

test("persistRecoveredSpendableNotes upgrades a proving stub with the same commitment", async () => {
  const database = createMemoryIndexedDb();
  const vault = await createBrowserOperationVault({ database, signature, binding });
  await vault.create({
    id: "inbound-aabbccdd",
    kind: "deposit",
    note: { commitment: recoveredNote.commitment, spendable: true },
    transaction: {},
  });
  const [op] = await vault.persistRecoveredSpendableNotes([recoveredNote]);
  assert.equal((await vault.list()).length, 1);
  assert.equal(op.id, "inbound-aabbccdd");
  assert.equal(op.state, "confirmed");
  assert.equal(op.note.npk, recoveredNote.npk);
  assert.equal((await vault.list()).filter(isConfirmedSpendableInput).length, 1);
});

test("persistRecoveredSpendableNotes is idempotent for an already-confirmed commitment", async () => {
  const database = createMemoryIndexedDb();
  const vault = await createBrowserOperationVault({ database, signature, binding });
  await vault.persistRecoveredSpendableNotes([recoveredNote]);
  await vault.persistRecoveredSpendableNotes([recoveredNote]);
  const listed = await vault.list();
  assert.equal(listed.length, 1);
  assert.equal(listed[0].state, "confirmed");
  assert.equal(listed.filter(isConfirmedSpendableInput).length, 1);
});
