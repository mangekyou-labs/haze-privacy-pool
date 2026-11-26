import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { decodeHazeAddress } from "../sdk/typescript/src/address.ts";
import { parseRecipientPlaintext } from "../sdk/typescript/src/hpke.ts";
import { encodeRecipientPlaintext } from "../sdk/typescript/src/note.ts";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PROTOCOL = join(HAZE_ROOT, "circuits/vectors/v1/haze-protocol-v1.json");

function loadJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function named(vectors, name) {
  return vectors.positive.find((vector) => vector.name === name);
}

function withoutReadBigUInt64BE(fn) {
  const original = Buffer.prototype.readBigUInt64BE;
  Buffer.prototype.readBigUInt64BE = undefined;
  try {
    return fn();
  } finally {
    Buffer.prototype.readBigUInt64BE = original;
  }
}

test("haze1 decode still works when Buffer.readBigUInt64BE is missing", () => {
  const file = loadJson(PROTOCOL);
  const address = named(file, "haze_address");
  const decoded = withoutReadBigUInt64BE(() => decodeHazeAddress(address.text));
  assert.equal(decoded.chainId, file.primitives.fuji_chain_id);
  assert.equal(decoded.notePublicKey, named(file, "note_public_key").field);
});

test("recipient plaintext parse still works when Buffer.readBigUInt64BE is missing", () => {
  const encoded = encodeRecipientPlaintext({
    value: 500_000n,
    blinding: `0x${"11".repeat(32)}`,
    notePublicKey: `0x${"22".repeat(32)}`,
    encryptionKeyHash: `0x${"33".repeat(32)}`,
    applicationId: `0x${"44".repeat(32)}`,
    poolVersion: `0x${"55".repeat(32)}`,
    commitment: `0x${"66".repeat(32)}`,
    spendingSecret: `0x${"77".repeat(32)}`,
  });
  const parsed = withoutReadBigUInt64BE(() => parseRecipientPlaintext(encoded));
  assert.equal(parsed.value, 500_000n);
  assert.equal(parsed.spendingSecret, `0x${"77".repeat(32)}`);
});
