import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { generateAuditKeypair } from "../dev/audit-keygen.mjs";
import { deriveBrowserX25519PublicKey } from "../sdk/typescript/src/browser-crypto.ts";
import { DEVELOPMENT_AUDIT_IKM } from "../sdk/typescript/src/audit.ts";
import { DEFAULT_HAZE_AUDIT_PUBLIC_KEY } from "../sdk/typescript/src/render-disclosure.ts";

const outDir = () => mkdtempSync(join(tmpdir(), "haze-keygen-"));
const hex = (bytes) => `0x${Buffer.from(bytes).toString("hex")}`;

test("published default audit key is the fixture IKM's derived key", () => {
  const ikm = Buffer.from(DEVELOPMENT_AUDIT_IKM.slice(2), "hex");
  assert.equal(hex(deriveBrowserX25519PublicKey(ikm)), DEFAULT_HAZE_AUDIT_PUBLIC_KEY);
});

test("writes a 0600 IKM file and returns the matching public key", () => {
  const outPath = join(outDir(), "audit-ikm");
  const { publicKey } = generateAuditKeypair({ outPath });
  assert.equal(statSync(outPath).mode & 0o777, 0o600);
  const ikm = readFileSync(outPath, "utf8").trim();
  assert.match(ikm, /^0x[0-9a-f]{64}$/);
  assert.notEqual(ikm, DEVELOPMENT_AUDIT_IKM);
  assert.equal(publicKey, hex(deriveBrowserX25519PublicKey(Buffer.from(ikm.slice(2), "hex"))));
  assert.notEqual(publicKey, DEFAULT_HAZE_AUDIT_PUBLIC_KEY);
});

test("refuses to overwrite an existing key file", () => {
  const outPath = join(outDir(), "audit-ikm");
  writeFileSync(outPath, "keep");
  assert.throws(() => generateAuditKeypair({ outPath }), /exists/);
  assert.equal(readFileSync(outPath, "utf8"), "keep");
});

test("refuses to write the secret inside the repository", () => {
  assert.throws(() => generateAuditKeypair({ outPath: join(import.meta.dirname, "audit-ikm") }), /outside the repository/);
});

test("envelope sealed to the new key opens with its IKM and not with the fixture IKM", async () => {
  const { openBrowserHpke, sealBrowserHpkeToPublicKey } = await import("../sdk/typescript/src/browser-crypto.ts");
  const outPath = join(outDir(), "audit-ikm");
  const { publicKey } = generateAuditKeypair({ outPath });
  const ikm = Buffer.from(readFileSync(outPath, "utf8").trim().slice(2), "hex");
  const info = new TextEncoder().encode("haze-audit-test");
  const aad = new Uint8Array([1, 2, 3]);
  const plaintext = new TextEncoder().encode("withdrawal facts");
  const sealed = sealBrowserHpkeToPublicKey({ recipientPublicKey: Buffer.from(publicKey.slice(2), "hex"), ephemeralSeed: new Uint8Array(32).fill(7), plaintext, info, aad });
  const opened = openBrowserHpke({ recipientIkm: ikm, encapsulatedKey: sealed.encapsulatedKey, ciphertext: sealed.ciphertext, info, aad });
  assert.deepEqual(Buffer.from(opened), Buffer.from(plaintext));
  const fixture = Buffer.from(DEVELOPMENT_AUDIT_IKM.slice(2), "hex");
  assert.throws(() => openBrowserHpke({ recipientIkm: fixture, encapsulatedKey: sealed.encapsulatedKey, ciphertext: sealed.ciphertext, info, aad }), /CIPHERTEXT_INVALID/);
});
