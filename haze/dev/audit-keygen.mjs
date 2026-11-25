// Generate a fresh Haze audit keypair.
// The private IKM goes to a 0600 file outside the repository and is never printed.
// The X25519 public key (RFC 9180 DeriveKeyPair, same as the browser and disclosure
// service) is printed for NEXT_PUBLIC_HAZE_AUDIT_PUBLIC_KEY.
//
//   node --experimental-strip-types dev/audit-keygen.mjs <out-path>
import { randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { deriveBrowserX25519PublicKey } from "../sdk/typescript/src/browser-crypto.ts";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

export function generateAuditKeypair({ outPath }) {
  const target = resolve(outPath);
  const fromRepo = relative(REPO_ROOT, target);
  if (!fromRepo.startsWith("..")) throw new Error("audit IKM must be written outside the repository");
  const ikm = randomBytes(32);
  try {
    // "wx" fails if the file exists; mode applies on create.
    writeFileSync(target, `0x${ikm.toString("hex")}\n`, { flag: "wx", mode: 0o600 });
  } catch (error) {
    if (error?.code === "EEXIST") throw new Error(`${target} already exists; refusing to overwrite`);
    throw error;
  }
  const publicKey = `0x${Buffer.from(deriveBrowserX25519PublicKey(ikm)).toString("hex")}`;
  ikm.fill(0);
  return { publicKey };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const outPath = process.argv[2];
  if (!outPath) {
    console.error("usage: audit-keygen.mjs <out-path outside the repo>");
    process.exit(2);
  }
  const { publicKey } = generateAuditKeypair({ outPath });
  console.log(publicKey);
}
