import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CIRCUITS_ROOT = join(HAZE_ROOT, "circuits");
const REJECTION_PATH = join(CIRCUITS_ROOT, "REJECTION.md");

const REJECTED_ARTIFACTS = [
  "policy_tx_",
  "policyTransaction",
  "transaction.circom",
  "smtverifier",
  "smthash_poseidon2",
  "aspMembership",
  "aspNonMembership",
  "globalViewKey",
  "selectiveDisclosure",
  "keypair.circom",
  "merkleProof.circom",
  "merkleTree.circom",
  "merkleTreeUpdater.circom",
];

function collectCircomFiles(directory) {
  if (!existsSync(directory)) {
    return [];
  }
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      return collectCircomFiles(path);
    }
    return extname(entry.name) === ".circom" ? [path] : [];
  });
}

test("documents rejection of incompatible Stellar privacy artifacts", () => {
  assert.equal(existsSync(REJECTION_PATH), true, "missing haze/circuits/REJECTION.md");
  const body = readFileSync(REJECTION_PATH, "utf8");
  for (const artifact of REJECTED_ARTIFACTS) {
    assert.match(
      body,
      new RegExp(artifact.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
      `REJECTION.md must name ${artifact}`,
    );
  }
  assert.match(body, /Poseidon2\(n\)/);
  assert.match(body, /single permutation/);
});

test("Haze circuits do not import rejected Stellar artifacts", () => {
  const files = collectCircomFiles(join(CIRCUITS_ROOT, "src"));
  const violations = [];
  for (const path of files) {
    const source = readFileSync(path, "utf8");
    for (const artifact of REJECTED_ARTIFACTS) {
      if (source.includes(artifact)) {
        violations.push(`${relative(HAZE_ROOT, path)} mentions ${artifact}`);
      }
    }
    if (/template\s+Poseidon2\s*\(/.test(source)) {
      violations.push(`${relative(HAZE_ROOT, path)} defines legacy Poseidon2(n)`);
    }
  }
  assert.deepEqual(violations, []);
});
