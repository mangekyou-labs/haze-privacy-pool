#!/usr/bin/env node
import { readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const SKIP = new Set(["target", "node_modules", "out", "cache", "lib", "ceremony-private"]);
const BINARY_EXT = new Set([".ptau", ".zkey", ".r1cs", ".sym", ".wasm"]);
const MAX_BYTES = 5 * 1024 * 1024;
const PEM = /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/;
const AWS = /AKIA[0-9A-Z]{16}/;
const AWS_SECRET = /aws[_-]secret[_-]access[_-]key/i;
const GITHUB = /ghp_[A-Za-z0-9]{20,}/;
const GITHUB_PAT = /github_pat_[A-Za-z0-9_]{20,}/;
const SLACK = /xox[baprs]-[A-Za-z0-9-]{10,}/;
const STRIPE = /sk_live_[A-Za-z0-9]{20,}/;
const RAW_X25519 = /x25519Secret\s*[:=]\s*0x[0-9a-fA-F]{64}/;

function walk(directory, files = []) {
  for (const entry of readdirSync(directory)) {
    if (SKIP.has(entry) || entry.startsWith(".")) {
      continue;
    }
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) {
      walk(path, files);
    } else {
      files.push(path);
    }
  }
  return files;
}

function shouldScan(path) {
  if (BINARY_EXT.has(extname(path).toLowerCase())) {
    return false;
  }
  return statSync(path).size <= MAX_BYTES;
}

const hits = [];
for (const path of walk(ROOT)) {
  if (!shouldScan(path)) {
    continue;
  }
  const text = readFileSync(path, "utf8");
  if (
    PEM.test(text) ||
    AWS.test(text) ||
    AWS_SECRET.test(text) ||
    GITHUB.test(text) ||
    GITHUB_PAT.test(text) ||
    SLACK.test(text) ||
    STRIPE.test(text) ||
    RAW_X25519.test(text)
  ) {
    hits.push(relative(ROOT, path));
  }
}

if (hits.length > 0) {
  console.error("secret-scan failed:", hits.join(", "));
  process.exit(1);
}

console.log("secret-scan ok");
