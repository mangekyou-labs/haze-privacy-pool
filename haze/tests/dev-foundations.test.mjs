import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const REPO_ROOT = resolve(HAZE_ROOT, "..");

test("Haze locks toolchains and stages CI", () => {
  const missing = [
    "rust-toolchain.toml",
    "dev/artifacts/development-circuit-manifest.json",
    "dev/postgres/migrations/0001_init.sql",
    "dev/secret-scan.mjs",
    "contracts/src/mocks/MockUsdc.sol",
    "contracts/src/mocks/MockSourceToken.sol",
    "contracts/src/mocks/MockDex.sol",
  ]
    .filter((path) => !existsSync(join(HAZE_ROOT, path)))
    .map((path) => `missing ${path}`);

  const workflow = join(REPO_ROOT, ".github/workflows/haze.yml");
  if (!existsSync(workflow)) {
    missing.push("missing .github/workflows/haze.yml");
  } else {
    const yaml = readFileSync(workflow, "utf8");
    for (const token of [
      "haze/",
      "secret-scan",
      "npm ci --prefix haze",
      "npm test --prefix haze",
      "cargo test --manifest-path haze/Cargo.toml",
      "circuits/test/spend.circom",
    ]) {
      if (!yaml.includes(token)) {
        missing.push(`workflow missing ${token}`);
      }
    }
  }

  const toolchain = existsSync(join(HAZE_ROOT, "rust-toolchain.toml"))
    ? readFileSync(join(HAZE_ROOT, "rust-toolchain.toml"), "utf8")
    : "";
  if (!toolchain.includes("1.97.1")) {
    missing.push("haze rust-toolchain.toml must pin 1.97.1");
  }

  assert.deepEqual(missing, []);
});

test("development circuit manifest cannot be labeled production", () => {
  const path = join(HAZE_ROOT, "dev/artifacts/development-circuit-manifest.json");
  assert.equal(existsSync(path), true, "development manifest must exist");
  const manifest = JSON.parse(readFileSync(path, "utf8"));
  assert.equal(manifest.profile, "development");
  assert.equal(manifest.not_for_production, true);
  assert.notEqual(manifest.profile, "production");
});

test("secret-scan completes when operator ceremony binaries are present", () => {
  const scanner = join(HAZE_ROOT, "dev/secret-scan.mjs");
  const source = readFileSync(scanner, "utf8");
  assert.match(source, /PRIVATE KEY/);
  assert.match(source, /AKIA/);
  assert.match(source, /github_pat_/);
  assert.match(source, /xox\[baprs\]/);
  const output = execFileSync(process.execPath, [scanner], {
    cwd: HAZE_ROOT,
    encoding: "utf8",
  });
  assert.match(output, /secret-scan ok/);
});

test("postgres migrations are numbered and fail-closed without a database", () => {
  const dir = join(HAZE_ROOT, "dev/postgres/migrations");
  assert.equal(existsSync(dir), true);
  const files = readdirSync(dir).filter((name) => name.endsWith(".sql")).sort();
  assert.ok(files[0] === "0001_init.sql");
  assert.ok(files.includes("0002_ops.sql"));
  const sql = readFileSync(join(dir, "0001_init.sql"), "utf8");
  assert.match(sql, /create table if not exists haze_schema_migrations/i);
  const ops = readFileSync(join(dir, "0002_ops.sql"), "utf8");
  assert.match(ops, /create table if not exists haze_idempotency/i);
  assert.match(ops, /create table if not exists haze_retention/i);
});
