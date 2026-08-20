#!/usr/bin/env node
import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const APP_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const APP_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

const CONTRACTS = [
  "HazePool",
  "HazeVerifier",
  "HazeScreenerRegistry",
  "HazeAdapterRegistry",
  "HazeNullifierSet",
];
const SERVICES = ["haze-gatekeeper", "haze-indexer", "haze-prover", "haze-disclosure"];
const MIGRATIONS = ["0001_init.sql", "0002_ops.sql"];
const MOCKS = ["MockUsdc", "malicious-adapter", "replay-bot"];
const FRONTENDS = ["privacy-pool-dex", "compliance-portal"];
const ACTORS = ["alice", "bob", "auditor", "adversary"];

function applicationFixture(applicationId, suffix) {
  return {
    applicationId,
    kmsKeyRef: `dev-kms-${suffix}`,
    gatekeeperSigner: `0x${suffix.repeat(20).slice(0, 40)}`,
    auditor: `auditor-${suffix}@local.test`,
    users: {
      eligible: `eligible-${suffix}@local.test`,
      ineligible: `ineligible-${suffix}@local.test`,
      auditor: `auditor-${suffix}@local.test`,
    },
  };
}

function canonicalSpec(profile) {
  return {
    profile,
    notForProduction: true,
    evm: "anvil-mock",
    circuitProfile: "development",
    contracts: [...CONTRACTS],
    services: [...SERVICES],
    database: { engine: "postgres-fixture", migrations: [...MIGRATIONS] },
    mocks: [...MOCKS],
    frontends: [...FRONTENDS],
    applications: [applicationFixture(APP_A, "aa"), applicationFixture(APP_B, "bb")],
    actors: [...ACTORS],
    deployments: {
      HazePool: "0x1111111111111111111111111111111111111111",
      HazeVerifier: "0x2222222222222222222222222222222222222222",
    },
  };
}

function hashSpec(spec) {
  return `0x${createHash("sha256").update(JSON.stringify(spec)).digest("hex")}`;
}

export function assembleStack(profile) {
  if (profile !== "local" && profile !== "ci") {
    throw new Error(`unsupported stack profile: ${profile}`);
  }
  const spec = canonicalSpec(profile);
  return { ...spec, hash: hashSpec(spec) };
}

export function verifyStack() {
  const stack = assembleStack("local");
  const publishedPath = join(HAZE_ROOT, "dev/fixtures/stack-manifest.json");
  const published = JSON.parse(readFileSync(publishedPath, "utf8"));
  if (published.fixtureHash !== stack.hash) {
    throw new Error("published stack fixture hash mismatch");
  }
  if (published.profile !== "development" || published.not_for_production !== true) {
    throw new Error("published stack fixture is not a development profile");
  }
  const circuit = JSON.parse(
    readFileSync(join(HAZE_ROOT, "dev/artifacts/development-circuit-manifest.json"), "utf8"),
  );
  if (circuit.profile !== "development" || circuit.not_for_production !== true) {
    throw new Error("circuit manifest is not a development profile");
  }
  return {
    fixtureHash: stack.hash,
    circuitProfile: circuit.profile,
    notForProduction: true,
  };
}

export function bootstrapStack({ root, profile }) {
  const stack = assembleStack(profile);
  mkdirSync(root, { recursive: true });
  const migrationsDir = join(root, "postgres", "migrations");
  mkdirSync(migrationsDir, { recursive: true });
  for (const file of MIGRATIONS) {
    copyFileSync(join(HAZE_ROOT, "dev/postgres/migrations", file), join(migrationsDir, file));
  }
  mkdirSync(join(root, "artifacts"), { recursive: true });
  copyFileSync(
    join(HAZE_ROOT, "dev/artifacts/development-circuit-manifest.json"),
    join(root, "artifacts", "development-circuit-manifest.json"),
  );
  writeFileSync(join(root, "stack.json"), `${JSON.stringify(stack, null, 2)}\n`);
  writeFileSync(
    join(root, "ready.json"),
    `${JSON.stringify({ ready: true, profile, hash: stack.hash }, null, 2)}\n`,
  );
  return stack;
}

export function teardownStack(root) {
  for (const name of ["ready.json", "stack.json", "postgres", "artifacts"]) {
    const path = join(root, name);
    if (existsSync(path)) {
      rmSync(path, { recursive: true, force: true });
    }
  }
}

function main(argv) {
  const command = argv[0] ?? "verify";
  if (command === "verify") {
    const report = verifyStack();
    process.stdout.write(`stack-verify ok ${report.fixtureHash}\n`);
    return;
  }
  if (command === "assemble") {
    process.stdout.write(`${JSON.stringify(assembleStack(argv[1] ?? "local"), null, 2)}\n`);
    return;
  }
  throw new Error(`unknown stack command: ${command}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2));
}
