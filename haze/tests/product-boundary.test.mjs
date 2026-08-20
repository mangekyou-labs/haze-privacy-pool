import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const REQUIRED_FILES = [
  "Cargo.toml",
  "README.md",
  "contracts/foundry.toml",
  "circuits/README.md",
  "crates/protocol/Cargo.toml",
  "crates/prover/Cargo.toml",
  "services/gatekeeper/Cargo.toml",
  "services/indexer/Cargo.toml",
  "services/audit-auth/Cargo.toml",
  "services/disclosure/Cargo.toml",
  "package.json",
  "sdk/typescript/package.json",
  "apps/privacy-pool-dex/package.json",
  "apps/compliance-portal/package.json",
  "deployments/README.md",
];

const REQUIRED_RUST_PACKAGES = [
  "haze-audit-auth",
  "haze-disclosure",
  "haze-gatekeeper",
  "haze-indexer",
  "haze-protocol",
  "haze-prover",
];

const REQUIRED_NODE_PACKAGES = [
  "@haze-avalanche/compliance-portal",
  "@haze-avalanche/privacy-pool-dex",
  "@haze-avalanche/sdk",
];

const PROHIBITED_DEPENDENCY =
  /(?:^|[^a-z0-9])(stellar|soroban|freighter|sep-?(?:01|10))(?:$|[^a-z0-9])/i;
const PROVIDER_VENDOR =
  /(?:^|[^a-z0-9@])(@aws-sdk|aws-sdk|alchemy|infura|quicknode|auth0|okta|cognito|vercel|traderjoe|pangolin)(?:$|[^a-z0-9])/i;
const SOURCE_EXTENSIONS = new Set([".circom", ".rs", ".sol", ".ts", ".tsx"]);
const IMPORT_PATTERN =
  /(?:^|\n)\s*(?:(?:pub(?:\([^)]*\))?\s+)?use|extern\s+crate|import|export\s+(?:\{[^}\n]*\}|\*)\s+from)\s+[^;\n]*/g;

function collectSourceFiles(directory) {
  if (!existsSync(directory)) {
    return [];
  }

  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      return collectSourceFiles(path);
    }
    return SOURCE_EXTENSIONS.has(extname(entry.name)) ? [path] : [];
  });
}

function cargoPackageViolations() {
  if (!existsSync(join(HAZE_ROOT, "Cargo.toml"))) {
    return ["cannot inspect Rust packages without haze/Cargo.toml"];
  }

  const metadata = JSON.parse(
    execFileSync(
      "cargo",
      ["metadata", "--format-version", "1", "--no-deps", "--manifest-path", "Cargo.toml"],
      { cwd: HAZE_ROOT, encoding: "utf8" },
    ),
  );
  const packageNames = metadata.packages.map(({ name }) => name).sort();
  const violations = [];

  if (JSON.stringify(packageNames) !== JSON.stringify(REQUIRED_RUST_PACKAGES)) {
    violations.push(`Rust package set differs: ${JSON.stringify(packageNames)}`);
  }

  for (const pkg of metadata.packages) {
    for (const dependency of pkg.dependencies) {
      if (PROHIBITED_DEPENDENCY.test(dependency.name)) {
        violations.push(`${pkg.name} depends on prohibited package ${dependency.name}`);
      }
    }
  }

  return violations;
}

function nodePackageViolations() {
  const packagePaths = [
    "sdk/typescript/package.json",
    "apps/privacy-pool-dex/package.json",
    "apps/compliance-portal/package.json",
  ];
  if (packagePaths.some((path) => !existsSync(join(HAZE_ROOT, path)))) {
    return ["cannot inspect Node packages until every Haze package manifest exists"];
  }

  const packages = packagePaths.map((path) =>
    JSON.parse(readFileSync(join(HAZE_ROOT, path), "utf8")),
  );
  const packageNames = packages.map(({ name }) => name).sort();
  const violations = [];

  if (JSON.stringify(packageNames) !== JSON.stringify(REQUIRED_NODE_PACKAGES)) {
    violations.push(`Node package set differs: ${JSON.stringify(packageNames)}`);
  }

  for (const pkg of packages) {
    const dependencies = {
      ...pkg.dependencies,
      ...pkg.devDependencies,
      ...pkg.peerDependencies,
    };
    for (const dependency of Object.keys(dependencies)) {
      if (PROHIBITED_DEPENDENCY.test(dependency)) {
        violations.push(`${pkg.name} depends on prohibited package ${dependency}`);
      }
    }
  }

  return violations;
}

function providerVendorViolations() {
  const publicRoots = ["crates/protocol/src", "crates/prover/src", "sdk/typescript/src"];
  const violations = [];
  for (const root of publicRoots) {
    for (const path of collectSourceFiles(join(HAZE_ROOT, root))) {
      const source = readFileSync(path, "utf8");
      if (PROVIDER_VENDOR.test(source)) {
        violations.push(`${relative(HAZE_ROOT, path)} names a concrete vendor in a public API`);
      }
    }
  }
  if (!existsSync(join(HAZE_ROOT, "crates/protocol/src/providers.rs"))) {
    violations.push("missing crates/protocol/src/providers.rs");
  }
  if (!existsSync(join(HAZE_ROOT, "sdk/typescript/src/providers.ts"))) {
    violations.push("missing sdk/typescript/src/providers.ts");
  }
  return violations;
}

function publicImportViolations() {
  const sourceRoots = ["apps", "circuits", "contracts", "crates", "sdk", "services"];
  const violations = [];

  for (const sourceRoot of sourceRoots) {
    for (const path of collectSourceFiles(join(HAZE_ROOT, sourceRoot))) {
      const source = readFileSync(path, "utf8");
      for (const statement of source.matchAll(IMPORT_PATTERN)) {
        if (PROHIBITED_DEPENDENCY.test(statement[0])) {
          violations.push(
            `${relative(HAZE_ROOT, path)} has prohibited import ${statement[0].trim()}`,
          );
        }
      }
    }
  }

  return violations;
}

test("Haze exposes an isolated Avalanche product boundary", () => {
  const violations = REQUIRED_FILES.filter((path) => !existsSync(join(HAZE_ROOT, path))).map(
    (path) => `missing ${path}`,
  );
  violations.push(...cargoPackageViolations());
  violations.push(...nodePackageViolations());
  violations.push(...publicImportViolations());
  violations.push(...providerVendorViolations());

  assert.deepEqual(violations, []);
});

test("public Haze APIs do not name concrete vendors", () => {
  const examples = [
    'import { KMS } from "@aws-sdk/client-kms";',
    'export { Alchemy } from "alchemy-sdk";',
  ];
  const detected = examples.filter((source) => PROVIDER_VENDOR.test(source));
  assert.deepEqual(detected, examples);
});

test("the boundary detector recognizes private and public import forms", () => {
  const examples = [
    'use soroban_sdk::Env;',
    'pub use stellar::Network;',
    'extern crate stellar;',
    'import { rpc } from "@stellar/sdk";',
    'export { rpc } from "@stellar/sdk";',
  ];
  const detected = examples.filter((source) =>
    [...source.matchAll(IMPORT_PATTERN)].some((statement) =>
      PROHIBITED_DEPENDENCY.test(statement[0]),
    ),
  );

  assert.deepEqual(detected, examples);
});
