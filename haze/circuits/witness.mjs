import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { copyFileSync, existsSync, mkdirSync, readFileSync, statSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const HERE = dirname(fileURLToPath(import.meta.url));

export function hazeRootFrom(circuitsRoot = HERE) {
  return resolve(circuitsRoot, "..");
}

export function resolveCircom(hazeRoot = hazeRootFrom()) {
  const pinned = join(hazeRoot, ".tools", "bin", "circom");
  if (!existsSync(pinned)) {
    throw new Error(
      `missing ${pinned}; install Circom 2.2.3 with cargo install circom --git https://github.com/iden3/circom --tag v2.2.3 --locked --root haze/.tools`,
    );
  }
  const version = execFileSync(pinned, ["--version"], { encoding: "utf8" });
  if (!version.includes("2.2.3")) {
    throw new Error(`expected Circom 2.2.3 at ${pinned}, got ${version.trim()}`);
  }
  return pinned;
}

export function fieldToBigInt(hex) {
  const stripped = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  return BigInt(`0x${stripped}`);
}

function needsCompile(sources, wasmPath) {
  if (!existsSync(wasmPath)) {
    return true;
  }
  const wasmMtime = statSync(wasmPath).mtimeMs;
  return sources.some((path) => existsSync(path) && statSync(path).mtimeMs > wasmMtime);
}

function collectIncludes(entry) {
  const seen = new Set();
  const stack = [entry];
  while (stack.length > 0) {
    const path = stack.pop();
    if (seen.has(path) || !existsSync(path)) {
      continue;
    }
    seen.add(path);
    const source = readFileSync(path, "utf8");
    for (const match of source.matchAll(/include\s+"([^"]+)"/g)) {
      stack.push(resolve(dirname(path), match[1]));
    }
  }
  return [...seen];
}

export function parseMainPublicSignals(source) {
  const match = source.match(/component\s+main\s*\{public\s*\[([^\]]+)\]\}/);
  if (!match) {
    throw new Error("missing component main {public [...]} declaration");
  }
  return match[1]
    .split(",")
    .map((name) => name.trim())
    .filter(Boolean);
}

function parseConstraintCount(log) {
  const match = log.match(/non-linear constraints:\s+(\d+)/i);
  return match ? Number(match[1]) : 0;
}

export function r1csConstraintCount(r1csPath) {
  const buf = readFileSync(r1csPath);
  if (buf.toString("utf8", 0, 4) !== "r1cs") {
    throw new Error(`not an r1cs file: ${r1csPath}`);
  }
  let offset = 4;
  const version = buf.readUInt32LE(offset);
  offset += 4;
  if (version < 1) {
    throw new Error(`unsupported r1cs version ${version}`);
  }
  const nSections = buf.readUInt32LE(offset);
  offset += 4;
  for (let i = 0; i < nSections; i += 1) {
    const sectionType = buf.readUInt32LE(offset);
    offset += 4;
    const sectionSize = Number(buf.readBigUInt64LE(offset));
    offset += 8;
    if (sectionType === 1) {
      const n8 = buf.readUInt32LE(offset);
      // n8 | prime | nWires | nPubOut | nPubIn | nPrvIn | nLabels(u64) | nConstraints
      return buf.readUInt32LE(offset + 4 + n8 + 4 + 4 + 4 + 4 + 8);
    }
    offset += sectionSize;
  }
  throw new Error(`r1cs header section missing in ${r1csPath}`);
}

export async function compileAndWitnessFull(
  circuitPath,
  input,
  hazeRoot = hazeRootFrom(),
  options = {},
) {
  if (!existsSync(circuitPath)) {
    throw new Error(`missing circuit ${circuitPath}`);
  }
  const circom = resolveCircom(hazeRoot);
  const name = basename(circuitPath, ".circom");
  const outDir = join(hazeRoot, "circuits", "build", name);
  const jsDir = join(outDir, `${name}_js`);
  const wasmPath = join(jsDir, `${name}.wasm`);
  const r1csPath = join(outDir, `${name}.r1cs`);
  mkdirSync(outDir, { recursive: true });
  let compileLog = "";
  if (needsCompile(collectIncludes(circuitPath), wasmPath)) {
    compileLog = execFileSync(circom, [circuitPath, "--r1cs", "--wasm", "--sym", "-o", outDir], {
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    });
  } else if (existsSync(join(outDir, `${name}.r1cs`))) {
    compileLog = "";
  }
  const calculatorCjs = join(jsDir, "witness_calculator.cjs");
  copyFileSync(join(jsDir, "witness_calculator.js"), calculatorCjs);
  const builder = require(calculatorCjs);
  const wasm = readFileSync(wasmPath);
  const calculator = await builder(wasm);
  const sanityCheck = options.sanityCheck === true ? 1 : 0;
  const witness = await calculator.calculateWitness(input, sanityCheck);
  const publicCount = options.publicCount ?? 29;
  const publicSignals = Array.from({ length: publicCount }, (_, index) =>
    BigInt(witness[index + 1]),
  );
  let nConstraints = parseConstraintCount(compileLog);
  if (existsSync(r1csPath)) {
    nConstraints = r1csConstraintCount(r1csPath);
  }
  return {
    out: BigInt(witness[1]),
    witness: witness.map((value) => BigInt(value)),
    publicSignals,
    nConstraints,
    compileLog,
  };
}

export async function compileAndWitness(circuitPath, input, hazeRoot = hazeRootFrom()) {
  const result = await compileAndWitnessFull(circuitPath, input, hazeRoot, {
    sanityCheck: false,
    publicCount: 1,
  });
  return { out: result.out };
}
