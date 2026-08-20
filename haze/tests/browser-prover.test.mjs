import assert from "node:assert/strict";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  createArtifactCache,
  createBrowserProver,
  selectCircuitArtifact,
} from "../sdk/typescript/src/browser-prover.ts";
import { SdkError } from "../sdk/typescript/src/errors.ts";
import {
  ProverError,
  createProverSession,
  handleProverWorkerMessage,
  hashArtifactSet,
} from "../sdk/typescript/src/prover.ts";
import { FUJI_COMPATIBILITY } from "../sdk/typescript/src/versions.ts";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SDK_ROOT = join(HAZE_ROOT, "sdk/typescript");
const BENCHMARK = join(HAZE_ROOT, "dev/artifacts/proving-benchmark.json");
const MANIFEST = join(HAZE_ROOT, "dev/artifacts/development-circuit-manifest.json");
const PROVER = join(HAZE_ROOT, "circuits/vectors/v1/haze-prover-v1.json");

function createLoopbackWorker() {
  const session = createProverSession();
  const listeners = [];
  return {
    session,
    addEventListener(type, listener) {
      if (type === "message") {
        listeners.push(listener);
      }
    },
    postMessage(data) {
      queueMicrotask(async () => {
        try {
          const result = await handleProverWorkerMessage(session, data);
          for (const listener of listeners) {
            listener({ data: result });
          }
        } catch (error) {
          const code = error instanceof Error && "code" in error ? error.code : "PROOF_INVALID";
          for (const listener of listeners) {
            listener({ data: { type: "error", code } });
          }
        }
      });
    },
    terminate() {},
  };
}

function collectLocalImports(entry, seen = new Set()) {
  const resolved = resolve(entry);
  if (seen.has(resolved)) {
    return seen;
  }
  seen.add(resolved);
  if (!existsSync(resolved)) {
    return seen;
  }
  const source = readFileSync(resolved, "utf8");
  for (const match of source.matchAll(/from\s+["'](\.[^"']+)["']/g)) {
    const next = match[1].endsWith(".ts") || match[1].endsWith(".json") ? match[1] : `${match[1]}.ts`;
    collectLocalImports(resolve(dirname(resolved), next), seen);
  }
  return seen;
}

test("the browser worker module graph does not import Node builtins", () => {
  const worker = join(SDK_ROOT, "src/prover-worker.ts");
  const files = [...collectLocalImports(worker)];
  const nodeImports = [];
  for (const file of files) {
    if (!file.endsWith(".ts")) {
      continue;
    }
    const source = readFileSync(file, "utf8");
    for (const match of source.matchAll(/from\s+["'](node:[^"']+)["']/g)) {
      nodeImports.push(`${file.slice(SDK_ROOT.length + 1)}:${match[1]}`);
    }
  }
  assert.deepEqual(nodeImports, []);
});

test("the browser prover host proves through a worker and reports progress", async () => {
  const worker = createLoopbackWorker();
  const progress = [];
  const prover = createBrowserProver({
    worker,
    profile: "development",
    expectedArtifactHash: FUJI_COMPATIBILITY.circuitArtifactHash,
  });
  const proof = await prover.proveDevelopment(7, {
    onProgress(stage) {
      progress.push(stage);
    },
  });
  assert.equal(proof.profile, "development");
  assert.equal(proof.notForProduction, true);
  assert.equal(proof.verified, true);
  assert.equal(proof.publicValue, 7);
  assert.ok(progress.includes("development"));
  assert.ok(prover.stages().includes("development"));
});

test("cancelling the browser host does not emit a proof", async () => {
  const prover = createBrowserProver({
    worker: createLoopbackWorker(),
    profile: "development",
    expectedArtifactHash: FUJI_COMPATIBILITY.circuitArtifactHash,
  });
  prover.cancel();
  await assert.rejects(() => prover.proveDevelopment(7), (error) => {
    assert.equal(error instanceof ProverError, true);
    assert.equal(error.code, "CANCELLED");
    return true;
  });
});

test("browser spend proving still returns KEYS_MISSING", async () => {
  const prover = createBrowserProver({
    worker: createLoopbackWorker(),
    profile: "development",
    expectedArtifactHash: FUJI_COMPATIBILITY.circuitArtifactHash,
  });
  await assert.rejects(() => prover.proveSpend({ action: "1" }), (error) => {
    assert.equal(error instanceof ProverError, true);
    assert.equal(error.code, "KEYS_MISSING");
    return true;
  });
});

test("artifact cache serves the matching hash and refuses substitution or production development keys", async () => {
  const expected = JSON.parse(readFileSync(PROVER, "utf8")).artifactHash;
  const digest = await hashArtifactSet({
    circuit: join(HAZE_ROOT, "circuits/src/spend.circom"),
    fixture: join(HAZE_ROOT, "circuits/vectors/v1/haze-spend-v1.json"),
    manifest: MANIFEST,
  });
  assert.equal(digest, expected);

  const cache = createArtifactCache();
  const bytes = Uint8Array.from([1, 2, 3, 4]);
  await cache.put({ artifactHash: expected, bytes });
  const hit = await cache.get(expected);
  assert.deepEqual([...hit], [1, 2, 3, 4]);

  await assert.rejects(() => cache.get(`0x${"11".repeat(32)}`), (error) => {
    assert.equal(error instanceof ProverError, true);
    assert.equal(error.code, "ARTIFACT_INVALID");
    return true;
  });

  await assert.rejects(
    () =>
      selectCircuitArtifact(
        "production",
        {
          profile: "development",
          notForProduction: true,
          artifactHash: expected,
        },
        expected,
      ),
    (error) => {
      assert.equal(error instanceof SdkError, true);
      assert.equal(error.code, "VERSION_UNSUPPORTED");
      return true;
    },
  );

  await assert.rejects(
    () =>
      selectCircuitArtifact(
        "development",
        {
          profile: "development",
          notForProduction: true,
          artifactHash: `0x${"11".repeat(32)}`,
        },
        expected,
      ),
    (error) => {
      assert.equal(error instanceof ProverError, true);
      assert.equal(error.code, "ARTIFACT_INVALID");
      return true;
    },
  );

  const prover = createBrowserProver({
    worker: createLoopbackWorker(),
    cache,
    profile: "development",
    expectedArtifactHash: expected,
  });
  await prover.ensureArtifacts({
    artifactHash: expected,
    profile: "development",
    notForProduction: true,
    bytes,
  });
  await assert.rejects(
    () =>
      prover.ensureArtifacts({
        artifactHash: expected,
        profile: "production",
        notForProduction: true,
        bytes,
      }),
    (error) => error.code === "VERSION_UNSUPPORTED",
  );
});

test("the SDK package documents the integrator API and exports the worker entry", () => {
  const manifest = JSON.parse(readFileSync(join(SDK_ROOT, "package.json"), "utf8"));
  assert.equal(manifest.name, "@haze-avalanche/sdk");
  assert.equal(manifest.license, "Apache-2.0");
  assert.equal(manifest.exports["."], "./src/index.ts");
  assert.equal(manifest.exports["./worker"], "./src/prover-worker.ts");
  assert.ok(manifest.files.includes("src"));
  assert.ok(manifest.files.includes("README.md"));
  assert.ok(manifest.files.includes("LICENSE"));
  assert.ok(manifest.files.includes("examples"));

  const readme = readFileSync(join(SDK_ROOT, "README.md"), "utf8");
  assert.match(readme, /createBrowserProver/);
  assert.match(readme, /createWorkflowClient/);
  assert.match(readme, /KEYS_MISSING/);
  assert.match(readme, /Web Worker/);
  assert.doesNotMatch(readme, /ethers|viem|alchemy|infura/i);

  const license = readFileSync(join(SDK_ROOT, "LICENSE"), "utf8");
  assert.match(license, /Apache License/);
  assert.match(license, /Version 2\.0/);

  const example = readFileSync(join(SDK_ROOT, "examples/direct-shield.mjs"), "utf8");
  assert.match(example, /createWorkflowClient/);
  assert.match(example, /createBrowserProver/);
  assert.match(example, /KEYS_MISSING/);
  assert.doesNotMatch(example, /ethers|viem|alchemy|infura/i);
});

test("the SDK dependency set is a reviewed MIT/Apache license surface", () => {
  const manifest = JSON.parse(readFileSync(join(SDK_ROOT, "package.json"), "utf8"));
  assert.deepEqual(Object.keys(manifest.dependencies ?? {}), ["@noble/curves"]);
  assert.equal(manifest.devDependencies, undefined);
  const lock = JSON.parse(readFileSync(join(HAZE_ROOT, "package-lock.json"), "utf8"));
  const noble = lock.packages["node_modules/@noble/curves"];
  const hashes = lock.packages["node_modules/@noble/hashes"];
  assert.equal(noble.license, "MIT");
  assert.equal(hashes.license, "MIT");
  const worker = readFileSync(join(SDK_ROOT, "src/prover-worker.ts"), "utf8");
  assert.doesNotMatch(worker, /ethers|viem|alchemy|infura/i);
});

test("browser development proving stays under the SC-06 P95 target", async () => {
  const prover = createBrowserProver({
    worker: createLoopbackWorker(),
    profile: "development",
    expectedArtifactHash: FUJI_COMPATIBILITY.circuitArtifactHash,
  });
  const started = performance.now();
  const samples = [];
  for (let i = 0; i < 5; i += 1) {
    const tick = performance.now();
    await prover.proveDevelopment(i + 1);
    samples.push(performance.now() - tick);
  }
  const durationMs = Number((performance.now() - started).toFixed(3));
  samples.sort((left, right) => left - right);
  const p95 = samples[samples.length - 1];
  writeFileSync(
    BENCHMARK,
    `${JSON.stringify(
      {
        profile: "development",
        circuit: "development-equality",
        worker: true,
        samples_ms: samples.map((value) => Number(value.toFixed(3))),
        duration_ms: durationMs,
        p95_ms: Number(p95.toFixed(3)),
        p95_target_ms: 15000,
        not_for_production: true,
        spend_keys: "T7.4",
        reference_desktop: "local-development",
      },
      null,
      2,
    )}\n`,
  );
  assert.ok(p95 < 15000);
  const recorded = JSON.parse(readFileSync(BENCHMARK, "utf8"));
  assert.equal(recorded.worker, true);
  assert.equal(recorded.p95_target_ms, 15000);
  assert.equal(recorded.spend_keys, "T7.4");
});
