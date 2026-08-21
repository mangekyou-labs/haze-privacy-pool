import assert from "node:assert/strict";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  createArtifactCache,
  createBrowserProver,
  generateBrowserSecrets,
  loadFujiProvingArtifacts,
  selectCircuitArtifact,
} from "../sdk/typescript/src/browser-prover.ts";
import { createBrowserWorkerSession } from "../sdk/typescript/src/browser-worker-session.ts";
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
  const bufferUses = [];
  for (const file of files) {
    if (!file.endsWith(".ts")) {
      continue;
    }
    const source = readFileSync(file, "utf8");
    for (const match of source.matchAll(/from\s+["'](node:[^"']+)["']/g)) {
      nodeImports.push(`${file.slice(SDK_ROOT.length + 1)}:${match[1]}`);
    }
    if (/\bBuffer\b/.test(source)) {
      bufferUses.push(file.slice(SDK_ROOT.length + 1));
    }
  }
  assert.deepEqual(nodeImports, []);
  assert.deepEqual(bufferUses, []);
});

test("browser secrets use browser cryptography for notes, bindings, and distinct HPKE channels", () => {
  let next = 1;
  const secrets = generateBrowserSecrets({
    getRandomValues(bytes) {
      bytes.fill(next++);
      return bytes;
    },
  });
  assert.equal(secrets.noteSecret.length, 32);
  assert.equal(secrets.blinding.length, 32);
  assert.equal(secrets.actionReference.length, 32);
  assert.equal(secrets.auditSalt.length, 32);
  assert.equal(secrets.recipientHpkeSeed.length, 32);
  assert.equal(secrets.auditHpkeSeed.length, 32);
  assert.notDeepEqual([...secrets.noteSecret], [...secrets.blinding]);
  assert.equal(new Set(Object.values(secrets).map((bytes) => bytes[0])).size, 6);
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

test("the browser prover forwards structured worker progress before success", async () => {
  const listeners = [];
  const worker = {
    addEventListener(_type, listener) {
      listeners.push(listener);
    },
    postMessage(message) {
      queueMicrotask(() => {
        for (const listener of listeners) listener({ data: { type: "progress", requestId: message.requestId, stage: "witness", percent: 25 } });
        for (const listener of listeners) listener({ data: { type: "progress", requestId: message.requestId, stage: "prove", percent: 75 } });
        for (const listener of listeners) listener({ data: { type: "success", requestId: message.requestId, proof: { profile: "development", notForProduction: true, publicValue: 9, verified: true } } });
      });
    },
  };
  const progress = [];
  const prover = createBrowserProver({ worker, profile: "development", expectedArtifactHash: FUJI_COMPATIBILITY.circuitArtifactHash });
  const proof = await prover.proveDevelopment(9, { onProgress: (event) => progress.push(event) });
  assert.equal(proof.publicValue, 9);
  assert.deepEqual(progress, [
    { stage: "witness", percent: 25 },
    { stage: "prove", percent: 75 },
  ]);
});

test("verified Fuji bytes are transferred to the browser Groth16 runtime", async () => {
  const messages = [];
  const handler = createBrowserWorkerSession(async () => ({
    async fullProve(input, wasm, zkey) {
      assert.equal(input.action, "1");
      assert.deepEqual([...wasm], [0, 97, 115, 109]);
      assert.deepEqual([...zkey], [1, 2, 3]);
      return { proof: { pi_a: ["1", "2"] }, publicSignals: ["3"] };
    },
  }));
  await handler(
    { type: "prove-spend", requestId: "proof-1", circom: { action: 1 }, wasm: Uint8Array.from([0, 97, 115, 109]), zkey: Uint8Array.from([1, 2, 3]) },
    (message) => messages.push(message),
  );
  assert.deepEqual(messages.map(({ type }) => type), ["progress", "progress", "progress", "success"]);
  assert.deepEqual(messages.at(-1).proof.publicSignals, ["3"]);
});

test("the browser prover sends only manifest-verified artifact bytes to spend proving", async () => {
  const listeners = [];
  let posted;
  const worker = {
    addEventListener(_type, listener) { listeners.push(listener); },
    postMessage(message) {
      posted = message;
      if (message.type === "prove-spend") queueMicrotask(() => listeners.forEach((listener) => listener({ data: { type: "success", requestId: message.requestId, proof: { publicSignals: [] } } })));
    },
  };
  const wasm = Uint8Array.from([0, 97, 115, 109]);
  const zkey = Uint8Array.from([1, 2, 3]);
  const digest = async (bytes) => `0x${Buffer.from(await crypto.subtle.digest("SHA-256", bytes)).toString("hex")}`;
  const prover = createBrowserProver({ worker, profile: "development", expectedArtifactHash: FUJI_COMPATIBILITY.circuitArtifactHash });
  await prover.loadFujiArtifacts({
    circuitId: "haze-spend-v1", profile: "fuji-development", notForProduction: true,
    wasm: { url: "https://example/wasm", byteSize: wasm.length, sha256: await digest(wasm) },
    zkey: { url: "https://example/zkey", byteSize: zkey.length, sha256: await digest(zkey) },
  }, { wasm, zkey });
  await prover.proveSpend({ action: 1 });
  assert.deepEqual([...posted.wasm], [...wasm]);
  assert.deepEqual([...posted.zkey], [...zkey]);
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

test("Fuji proving artifacts load from URLs or bytes only after SHA-256 and size verification", async () => {
  const wasm = Uint8Array.from([0, 97, 115, 109]);
  const zkey = Uint8Array.from([1, 2, 3, 4, 5]);
  const digest = async (bytes) =>
    `0x${Buffer.from(await crypto.subtle.digest("SHA-256", bytes)).toString("hex")}`;
  const manifest = {
    circuitId: "haze-spend-v1",
    profile: "fuji-development",
    notForProduction: true,
    wasm: { url: "https://haze.example/spend.wasm", byteSize: wasm.byteLength, sha256: await digest(wasm) },
    zkey: { url: "https://haze.example/spend.zkey", byteSize: zkey.byteLength, sha256: await digest(zkey) },
  };
  const fetch = async (url) => ({
    ok: true,
    arrayBuffer: async () => (url.endsWith(".wasm") ? wasm : zkey).buffer,
  });

  const loaded = await loadFujiProvingArtifacts(manifest, { fetch });
  assert.deepEqual([...loaded.wasm], [...wasm]);
  assert.deepEqual([...loaded.zkey], [...zkey]);

  const fromBytes = await loadFujiProvingArtifacts(manifest, { wasm, zkey });
  assert.deepEqual([...fromBytes.zkey], [...zkey]);

  await assert.rejects(
    () => loadFujiProvingArtifacts({ ...manifest, wasm: { ...manifest.wasm, byteSize: 99 } }, { wasm, zkey }),
    (error) => error instanceof ProverError && error.code === "ARTIFACT_INVALID",
  );
  await assert.rejects(
    () => loadFujiProvingArtifacts({ ...manifest, zkey: { ...manifest.zkey, sha256: `0x${"00".repeat(32)}` } }, { wasm, zkey }),
    (error) => error instanceof ProverError && error.code === "ARTIFACT_INVALID",
  );
  await assert.rejects(
    () => loadFujiProvingArtifacts({ ...manifest, profile: "production", notForProduction: false }, { wasm, zkey }),
    (error) => error instanceof ProverError && error.code === "ARTIFACT_INVALID",
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
  assert.deepEqual(Object.keys(manifest.dependencies ?? {}), ["@noble/ciphers", "@noble/curves", "@noble/hashes"]);
  assert.equal(manifest.devDependencies, undefined);
  const lock = JSON.parse(readFileSync(join(HAZE_ROOT, "package-lock.json"), "utf8"));
  const noble = lock.packages["node_modules/@noble/curves"];
  const ciphers = lock.packages["node_modules/@noble/ciphers"];
  const hashes = lock.packages["node_modules/@noble/hashes"];
  assert.equal(ciphers.license, "MIT");
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
