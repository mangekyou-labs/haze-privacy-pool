# @haze-avalanche/sdk

Provider-neutral TypeScript SDK for Haze Avalanche compliant-pool integrators.

## Public surface

- `createWorkflowClient` — quote → authorize → prove → submit → finality for the six user paths.
- `createBrowserProver` — host that drives a proving **Web Worker** with artifact cache, progress,
  and cancel hooks.
- `createProverSession` — same-stack development proving used by Node tests and the worker.
- Production spend proving stays `KEYS_MISSING` until the T7.4 ceremony.

## Browser proving

Load the worker from `@haze-avalanche/sdk/worker` (or the committed `src/prover-worker.ts` entry)
and pass it to `createBrowserProver`. The worker graph has no `node:` builtins.

```ts
import { createBrowserProver, createWorkflowClient } from "@haze-avalanche/sdk";

const worker = new Worker(new URL("@haze-avalanche/sdk/worker", import.meta.url), {
  type: "module",
});
const prover = createBrowserProver({
  worker,
  profile: "development",
  expectedArtifactHash: expectedHash,
});
const proof = await prover.proveDevelopment(7, {
  onProgress(stage) {
    console.log(stage);
  },
});
```

`selectCircuitArtifact("production", developmentManifest, hash)` is `VERSION_UNSUPPORTED`.
A hash mismatch is `ProverError ARTIFACT_INVALID`. `proveSpend` is `KEYS_MISSING`.

Development proofs are not for production. Do not substitute roots or artifacts after
authorization.

## Workflows

`createWorkflowClient` accepts provider-neutral wallet, transport, quote, policy, and finality
adapters. Cancel during prove does not consume authorization nonces. See
`examples/direct-shield.mjs` for the integrator shape.

## License

Apache-2.0.
