import {
  createBrowserProver,
  createWorkflowClient,
} from "../src/index.ts";

/**
 * Reference direct-shield integration.
 *
 * Construct a Web Worker from `@haze-avalanche/sdk/worker` and pass it to
 * `createBrowserProver`. Production spend proving returns KEYS_MISSING until
 * the ceremony. Adapters stay provider-neutral: supply your own wallet send,
 * RPC transport, and quote source.
 */
export function createDirectShieldExample(config) {
  const prover = createBrowserProver({
    worker: config.worker,
    profile: "development",
    expectedArtifactHash: config.expectedArtifactHash,
  });
  const workflow = createWorkflowClient({
    ...config,
    prover,
  });
  return {
    prover,
    workflow,
    async run(input) {
      return workflow.run("direct-shield", input);
    },
  };
}
