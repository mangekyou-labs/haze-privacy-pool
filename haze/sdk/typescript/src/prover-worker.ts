import { createBrowserWorkerSession } from "./browser-worker-session.ts";

const handle = createBrowserWorkerSession(async () => {
  // Use the package's browser build explicitly so bundlers cannot select its Node condition.
  // @ts-expect-error snarkjs does not publish declarations for this browser entry.
  const module = await import("../../../node_modules/snarkjs/build/browser.esm.js");
  return module.groth16;
});

self.addEventListener("message", async (event: MessageEvent) => {
  try {
    await handle(event.data, (result) => self.postMessage(result));
  } catch (error) {
    const code = error instanceof Error && "code" in error ? error.code : "PROOF_INVALID";
    self.postMessage({ type: "error", requestId: event.data?.requestId, code });
  }
});
