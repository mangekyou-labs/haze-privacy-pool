import { createBrowserWorkerSession } from "./browser-worker-session.ts";

const handle = createBrowserWorkerSession(async () => {
  const module = await import("snarkjs");
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
