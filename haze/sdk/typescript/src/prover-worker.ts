// @ts-expect-error snarkjs does not publish declarations for this browser entry.
import { groth16 } from "../../../node_modules/snarkjs/build/browser.esm.js";
import { createBrowserWorkerSession } from "./browser-worker-session.ts";

const handle = createBrowserWorkerSession(async () => groth16);

self.addEventListener("message", async (event: MessageEvent) => {
  try {
    await handle(event.data, (result) => self.postMessage(result));
  } catch (error) {
    const code = error instanceof Error && "code" in error ? error.code : "PROOF_INVALID";
    const message = error instanceof Error ? error.message : String(error);
    self.postMessage({ type: "error", requestId: event.data?.requestId, code, message });
  }
});
