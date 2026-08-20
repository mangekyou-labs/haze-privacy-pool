import { createProverSession, handleProverWorkerMessage } from "./prover-session.ts";

const session = createProverSession();

self.addEventListener("message", async (event: MessageEvent) => {
  try {
    const result = await handleProverWorkerMessage(session, event.data);
    self.postMessage(result);
  } catch (error) {
    const code = error instanceof Error && "code" in error ? error.code : "PROOF_INVALID";
    self.postMessage({ type: "error", code });
  }
});
