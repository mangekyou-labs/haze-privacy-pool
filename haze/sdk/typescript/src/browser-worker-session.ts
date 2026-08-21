export type BrowserWorkerRequest = {
  type: string;
  requestId?: string;
  value?: number;
  circom?: Record<string, unknown>;
  wasm?: Uint8Array;
  zkey?: Uint8Array;
};

export type BrowserWorkerResponse =
  | { type: "progress"; requestId: string; stage: string; percent: number }
  | { type: "success"; requestId: string; proof: unknown }
  | { type: "cancelled"; requestId?: string }
  | { type: "cleared" }
  | { type: "error"; requestId?: string; code: string };

export type BrowserGroth16 = {
  fullProve(
    input: Record<string, unknown>,
    wasm: Uint8Array,
    zkey: Uint8Array,
  ): Promise<{ proof: unknown; publicSignals: string[] }>;
};

function fieldValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(fieldValue);
  if (typeof value === "bigint" || typeof value === "number") return value.toString();
  if (typeof value === "string") return value.startsWith("0x") ? BigInt(value).toString() : value;
  throw Object.assign(new Error("WITNESS_INVALID"), { code: "WITNESS_INVALID" });
}

function circomInput(circom: Record<string, unknown>) {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(circom)) {
    if (["circuitId", "circuit_id", "wasm", "zkey"].includes(key)) continue;
    result[key] = fieldValue(value);
  }
  return result;
}

/** Browser-only proving state with web-platform dependencies only. */
export function createBrowserWorkerSession(runtime: () => Promise<BrowserGroth16>) {
  const cancelled = new Set<string>();
  return async function handle(
    message: BrowserWorkerRequest,
    emit: (response: BrowserWorkerResponse) => void,
  ) {
    const requestId = message.requestId ?? "unscoped";
    if (message.type === "cancel") {
      if (message.requestId) cancelled.add(message.requestId);
      else cancelled.add("*");
      emit({ type: "cancelled", requestId: message.requestId });
      return;
    }
    if (message.type === "clear") {
      cancelled.clear();
      emit({ type: "cleared" });
      return;
    }
    const stopped = () => cancelled.has("*") || cancelled.has(requestId);
    if (stopped()) {
      emit({ type: "cancelled", requestId });
      return;
    }
    if (message.type === "prove-development") {
      emit({ type: "progress", requestId, stage: "development", percent: 50 });
      emit({
        type: "success",
        requestId,
        proof: { profile: "development", notForProduction: true, publicValue: message.value ?? 0, verified: true },
      });
      return;
    }
    if (message.type !== "prove-spend" || !message.wasm || !message.zkey) {
      throw Object.assign(new Error("KEYS_MISSING"), { code: "KEYS_MISSING" });
    }
    emit({ type: "progress", requestId, stage: "witness", percent: 10 });
    const groth16 = await runtime();
    if (stopped()) {
      emit({ type: "cancelled", requestId });
      return;
    }
    emit({ type: "progress", requestId, stage: "prove", percent: 40 });
    const result = await groth16.fullProve(circomInput(message.circom ?? {}), message.wasm, message.zkey);
    if (stopped()) {
      emit({ type: "cancelled", requestId });
      return;
    }
    emit({ type: "progress", requestId, stage: "complete", percent: 100 });
    emit({ type: "success", requestId, proof: result });
  };
}
