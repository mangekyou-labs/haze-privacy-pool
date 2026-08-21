const RETRYABLE = new Set([502, 503, 504]);

export async function requestFujiDisclosure(options: {
  origin: string;
  body: unknown;
  fetch?: typeof globalThis.fetch;
  delaysMs?: number[];
  sleep?: (delayMs: number) => Promise<void>;
}): Promise<unknown> {
  const origin = new URL(options.origin);
  if (origin.protocol !== "https:" || origin.hostname === "localhost" || origin.hostname === "127.0.0.1") {
    throw new Error("INVALID_DISCLOSURE_ORIGIN");
  }
  const fetcher = options.fetch ?? globalThis.fetch;
  const delays = options.delaysMs ?? [1_000, 2_500, 5_000];
  const sleep = options.sleep ?? ((delayMs) => new Promise((resolve) => setTimeout(resolve, delayMs)));
  const url = new URL("/v1/fuji/disclosures/withdrawal", origin).toString();
  let lastError = "UNAVAILABLE";
  for (let attempt = 0; attempt <= delays.length; attempt += 1) {
    try {
      const response = await fetcher(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(options.body) });
      const value = await response.json() as { code?: string };
      if (response.ok) return value;
      lastError = value.code ?? "UNAVAILABLE";
      if (!RETRYABLE.has(response.status)) throw new Error(lastError);
    } catch (error) {
      lastError = error instanceof Error ? error.message : "UNAVAILABLE";
      if (lastError !== "UNAVAILABLE" && !/fetch|network/i.test(lastError)) throw error;
    }
    if (attempt < delays.length) await sleep(delays[attempt]);
  }
  throw new Error(lastError);
}
