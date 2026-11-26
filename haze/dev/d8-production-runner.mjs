import { PRODUCTION_URL } from "./production-origin.mjs";

const FORBIDDEN_ORIGIN = /(?:localhost|127\.0\.0\.1|preview\.vercel\.app)/i;

export function assertProductionOrigin(value) {
  const url = new URL(value);
  if (url.protocol !== "https:" || FORBIDDEN_ORIGIN.test(url.hostname)) {
    throw new Error(`D8_INVALID_ORIGIN: ${value}`);
  }
  return url.origin;
}

export function planD8ProductionJourney(options = {}) {
  const productionUrl = assertProductionOrigin(options.productionUrl ?? PRODUCTION_URL);
  return {
    productionUrl,
    chainId: options.chainId ?? 43113,
    runner: options.runner ?? "playwright-audit-walk.mjs",
  };
}
