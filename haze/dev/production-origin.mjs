/** The only canonical production origin used by acceptance tooling and SIWE. */
export const PRODUCTION_HOST = "haze-avax.vercel.app";
export const PRODUCTION_URL = `https://${PRODUCTION_HOST}`;

export const LEGACY_VERCEL_HOSTS = Object.freeze([
  "haze-mu-flax.vercel.app",
  "haze.vercel.app",
  "haze-finance.vercel.app",
  "haze-pool.vercel.app",
]);

export function resolveSiweDomain(requestHost, fallbackDomain = "compliance.haze.network") {
  const host = typeof requestHost === "string" ? requestHost.split(":", 1)[0].toLowerCase() : "";
  if (host === PRODUCTION_HOST) return PRODUCTION_HOST;
  return process.env.HAZE_COMPLIANCE_DOMAIN ?? fallbackDomain;
}
