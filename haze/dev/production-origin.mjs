/** The only canonical production origin used by acceptance tooling. */
export const PRODUCTION_HOST = "compliance-haze.vercel.app";
export const PRODUCTION_URL = `https://${PRODUCTION_HOST}`;

export const LEGACY_VERCEL_HOSTS = Object.freeze([
  "haze-mu-flax.vercel.app",
  "haze.vercel.app",
  "haze-finance.vercel.app",
  "haze-pool.vercel.app",
  "haze-avax.vercel.app",
]);

export function stripPort(host) {
  return typeof host === "string" ? host.split(":", 1)[0].trim().toLowerCase() : "";
}

export function resolveSiweDomain(requestHost, fallbackDomain = "compliance.haze.network") {
  if (stripPort(requestHost) === PRODUCTION_HOST) return PRODUCTION_HOST;
  return process.env.HAZE_COMPLIANCE_DOMAIN ?? fallbackDomain;
}
