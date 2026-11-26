import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { PRODUCTION_HOST, PRODUCTION_URL } from "../dev/production-origin.mjs";

const challengeRoute = readFileSync(new URL("../web/apps/haze/app/api/v1/auth/challenge/route.ts", import.meta.url), "utf8");
const bff = readFileSync(new URL("../web/apps/haze/app/api/v1/_lib.ts", import.meta.url), "utf8");
const disclosureRoute = readFileSync(new URL("../web/apps/haze/app/api/compliance/auth/challenge/route.ts", import.meta.url), "utf8");
const disclosureAuth = readFileSync(new URL("../services/disclosure/src/http.rs", import.meta.url), "utf8");

test("production SIWE uses the one canonical host and page request host binding", () => {
  assert.equal(`https://${PRODUCTION_HOST}`, PRODUCTION_URL);
  assert.match(challengeRoute, /headers\.get\("host"\)/);
  assert.match(challengeRoute, /createChallengeBFF\([^;]+requestHost/s);
  assert.match(bff, /X-Haze-Origin-Host/);
  assert.match(disclosureRoute, /headers\.get\("host"\)/);
  assert.match(disclosureAuth, /bound_siwe_config/);
  assert.doesNotMatch(bff, /haze-mu-flax\.vercel\.app/);
});
