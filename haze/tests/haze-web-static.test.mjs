import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { LEGACY_VERCEL_HOSTS, PRODUCTION_HOST, PRODUCTION_URL } from "../dev/production-origin.mjs";

const config = JSON.parse(readFileSync(new URL("../vercel.json", import.meta.url), "utf8"));

test("legacy Vercel aliases permanently redirect to the canonical origin", () => {
  const redirects = config.redirects ?? [];
  assert.equal(redirects.length, LEGACY_VERCEL_HOSTS.length);
  for (const host of LEGACY_VERCEL_HOSTS) {
    const redirect = redirects.find((candidate) => candidate.has?.some((entry) => entry.type === "host" && entry.value === host));
    assert.ok(redirect, `missing redirect for ${host}`);
    assert.equal(redirect.destination, `${PRODUCTION_URL}/:path*`);
    assert.equal(redirect.permanent, true);
  }
});

test("the canonical host is not redirected and preview hosts stay untouched", () => {
  const redirectHosts = (config.redirects ?? []).flatMap((redirect) =>
    (redirect.has ?? []).map((entry) => entry.value),
  );
  assert.ok(!redirectHosts.includes(PRODUCTION_HOST));
  assert.doesNotMatch(redirectHosts.join("\n"), /preview|\*\.vercel\.app/i);
  assert.match(JSON.stringify(config.redirects ?? []), new RegExp(PRODUCTION_HOST.replaceAll(".", "\\.")));
});
