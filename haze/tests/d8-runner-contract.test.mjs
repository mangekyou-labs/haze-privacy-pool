import assert from "node:assert/strict";
import test from "node:test";
import { PRODUCTION_URL } from "../dev/production-origin.mjs";
import { planD8ProductionJourney } from "../dev/d8-production-runner.mjs";

test("D8 defaults to the canonical production origin", () => {
  assert.equal(planD8ProductionJourney().productionUrl, PRODUCTION_URL);
  assert.equal(PRODUCTION_URL, "https://compliance-haze.vercel.app");
});

test("D8 rejects localhost and preview deployment origins", () => {
  for (const productionUrl of [
    "http://localhost:3000",
    "https://127.0.0.1:3000",
    "https://haze-git-feature-preview.vercel.app",
  ]) {
    assert.throws(() => planD8ProductionJourney({ productionUrl }), /D8_INVALID_ORIGIN/);
  }
});
