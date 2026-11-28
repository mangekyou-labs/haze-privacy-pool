import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

test("Vercel excludes local-only tool and ceremony artifacts", () => {
  const ignored = readFileSync(new URL("../.vercelignore", import.meta.url), "utf8")
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter(Boolean);

  assert.ok(ignored.includes(".tools"));
  assert.ok(ignored.includes("dev/artifacts/ceremony-private"));
});
