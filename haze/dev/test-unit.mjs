import { readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const testsDir = join(ROOT, "tests");
const testFiles = readdirSync(testsDir)
  .filter((f) => f.endsWith(".test.mjs") && !f.includes("playwright") && !f.includes("browser-e2e"))
  .sort()
  .map((f) => join("tests", f));

const result = spawnSync("node", ["--experimental-strip-types", "--test", ...testFiles], {
  cwd: ROOT,
  stdio: "inherit",
  env: process.env,
});

process.exit(result.status ?? 1);
