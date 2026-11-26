import { readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const testsDir = join(ROOT, "tests");
const browserTestFiles = readdirSync(testsDir)
  .filter((f) => f.endsWith(".test.mjs") && (f.includes("playwright") || f.includes("browser-e2e")))
  .sort()
  .map((f) => join("tests", f));

if (browserTestFiles.length === 0) {
  console.log("No browser tests found.");
  process.exit(0);
}

// Run browser tests serially with explicit per-process timeout
let allPassed = true;
for (const testFile of browserTestFiles) {
  console.log(`Running browser test: ${testFile}`);
  const result = spawnSync("node", ["--experimental-strip-types", "--test", testFile], {
    cwd: ROOT,
    stdio: "inherit",
    env: process.env,
    timeout: 60_000,
  });
  if (result.status !== 0) {
    allPassed = false;
    break;
  }
}

process.exit(allPassed ? 0 : 1);
