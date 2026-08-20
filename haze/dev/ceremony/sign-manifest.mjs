#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { HAZE_ROOT, signManifest } from "./lib.mjs";

const input = process.argv[2] ?? join(HAZE_ROOT, "dev/artifacts/rehearsal-ceremony.json");
const output = process.argv[3] ?? join(HAZE_ROOT, "dev/artifacts/rehearsal-signed-manifest.json");
const payload = readFileSync(input);
const signed = signManifest(payload);
writeFileSync(output, `${JSON.stringify(signed, null, 2)}\n`);
process.stdout.write(`haze ceremony signed ${input} -> ${output}\n`);
