#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { HAZE_ROOT, verifyTranscript } from "./lib.mjs";

const path = process.argv[2] ?? join(HAZE_ROOT, "dev/artifacts/rehearsal-ceremony.json");
const transcript = JSON.parse(readFileSync(path, "utf8"));
verifyTranscript(transcript);
process.stdout.write(`haze ceremony transcript ok (${transcript.contributions.length} contributions)\n`);
