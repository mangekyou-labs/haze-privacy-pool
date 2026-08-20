#!/usr/bin/env node
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { HAZE_ROOT, SPEND_CIRCUIT_ID } from "./lib.mjs";

const STRIP_KEYS = new Set(["entropy", "entropy_commitment", "entropyCommitment", "toxic_waste"]);

export function publicTranscript(input) {
  const contributions = (input?.contributions ?? []).map((entry) => ({
    contributor: entry.contributor,
    zkey_hash: entry.zkey_hash ?? entry.zkeyHash,
  }));
  return {
    circuit_id: input?.circuit_id ?? SPEND_CIRCUIT_ID,
    profile: "operator-owned",
    not_for_production: true,
    production_ceremony_approved: false,
    contributions,
  };
}

export function writePublicTranscript(input, dest = join(HAZE_ROOT, "dev/artifacts/production-ceremony-transcript.json")) {
  const transcript = publicTranscript(input);
  if (Object.keys(transcript).some((key) => STRIP_KEYS.has(key))) {
    throw new Error("ENCODING_INVALID");
  }
  writeFileSync(dest, `${JSON.stringify(transcript, null, 2)}\n`);
  return dest;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.stdout.write(`${JSON.stringify(publicTranscript({ circuit_id: SPEND_CIRCUIT_ID, contributions: [] }), null, 2)}\n`);
}
