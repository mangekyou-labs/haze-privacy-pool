#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolveCircom } from "../../circuits/witness.mjs";
import {
  HAZE_ROOT,
  REHEARSAL_CIRCUIT_ID,
  ceremonyGenesis,
  fileKeccak,
  nextTranscript,
  renderDevelopmentVerifier,
  toHex,
} from "./lib.mjs";

const artifacts = join(HAZE_ROOT, "dev/artifacts");
mkdirSync(artifacts, { recursive: true });

const circom = resolveCircom(HAZE_ROOT);
const equality = join(HAZE_ROOT, "circuits/test/development_equality.circom");
if (!existsSync(equality)) {
  throw new Error(`missing ${equality}`);
}

const hashes = [0, 1].map((index) => {
  const dir = mkdtempSync(join(tmpdir(), `haze-rehearse-${index}-`));
  try {
    execFileSync(circom, [equality, "--r1cs", "--O0", "-o", dir], { encoding: "utf8" });
    return toHex(fileKeccak(join(dir, "development_equality.r1cs")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
if (hashes[0] !== hashes[1]) {
  throw new Error("two clean equality-circuit builds produced different r1cs hashes");
}

const genesis = ceremonyGenesis(REHEARSAL_CIRCUIT_ID);
const contributions = [
  { contributor: "alice", entropy: Buffer.alloc(32, 0x01) },
  { contributor: "bob", entropy: Buffer.alloc(32, 0x02) },
];
let previous = genesis;
const recorded = contributions.map(({ contributor, entropy }) => {
  const transcriptHash = nextTranscript(previous, contributor, entropy);
  previous = transcriptHash;
  return {
    contributor,
    entropy_commitment: toHex(entropy),
    transcript_hash: toHex(transcriptHash),
  };
});

const transcript = {
  circuit_id: REHEARSAL_CIRCUIT_ID,
  profile: "development",
  not_for_production: true,
  genesis: toHex(genesis),
  contributions: recorded,
  final_transcript: toHex(previous),
  two_build: {
    r1cs_hash_a: hashes[0],
    r1cs_hash_b: hashes[1],
    matched: true,
  },
};

writeFileSync(join(artifacts, "rehearsal-ceremony.json"), `${JSON.stringify(transcript, null, 2)}\n`);
writeFileSync(
  join(artifacts, "DevelopmentEqualityVerifier.sol"),
  renderDevelopmentVerifier(transcript.final_transcript),
);

const written = readFileSync(join(artifacts, "rehearsal-ceremony.json"), "utf8");
if (!written.includes(transcript.final_transcript)) {
  throw new Error("failed to persist rehearsal transcript");
}
process.stdout.write("haze ceremony rehearsal wrote transcript and development verifier\n");
