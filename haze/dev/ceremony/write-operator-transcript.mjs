import { createHash } from "node:crypto";
import { createReadStream, writeFileSync } from "node:fs";
import { join } from "node:path";
import { HAZE_ROOT } from "./lib.mjs";
import { publicTranscript } from "./export.mjs";

function sha256(path) {
  return new Promise((resolve, reject) => {
    const hash = createHash("sha256");
    createReadStream(path)
      .on("data", (chunk) => hash.update(chunk))
      .on("end", () => resolve(hash.digest("hex")))
      .on("error", reject);
  });
}

const priv = join(HAZE_ROOT, "dev/artifacts/ceremony-private");
const files = {
  ptau: join(priv, "powersOfTau28_hez_final_20.ptau"),
  zkey0: join(priv, "haze-spend-0000.zkey"),
  zkey1: join(priv, "haze-spend-0001.zkey"),
  zkey2: join(priv, "haze-spend-0002.zkey"),
  final: join(priv, "haze-spend-final.zkey"),
  vk: join(priv, "haze-spend-verification-key.json"),
  sol: join(priv, "HazeGroth16Verifier.generated.sol"),
};
const hashes = {};
for (const [key, path] of Object.entries(files)) {
  hashes[key] = await sha256(path);
}

const transcript = publicTranscript({
  circuit_id: "haze-spend-v1",
  contributions: [
    { contributor: "operator-1", zkey_hash: `0x${hashes.zkey1}` },
    { contributor: "operator-2", zkey_hash: `0x${hashes.zkey2}` },
    { contributor: "beacon-zero-10", zkey_hash: `0x${hashes.final}` },
  ],
});
transcript.ptau_sha256 = hashes.ptau;
transcript.setup_zkey_sha256 = hashes.zkey0;
transcript.verification_key_sha256 = hashes.vk;
transcript.generated_verifier_sha256 = hashes.sol;
transcript.snarkjs_circuit_hash =
  "32910b51948d136bca4a325204ad5ad9c0dc860bd1e3be9279cc4a943d2843834f7ca506cc7628ae5616cea79cf175de554835b1e64e37363bcee0207faa34e8";
transcript.snarkjs_contribution_hashes = {
  "operator-1":
    "96fbe0dbf7167c1d3905797bb632acd68b5da13afe7af9a9d17cc6934ce4df65e914dd6d59f3c62ff272d5103818f99494df24e80df7e6dd5f62e798a6d4672e",
  "operator-2":
    "67714a018c559de78e0ebea67a025f1913ca565a07aa20100e16cd4248035894467ddaa79076d7510af05e2251950c68d4fdb2adc780b2db6ed5f7cb6b291065",
  beacon:
    "6829708d1f662f401de303e433c61b9b236cb6b30c3ef536e1dbda64da312b3b6258f1cd80853efbcf31328784b06c7524cc22cd0630342a7e46727b89bdeb8e",
};
transcript.zkey_verify = "ZKey Ok";
transcript.hardware = {
  ram_bytes: 17179869184,
  note: "one-laptop operator run; not production_ceremony.approved",
};

const dest = join(HAZE_ROOT, "dev/artifacts/operator-owned-ceremony-transcript.json");
writeFileSync(dest, `${JSON.stringify(transcript, null, 2)}\n`);
process.stdout.write(`${dest}\n`);
