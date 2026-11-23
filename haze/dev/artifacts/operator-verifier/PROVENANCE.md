# Operator Groth16 verifier provenance

`HazeGroth16Verifier.generated.sol` is the snarkjs-generated verifier for `haze-spend-v1`,
deployed on Fuji at `0x87513584DF1f082ff3a34f15EAD5d3D14C7e0639`. This is an operator-run
development setup (`production_ceremony_approved: false`), not a production ceremony.

| Artifact | sha256 | Matches |
| --- | --- | --- |
| Final zkey (public, see `web/apps/haze/public/proving/fuji-development/haze-spend-v1/manifest.json`) | `374bb2394da985ab824ce61a95b3b3409b71355139f0a6b16fb8e0bff8e508d5` | final contribution `zkey_hash` in `../operator-owned-ceremony-transcript.json` |
| `verification_key.json` | `09534f9af477daf1e8d45c20c796b3d5f8ddf25c4584ff789df0f29158d391c4` | transcript `verification_key_sha256` |
| `HazeGroth16Verifier.generated.sol` | `cce1cb53c7e93a814b3af6a3f8eec55f4bac2018ffa2548d4d318fa1aa94e066` | transcript `generated_verifier_sha256` |

Compiled with this repo's `foundry.toml` (solc 0.8.28, via-IR, no CBOR metadata), the runtime
bytecode is byte-identical (5725 bytes) to the deployed contract.

## Reproduce

```sh
curl -o spend.zkey "$(jq -r .zkey.url haze/web/apps/haze/public/proving/fuji-development/haze-spend-v1/manifest.json)"
npx snarkjs@0.7.6 zkey export verificationkey spend.zkey vk.json
npx snarkjs@0.7.6 zkey export solidityverifier spend.zkey HazeGroth16Verifier.generated.sol
shasum -a 256 spend.zkey vk.json HazeGroth16Verifier.generated.sol

cd haze/contracts && forge build
diff <(jq -r .deployedBytecode.object out/HazeGroth16Verifier.generated.sol/Groth16Verifier.json) \
     <(cast code 0x87513584DF1f082ff3a34f15EAD5d3D14C7e0639 --rpc-url https://api.avax-test.network/ext/bc/C/rpc) \
  && echo "bytecode identical"
```
