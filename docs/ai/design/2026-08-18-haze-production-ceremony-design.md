# Haze production Groth16 ceremony pipeline

date: 2026-08-18
status: approved
feature: haze-avalanche-compliant-pool
does-not-replace: T1.4 / T7.4 documented rehearsal, SC-09, committed `fuji-v1.json`

## Goal

Give operators a Haze-owned snarkjs pipeline that can run Groth16 phase-2 against the frozen
`haze-spend-v1` r1cs (588459 constraints, Circom 2.2.3). Do not treat a one-laptop run as
`production_ceremony.approved`. Do not flip committed Fuji or SC-09.

## Why Builder Hub is not this

`https://build.avax.network/llms.txt` indexes L1s, ICM/ICTT, faucet, RPC, Foundry/Hardhat, wallets,
and Avalanche Encrypted ERC Groth16. eERC keys are a different circuit and different public inputs.
They are not a Powers-of-Tau or phase-2 service for `haze-spend-v1`. Using them would be a security
failure.

`KEYS_MISSING` is operator-owned Haze ceremony work, not an Avalanche RPC or wallet problem.

## Decisions

| Topic | Choice |
|---|---|
| Circuit | Frozen `haze/circuits/build/spend/spend.r1cs` only. Hashes must match `circuit-build-manifest.json` |
| Phase 1 | Public Hermez `powersOfTau28_hez_final_20.ptau` (2^20 = 1,048,576 > 588,459). PSE perpetual ptau of the same power is an allowed alternate URL |
| Phase 2 | `snarkjs groth16 setup` → ≥2 CSPRNG contributions → beacon → `zkey verify` |
| Export | Verification key JSON + Solidity verifier. Public transcript: contributor names + zkey hashes |
| Toxic waste | Proving key and intermediate zkeys stay in gitignored `haze/dev/artifacts/ceremony-private/` |
| Parent CLI | Do not import or wrap `tools/ceremony-cli` (Stellar `policy_tx_2_2_AB`, ptau 16) |
| Activation | SC-09 all four gates stay `approved: false`. One-laptop setup is not production |
| Live Fuji | Current verifier is immutable and reverts `production=true`. Pairing needs a new set later, out of this milestone |
| Prover | `proveSpend` stays `KEYS_MISSING` unless an operator zkey path is supplied. Browser/web never ships the key |

## Out of scope

- Flipping `haze/deployments/fuji-v1.json` (`broadcast: false`, `spend_prove: KEYS_MISSING`)
- Flipping SC-09 or `mainnetAuthorized`
- Calling this run `production_ceremony.approved`
- Inventing or committing Groth16 proving keys or fake pairing points
- Redeploying the live Fuji verifier/pool/router/exit
- Encrypted ERC, Unlink, or Builder Hub circuits
- Wrapping parent `tools/ceremony-cli` as a Haze public API

## Driver

```text
haze/dev/ceremony/ptau.mjs      download + checksum Hermez ptau 20
haze/dev/ceremony/phase2.mjs    setup / contribute / beacon / verify
haze/dev/ceremony/export.mjs    vk JSON, Solidity, public transcript
haze/dev/ceremony/production.mjs orchestration + refuse-rehearsal gates
```

Entropy is redacted from logs. The public transcript must not contain raw entropy.

## Verifier wrap

Committed `HazeSpendVerifier` is unchanged: `production=true` reverts `KEYS_MISSING`.
A sibling `HazeSpendVerifierPairing` documents the pairing-shaped backend and still reverts
`KEYS_MISSING` on `production=true` until a later SC-09 flip. Do not upgrade the live Fuji address.

## Operator run

Requires ≥16 GB RAM and can take hours. If the machine cannot finish, stop and report.
A finished local run is still not a multi-party production ceremony.

## Testing

TDD. `haze/tests/production-ceremony.test.mjs` refuses the equality rehearsal as a spend zkey,
pins 588459 / Circom 2.2.3 / committed hashes, requires ptau power 20, keeps fuji-v1 and SC-09
closed, and scans Haze sources so they do not import `tools/ceremony-cli`.
`npm test --prefix haze` stays green.
