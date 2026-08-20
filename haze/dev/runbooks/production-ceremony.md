# Production Groth16 ceremony runbook

This runbook is the operator procedure for a future production trusted setup.
It is **not** authorization to run that ceremony now.

## Hard stops

- T7.4 must not start until T7.3 has frozen the audited spend circuit and
  recorded the independent-audit artifact hash.
- Do not generate 588459-constraint proving keys from this T1.4 rehearsal.
- Development and rehearsal artifacts are `not_for_production`. Production
  configuration must reject them (`VERSION_UNSUPPORTED`).
- Do not import or wrap the parent Stellar `tools/ceremony-cli` as a Haze
  public API. That CLI targets `policy_tx_2_2_AB` on a different stack.
- Circom must be exactly 2.2.3 at `haze/.tools/bin/circom`.
- Spend proving remains `KEYS_MISSING` until the production ceremony publishes
  verifying keys that match the frozen `haze-spend-v1` source and constraint
  hashes.

## SC-09

Production activation stays blocked until all four records exist, each with an
artifact hash:

1. Fuji pilot approval
2. Independent smart-contract and circuit audit approval
3. Production Groth16 multi-party ceremony approval
4. Operational incident-review approval

`haze-protocol::ceremony::assert_production_activation` returns
`VERSION_UNSUPPORTED` until those four approvals are present.

## Development rehearsal (T1.4)

Use only the tiny equality circuit `haze/circuits/test/development_equality.circom`.

```sh
node haze/dev/ceremony/setup.mjs
node haze/dev/ceremony/rehearse.mjs
node haze/dev/ceremony/verify-transcript.mjs
node haze/dev/ceremony/sign-manifest.mjs
```

Two clean equality-circuit builds must match r1cs hashes. Every contribution
must recompute from the domain-separated genesis. The generated Solidity file
`haze/dev/artifacts/DevelopmentEqualityVerifier.sol` is a hash-gated equality
check labeled `NOT_FOR_PRODUCTION`. T2.1 owns the immutable spend verifier.

## T7.4 library package

T7.4 publishes a **documented-rehearsed** public contribution process. Independent
verification reuses the T1.4 rehearsal transcript via `verifyTranscript`. The
generated verifier stays `DevelopmentEqualityVerifier` and `NOT_FOR_PRODUCTION`.
Production spend proving stays `KEYS_MISSING` until an operator publishes
matching production verifying keys (T7.5). Do not generate 588459-constraint
proving keys from this package. SC-09 `production_ceremony.approved` stays false.

## Operator pipeline (not production approval)

Haze-owned snarkjs driver against frozen `haze-spend-v1`. Avalanche Builder Hub
and Encrypted ERC keys are the wrong circuit. Parent `tools/ceremony-cli` stays
out of the Haze public API.

```sh
node haze/dev/ceremony/ptau.mjs
node haze/dev/ceremony/phase2.mjs
node haze/dev/ceremony/export.mjs
```

- Phase 1: Hermez `powersOfTau28_hez_final_20.ptau` (power 20).
- Phase 2: `groth16 setup` → ≥2 CSPRNG contributions → beacon → `zkey verify`.
- Export: verification key + Solidity. Public transcript is names + zkey hashes.
- Proving keys stay in gitignored `haze/dev/artifacts/ceremony-private/`.
- A one-laptop run is **not** `production_ceremony.approved`.
- Committed `fuji-v1.json` stays `broadcast: false` / `spend_prove: KEYS_MISSING`.
- Live Fuji `HazeSpendVerifier` is immutable. Pairing requires a new set later.

### Demo operator spend vs T7.4

A Fuji **demo** spend uses the operator-owned zkey and pairing verifier. It is
not T7.4 / T7.5 and must not flip committed `spend_prove`.

The keccak pairing pool (`0x97bB3063…`) remains unspendable. Circuit-valid
demo notes live on `HazePoolPoseidon` (`0x00BEB0A5…`) with a real membership
root and the sentinel blocklist.

Start the clickable operator host with `npm run commercial:operator` from
`haze/` (sets `HAZE_OPERATOR_PROVE=1`, requires the gitignored zkey). Default
`npm run commercial` stays fail-closed (`KEYS_MISSING`). The browser never
fetches the zkey. Committed `fuji-v1.json` stays `broadcast: false` /
`KEYS_MISSING`.

Headed MetaMask Shield → Withdraw (operator hatch, not T7.4):

```sh
PORT=3014 npm run commercial:operator
HAZE_COMMERCIAL_URL=http://127.0.0.1:3014 npm run dappwright:live-operator
```

Groth16 prove can take several minutes per action. Success is mined receipts
(`status: 0x1`). The hatch plans an unused Poseidon note; it must not reuse a
commitment already on the live pool. playwright-cli does not claim
`notification.html`.

Two live shield paths — do not mix them:

- **Default `/shield?live=1`** (hatch off): keccak **digest** deposit. These
  notes must not be Groth16-spent.
- **Operator hatch `/shield?live=1`** (`HAZE_OPERATOR_PROVE=1` + local zkey):
  circuit-valid Poseidon deposit. The host persists the spendable note to
  gitignored `dev/artifacts/ceremony-private/fuji-poseidon-note.json`. Then
  `/withdraw?live=1` proves a Groth16 spend of **that** note.

Private send stays closed even with the hatch.

### Operator run 2026-08-18 (this laptop)

Hermez ptau 20 downloaded (SHA-256
`159d3f938d941e06767d99f30b9fe59a245400a4aae138cf8e411732d7a2f6cd`).
`snarkjs zkey verify` reported `ZKey Ok!` after two CSPRNG contributions and a
zero-beacon (10 iterations). Public hashes live in
`haze/dev/artifacts/operator-owned-ceremony-transcript.json`. Proving keys stay
in gitignored `haze/dev/artifacts/ceremony-private/`. This run is **not**
`production_ceremony.approved` and does not flip `fuji-v1.json`.

## Production ceremony (T7.4 only)

After audit freeze:

1. Recompute the spend circuit-build manifest from the frozen source and r1cs.
2. Confirm `n_constraints = 588459` and Circom 2.2.3.
3. Run an independent multi-party Powers-of-Tau and circuit-specific phase
   against that frozen r1cs. Verify every contribution from the published
   transcript.
4. Export the verifying key and a Solidity verifier. Wrap it in T2.1 with the
   29 public-input checks. Do not leave a proxy or admin mutation path.
5. Sign the production artifact manifest. Publish provenance with the four
   SC-09 hashes. Only then may spend proving leave `KEYS_MISSING`.

## Failure handling

A mismatched source hash, constraint count, contribution link, or verifier
artifact hash aborts the ceremony. Any circuit change after T7.3 invalidates
T7.4 and requires re-audit plus a new ceremony review.
