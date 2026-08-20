# Haze deployments

This directory holds immutable, versioned deployment manifests for local development, Fuji,
and Avalanche C-Chain mainnet. Development artifacts must never be selectable by production
configuration.

`fuji-v1.json` is the T7.1 version-pinned Fuji package. It is labeled `not_for_production`,
does not broadcast, and keeps production spend keys `KEYS_MISSING`. Live RPC remains
operator-owned.

`fuji-v1.live.json` is a development sidecar with 20-byte addresses from a Fuji broadcast that
uses the development-equality verifier. It does not replace `fuji-v1.json`, does not flip SC-09,
and does not invent production Groth16 keys (`spend_prove` stays `KEYS_MISSING`). A later
sidecar field records one development-digest `HazePool.deposit` of 1 USDC.

`mainnet-v1.json` is the T7.5 unauthorized Avalanche C-Chain plan (`chainId` 43114).
It stays `authorized: false` and `broadcast: false`. Owners, KMS, identity, live RPC,
and USDC remain operator-owned. Production spend keys stay `KEYS_MISSING`. SC-09
gates stay closed.

T1.4 ceremony tooling and SC-09 provenance live under `haze/dev/`. Production ceremony
execution is T7.4 and remains blocked until the four SC-09 approvals exist together.

