# Haze Privacy Pool

USDC-only private pool on Avalanche C-Chain / Fuji. This repository is the Haze
product: contracts, Circom circuits, Rust services, TypeScript SDK, and the
Privacy Pool DEX.

It is not a fork of Nethermind `stellar-private-payments` and does not import
Stellar, Soroban, or Freighter adapters.

## Layout

- `haze/` — product workspace (contracts, circuits, crates, services, SDK, web, tests)
- `poseidon2/` — sibling crate required by `haze-protocol` (`path = "../../../poseidon2"`)
- `docs/ai/` — requirements, design, planning, implementation, and testing notes
- `haze/deployments/fuji-v1.json` — committed Fuji package (`broadcast: false`, `spend_prove: KEYS_MISSING`)
- `haze/deployments/fuji-v1.live.json` — operator-owned live sidecar (not a ceremony approval)

## Foundations

```sh
npm test --prefix haze
npm run build --prefix haze
cargo test --manifest-path haze/Cargo.toml --workspace
forge build --root haze/contracts
```

## Operator hatch (Fuji demo)

Committed package stays fail-closed (`KEYS_MISSING`). A local operator with a
gitignored zkey can run:

```sh
PORT=3014 npm run commercial:operator --prefix haze
```

That host is not a public clone-and-run proving package and does not flip SC-09.

## License

Source in this snapshot is unpublished pending a license file. Do not treat
publication of the git history as a grant of production proving keys.
