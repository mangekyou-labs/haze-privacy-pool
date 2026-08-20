# Haze Avalanche Compliant Pool

Haze is an independent Avalanche C-Chain product. It combines a private,
USDC-only pool with application gatekeepers, association-set policy, encrypted audit records, a
Privacy Pool DEX, and a separate Compliance Portal.

## Product boundary

The `haze/` tree owns its public contracts, circuits, Rust services, SDK, frontends, deployments,
and tests. It is a nested workspace so its dependency graph can be validated without inheriting
another network's packages. Public Haze source and manifests must not import Stellar, Soroban,
Freighter, or SEP authentication adapters. The architecture test in
`tests/product-boundary.test.mjs` enforces this rule. Run `secret-scan` before review.

## Packages

- `contracts/`: Solidity and Foundry contracts for Avalanche C-Chain.
- `circuits/`: Haze-specific Circom circuits and language-neutral vectors.
- `crates/protocol/`: canonical, provider-neutral protocol types and encodings.
- `crates/prover/`: native prover and cryptographic client primitives.
- `services/`: gatekeeper, indexer, audit authorization, and disclosure services.
- `sdk/typescript/`: TypeScript integration SDK and browser-facing interfaces.
- `apps/privacy-pool-dex/`: end-user Privacy Pool DEX deployment.
- `apps/compliance-portal/`: administrator, auditor, and governance portal deployment.
- `apps/_shared/`: shared Haze UX contracts (not a Node package).
- `deployments/`: versioned local, Fuji, and mainnet deployment manifests.
- `tests/`: product-boundary and future cross-component tests.

## Foundation checks

```sh
npm test --prefix haze
npm run build --prefix haze
cargo test --manifest-path haze/Cargo.toml --workspace
forge build --root haze/contracts
```

This foundation includes the independent product boundary, provider-neutral interfaces, mock tokens,
and canonical encodings plus four-language vector harnesses. T0.2 encodings were accepted in
independent review with follow-ups that are now implemented. T0.2 stays open until product approval.
Production circuits and HazePool are not in this tree.

