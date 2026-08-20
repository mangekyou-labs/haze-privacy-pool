# Deploy and rollback by version

Owner: protocol-release
Escalation: incident-commander → super-auditor

This procedure deploys or rolls back a version-pinned Fuji package. Live broadcast remains operator-owned.

## Hard stops

- Contracts have no owner, proxy, or upgrade path. Rollback means **selecting a previously published version**, not mutating deployed bytecode.
- Development ceremony artifacts stay `not_for_production`. Production configuration must reject them (`VERSION_UNSUPPORTED`).
- Do not generate production proving keys from this runbook.

## Deploy (library-first)

1. Confirm `haze/dev/fixtures/stack.json`, `e2e.json`, `gates-report.json`, `security-review.json`, and this catalog verify.
2. Record the version identifiers: circuit constraint hash, verifying-key hash, policy root, and contract bytecode hashes.
3. Publish a deployment manifest that lists those hashes. Do not host HTTP or Anvil from this product.

## Rollback

1. Pause new deposits via `HazeAccess.pause` (see `pause.md`).
2. Point services and frontends at the **previous published version** in `VersionRegistry` / the deployment manifest.
3. Do not attempt a proxy upgrade. If the immutable contracts are wrong, users use emergency exit.

## Local tabletop

Verified against `production-ceremony.md`, `VersionRegistry.sol`, and `haze/dev/stack.mjs verify`.

Fuji-configured rehearsal: chainId 43113, Circle USDC `0x5425890298aed601595a70AB815c96711a31Bc65`, and `deployments/fuji-v1.json`. Live broadcast remains operator-owned.
