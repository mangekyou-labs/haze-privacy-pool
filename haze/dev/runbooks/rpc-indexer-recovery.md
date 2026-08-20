# RPC and indexer recovery

Owner: indexer-ops
Escalation: incident-commander → protocol-ops

## When

RPC lag, missing events, or indexer health/ready failing.

## Procedure

1. Mark the indexer not-ready. Do not serve stale membership or nullifier state as current.
2. Confirm RPC endpoint health. Fail over to the secondary RPC listed in the deployment manifest. This product does not embed a vendor RPC client.
3. Replay from the last durable checkpoint (`DurableStore` schema 2). Do not skip nullifiers.
4. Compare reconstructed roots to on-chain `HazePool` / policy roots.
5. Restore ready only when health checks pass and roots match.

## Local tabletop

Verified against `haze/crates/protocol/src/ops.rs` health/ready and backup checkpoints.

Fuji-configured rehearsal: chainId 43113, Circle USDC `0x5425890298aed601595a70AB815c96711a31Bc65`, and `deployments/fuji-v1.json`. Live broadcast remains operator-owned.
