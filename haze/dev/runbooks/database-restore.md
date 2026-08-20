# Database restore

Owner: protocol-ops
Escalation: incident-commander → security-oncall

## Hard stops

- Restore is from `DurableStore::backup` snapshots only. Schema version must remain 2.
- Retention is write-once. Do not shrink or rewrite historical audit rows.
- Restored snapshots must not contain witnesses, plaintext notes, or KMS secrets.

## Procedure

1. Pause user traffic (`pause.md`).
2. Take a forensic copy of the failed store before overwrite.
3. Call `DurableStore::restore(snapshot)` with the last known-good backup.
4. Re-run indexer recovery (`rpc-indexer-recovery.md`) so chain and store agree.
5. Record the restore in the audit log with the snapshot hash only.

## Local tabletop

Verified against `DurableStore::backup` / `restore` in `haze/crates/protocol/src/ops.rs`.

Fuji-configured rehearsal: chainId 43113, Circle USDC `0x5425890298aed601595a70AB815c96711a31Bc65`, and `deployments/fuji-v1.json`. Live broadcast remains operator-owned.
