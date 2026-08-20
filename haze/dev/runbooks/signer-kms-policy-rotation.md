# Signer, KMS, and policy rotation

Owner: gatekeeper-ops
Escalation: security-oncall → super-auditor

## Hard stops

- Do not paste KMS material, seed phrases, or x25519 secrets into tickets, logs, or this catalog.
- Policy rotation is write-once for a version. A new policy is a new version, not an overwrite.

## Procedure

1. Generate the next signer or KMS key outside this repository.
2. Compute `haze_protocol::ops::rotation_id(application_id, previous, next)` and record only the hash.
3. Schedule the policy or signer change through governance (`POST /v1/governance/schedule` is a super-auditor API, not a user API).
4. After the delay, activate the next policy root. Old signatures must fail domain checks.
5. Retire the previous key in KMS. Keep the rotation id in the durable audit store.

## Local tabletop

Verified against `rotation_id` in `haze/crates/protocol/src/ops.rs` and T4.5 ops tests.

Fuji-configured rehearsal: chainId 43113, Circle USDC `0x5425890298aed601595a70AB815c96711a31Bc65`, and `deployments/fuji-v1.json`. Live broadcast remains operator-owned.
