# Disclosure incident

Owner: disclosure-ops
Escalation: legal-oncall → super-auditor

## When

Unauthorized disclosure, auditor key misuse, or a request that would leak another application's notes.

## Procedure

1. Revoke or rotate the implicated auditor key (`signer-kms-policy-rotation.md`).
2. Freeze further disclosure jobs for that application until legal-oncall signs off.
3. Collect evidence only through `redactEvidence`. Replace secrets with `[redacted]`.
4. Write the incident record in the durable store. Do not attach ciphertexts or witnesses to tickets.
5. If a user must be notified, use `user-communication.md`. Do not notify other applications.

## Local tabletop

Verified against `export function redactEvidence` in `haze/dev/e2e.mjs`.

Fuji-configured rehearsal: chainId 43113, Circle USDC `0x5425890298aed601595a70AB815c96711a31Bc65`, and `deployments/fuji-v1.json`. Live broadcast remains operator-owned.
