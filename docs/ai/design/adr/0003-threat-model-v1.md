# ADR-0003: Protocol v1 threat-model freeze

## Status

Accepted as the working threat model. Independent review `91cfa5ee` accepted the encoding freeze
that this model bounds. Product approved T0.2 on 2026-08-17.

## Context

Haze is a compliant privacy pool: users hide values and counterparties from the public chain while applications and an institutional auditor can obtain authorized records. Relayers, DEX quotes, KMS, and identity providers are out of the T0.2 encoding freeze.

## Trust boundaries

| Actor | Trusted for | Not trusted for |
| --- | --- | --- |
| User wallet | Spending secret, X25519 private key, EIP-712 consent | Hiding a blocked note or mixing applications |
| Application gatekeeper | Membership root authenticity for its application | Haze global blocklist or other applications |
| Haze policy operators | Timelocked global blocklist root | Application KYC membership |
| Institutional auditor | Decrypting audit envelopes they are authorized to open | Learning recipient HPKE payloads |
| Pool contract | Custody, nullifiers, root history, proof verification | Reconstructing private note fields |
| Relayer / RPC / DEX | Availability | Authorization, value conservation, policy freshness |

## Explicit non-goals of this freeze

- No production circuit, verifier, or HazePool bytecode.
- No provider types in public APIs.
- Sorted blocklist membership, not an SMT, for the Haze global list.
- Depth-32 Merkle trees with domain-separated empty roots.

## Residual risks

Poseidon sponge padding, EIP-712 field ordering, and envelope hashing must be reviewed independently. A mismatch between Rust, Circom, Solidity, and TypeScript remains a release blocker.
