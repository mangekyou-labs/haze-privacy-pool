# ADR-0004: Provider-neutral interfaces and candidate evaluation

## Status

Accepted for T0.3. No vendor SDK is a public Haze type. Mocks are the only accepted implementations
until a later adapter lands behind these interfaces.

## Context

Requirements defer the exact DEX aggregator, C-Chain RPC, KMS, OIDC/SAML, object storage, and
hosting vendors. Services and the SDK must still compile and test swap quotes, disclosure unwrap,
identity intake, and storage against fail-closed mocks.

## Decision

Public interfaces live in `haze_protocol::providers` and `@haze-avalanche/sdk` as capability types:
`DexQuoteSource`, `ChainRpc`, `KeyManagement`, `IdentityProvider`, and `ObjectStore`. Errors are
`Unavailable`, `Rejected`, `QuoteStale`, and `ChainMismatch`. Adapters may exist later as private
modules; they must not appear in `lib.rs` / package exports.

### Evaluation (MVP recommendation, not a public type)

| Capability | Candidate | Security | Availability | Pricing | Data residency | Fallback | Exit |
| --- | --- | --- | --- | --- | --- | --- | --- |
| DEX quote / adapter | Generic allowlisted AMM adapter (LFJ/Uniswap-v2 style on C-Chain); mock in CI | Route and amount are public; adapter allowlist in the router | Quote cache short TTL; outage fails the swap-and-shield path | Per-swap LP fee only | N/A (on-chain) | Direct USDC shield remains | Swap another allowlisted pool |
| C-Chain RPC | Avalanche official public RPC + one paid replica | TLS; no private keys on the node | Dual endpoint; fail closed on chain-id mismatch | Public free + paid replica | Operator region | Second replica | Change URL only |
| KMS | Application-owned cloud KMS via envelope encryption | Haze never holds long-lived DEKs; unwrap is per case | Outage denies disclosure | Per-key / per-op | Application chooses region | No plaintext cache | Re-wrap under a new key ref |
| Identity | Generic OIDC (SAML optional) + SIWE bind | Short-lived tokens; no Haze IdP | Outage denies portal/disclosure login | IdP license | Customer tenant | Break-glass is out of MVP | Change issuer metadata |
| Object storage | S3-compatible bucket behind `ObjectStore` | SSE; application-partitioned keys | Outage denies new ciphertext persist | Storage + egress | Application region | Local disk only in CI | Copy + retarget |
| Hosting | Separate static DEX and portal hosts | No shared origin cookies | Independent deploys | Standard static hosting | Optional | Second host | DNS cut |

## Consequences

T4/T5 services implement against traits and inject mocks in tests. Accepting a vendor requires a
new adapter crate/module plus this ADR addendum. Architecture tests reject named vendor SDKs in
public sources.
