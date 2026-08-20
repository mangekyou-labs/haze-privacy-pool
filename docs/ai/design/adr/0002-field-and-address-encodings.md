# ADR-0002: Field, limb, address, and action encodings

## Status

Accepted for protocol v1. Independent cryptography and EVM review `91cfa5ee` accepted these
encodings. Product approved T0.2 on 2026-08-17.

## Context

EVM identifiers are 160- or 256-bit. BN254 scalars live in \(r < 2^{254}\). Reducing identifiers modulo \(r\) would collide and diverge from Solidity `bytes32` equality.

## Decision

- Encode field elements as 32-byte big-endian integers strictly less than \(r\).
- Split every opaque `bytes32` into two unsigned 128-bit limbs. Recombine without modular reduction.
- Encode EVM addresses as `uint160` left-padded to 32 bytes.
- Bind pool domain to `(chainId, pool, poolVersion)` so Fuji (43113) and C-Chain (43114) cannot reuse notes.
- Represent app-scoped addresses as `haze1:` plus unpadded base64url of a 145-byte `HZAV` payload (checksum over `haze/avalanche/v1/address || payload`). Decoders reject RFC 7748 low-order X25519 keys.
- Freeze actions `1..=5` (deposit, transfer, withdraw, swap-and-shield, emergency-exit). Unknown codes are invalid.
- Frame HPKE envelopes as `HZHP` with X25519 / HKDF-SHA256 / ChaCha20-Poly1305 identifiers. Hash the complete envelope.

## Consequences

Vectors reject modulus equality, short hex, padded addresses, unknown actions, and chain mismatches. T1.x circuits must consume the same limb split.
