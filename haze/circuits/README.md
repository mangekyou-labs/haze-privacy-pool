# Haze circuits

Canonical protocol vectors live in `vectors/v1/haze-protocol-v1.json`. Load them with:

```sh
node haze/circuits/vectors/check.mjs
```

T1.1 gadgets independently reproduce the approved Poseidon2 permutation and v1 sponge:

- `src/poseidon2/` — reviewed BN254 permutation constants plus the width-3 `pad10*` sponge
- `src/gadgets/` — note key/commitment/nullifier, Merkle parent/path, and application-member leaves
- `test/` — compile-and-witness mains compared to committed vectors
- `REJECTION.md` — Stellar artifacts that must not be imported, including legacy `Poseidon2(n)`

Compile with Circom **2.2.3** from `haze/.tools/bin/circom` (PATH may still have Circom 0.5). Install:

```sh
cargo install circom --git https://github.com/iden3/circom --tag v2.2.3 --locked --root haze/.tools
```

Production 2-in/2-out spend circuits are T1.2 and are not present here.
