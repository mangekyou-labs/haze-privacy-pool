# Rejected Stellar privacy artifacts

Haze reuses only the reviewed BN254 Poseidon2 **permutation** (S-box, MDS / external and internal
rounds, and Horizen SAGE constants for `t = 2/3/4`). It does **not** import Stellar transaction,
policy, Merkle, keypair, or SMT circuits, and it does **not** use the legacy `Poseidon2(n)` wrapper.

Legacy `Poseidon2(n)` is a **single permutation** of `[inputs..., domain]` with width `n + 1`. Haze
v1 is a width-3 rate-2 capacity-1 sponge: state `[0, 0, domain]`, `pad10*` (even input length adds
`[1, 0]`; odd length ends with `[field, 1]`), then reject a zero digest. Those encodings are not
compatible.

## Rejected circuit artifacts

| Artifact | Reason |
|---|---|
| `transaction.circom` | Stellar 2-in/2-out spend; wrong public inputs, policy, and address encodings |
| `policy_tx_` / `policyTransaction` | Input-only policy; Haze requires membership and global non-membership on every enabled slot |
| `smtverifier` / `smthash_poseidon2` | Sparse-Merkle / SMT membership, not the Haze depth-32 binary trees |
| `aspMembership` / `aspNonMembership` | Stellar ASP leaf encodings |
| `globalViewKey` / `selectiveDisclosure` | Stellar view-key and disclosure gadgets |
| `keypair.circom` | Stellar note/address key derivation |
| `merkleProof.circom` / `merkleTree.circom` / `merkleTreeUpdater.circom` | Stellar Merkle wiring and domains |
| `Poseidon2(n)` single permutation | Not the v1 sponge; would silently disagree with approved vectors |

Existing Stellar proving/verifying keys, custom raw-ECDH KDFs, network adapters, and relayer
payout/ragequit flows are also out of scope.
