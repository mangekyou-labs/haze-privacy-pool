---
phase: design
title: Haze Avalanche Protocol V1 Encoding Design
description: Review candidate for canonical Haze v1 hashes, encodings, envelopes, and trust boundaries
---

# Define Haze Avalanche protocol v1 encodings

This reference defines one canonical representation for every Haze v1 value that crosses a circuit,
contract, service, SDK, or encrypted-envelope boundary. Use it to build shared vectors before writing
production circuits or contracts.

## Status and review gate

This document is the frozen Haze Avalanche protocol v1 encoding specification. It refines the
approved umbrella design into exact protocol rules. It does not authorize production proving keys,
circuits, contracts, or mainnet use. Independent cryptography and EVM review `91cfa5ee` accepted
the encodings with follow-ups; those follow-ups are implemented. Product approved
[`2026-08-17-t0.2-product-approval-packet.md`](./2026-08-17-t0.2-product-approval-packet.md)
in-thread on 2026-08-17. T0.2 is complete. T1.1 may start.

Normative terms such as MUST, MUST NOT, and SHOULD are used as requirements. A v1 parser MUST reject
unknown versions, unknown algorithm suites, non-canonical encodings, out-of-range fields, omitted
required values, and unknown fields. It MUST NOT reinterpret a rejected v1 value as a legacy format.

## Decision summary

- Haze v1 uses a hybrid hash boundary: Poseidon2 for circuit-native relationships and Keccak-256 for
  Ethereum Virtual Machine (EVM) hashes, EIP-712, envelopes, manifests, routes, and calldata.
- Haze v1 reuses the existing reviewed Poseidon2 permutation and width-3 sponge construction after a
  differential review. It reuses no existing transaction preimage or network domain.
- Arbitrary 32-byte identifiers are split into two 128-bit limbs in circuits. They are never reduced
  modulo the BN254 scalar field.
- Transaction direction is encoded by an action plus an unsigned public amount. The signed
  `public_value` proposed in the umbrella design is replaced to remove signed-field ambiguity.
- Recipient and institutional audit records use separate Hybrid Public Key Encryption (HPKE) keys,
  labels, payload schemas, and key lifecycles, even though both use the same standardized suite.
- Circuit-bound transaction facts are separated from application identity assertions. A circuit can
  prove the former; the gatekeeper signs but cannot make the latter cryptographically intrinsic to a
  note transfer.

## Primitive registry

### BN254 scalar field

The circuit field is the BN254 scalar field with modulus:

```text
21888242871839275222246405745257275088548364400416034343698204186575808495617
```

A field element is serialized as exactly 32 unsigned big-endian bytes. Decoders MUST reject a value
greater than or equal to the modulus. Zero is valid except where a type explicitly forbids it.

### Keccak-256 hashes

`K(bytes)` means the Ethereum Keccak-256 function, not standardized SHA3-256. Keccak outputs are
exactly 32 bytes. A Keccak value entering a circuit is represented as two fields:

```text
bytes32_limbs(value) = [uint128(value[0..16]), uint128(value[16..32])]
```

Both limbs use unsigned big-endian interpretation. Recombination MUST reproduce the original bytes.

### Poseidon2 sponge

`P(domain, fields…)` means the existing BN254 Poseidon2 permutation with this frozen sponge:

- width 3, rate 2, capacity 1;
- S-box exponent 5, 8 full rounds, and 56 partial rounds;
- lane order `[rate_0, rate_1, capacity]`;
- initial state `[0, 0, domain]`;
- add each two-field message block to the rate lanes, then permute;
- field-element `pad10*`, including a full `[1, 0]` block when the input count is even; and
- lane 0 as the digest.

Every preimage in v1 has a fixed field count and a distinct domain. Implementations MUST reject a
vector set whose parameter-file hashes differ from the reviewed v1 artifact manifest.

### Domain derivation

A Poseidon domain label is ASCII text matching `haze/avalanche/v1/<purpose>`. Its field constant is:

```text
domain_field = uint256(K(ascii_label)) mod BN254_R
```

Reduction is allowed only for these fixed reviewed domain constants and secret-key derivation where
specified. Arbitrary external identifiers MUST use lossless limbs. The vector set freezes every label,
Keccak digest, and resulting decimal field constant. Duplicate field constants are invalid.

The initial v1 labels are:

```text
haze/avalanche/v1/protocol
haze/avalanche/v1/pool
haze/avalanche/v1/note-key
haze/avalanche/v1/encryption-key
haze/avalanche/v1/note
haze/avalanche/v1/nullifier
haze/avalanche/v1/note-tree-node
haze/avalanche/v1/app-tree-node
haze/avalanche/v1/block-tree-node
haze/avalanche/v1/app-member
haze/avalanche/v1/block-note
haze/avalanche/v1/block-evm-address
haze/avalanche/v1/audit-data
```

The protocol tag and pool domain are:

```text
protocol_version_tag = domain_field("haze/avalanche/v1/protocol")

pool_domain =
  P(POOL,
    protocol_version_tag,
    chain_id,
    pool_address,
    pool_version_hi, pool_version_lo)
```

Every note and nullifier includes `pool_domain`. This prevents a valid proof or note preimage from
being reused across chain IDs, pool contracts, or immutable versions that happen to share other data.

## Canonical scalar and identifier encodings

- `u8`, `u32`, `u48`, `u64`, `u128`, and `uint160` are unsigned integers and use their exact range.
- Binary wire encodings use unsigned big-endian integers unless an external standard fixes another
  representation.
- An EVM address becomes one field equal to its unsigned `uint160` value.
- `bytes32`, application IDs, pool versions, nonces, and Keccak hashes use two 128-bit limbs in a
  circuit.
- USDC private values and public USDC amounts are `u64` base units. Amounts never use decimal text or
  floating point in a signed, hashed, encrypted, or circuit value.
- Source-token `amount_in` is `uint256` because a public router may support tokens with a wider amount
  range. It never enters private note accounting.
- Action codes are fixed: `1 DEPOSIT`, `2 TRANSFER`, `3 WITHDRAW`, `4 SWAP_AND_SHIELD`, and
  `5 EMERGENCY_EXIT`. Zero and all other values are invalid.

## Shielded keys and notes

### Derive shielded keys

An externally owned account (EOA) locally signs this EIP-712 message:

```text
Domain {
  name: "Haze Shielded Account",
  version: "1",
  chainId,
  verifyingContract: pool
}

HazeKeyDerivation(
  address wallet,
  bytes32 applicationId,
  bytes32 poolVersion
)
```

The client verifies that the recovered signer equals `wallet`, normalizes the 65-byte signature to a
low-s form with `v` encoded as 0 or 1, and uses the normalized bytes as HKDF-SHA256 input keying
material. Separate labels derive spending-secret candidates, X25519 key material, local-vault keys,
and application-membership blinding. Spending-secret candidates use counter-based rejection sampling
until `0 < candidate < BN254_R`; modulo reduction is not used. Secret buffers are zeroized after use.

Contract-wallet recovery is not silently approximated. A wallet that cannot produce a deterministic,
recoverable signature receives a typed unsupported-recovery error until a separately reviewed adapter
is available.

### Derive circuit identities

```text
note_public_key =
  P(NOTE_KEY, spending_secret)

encryption_key_hash =
  P(ENCRYPTION_KEY, x25519_public_key_hi, x25519_public_key_lo)
```

The X25519 public key limb order follows `bytes32_limbs` exactly.

### Note commitment

```text
note_commitment =
  P(NOTE,
    pool_domain,
    application_id_hi, application_id_lo,
    value,
    note_public_key,
    encryption_key_hash,
    blinding)
```

`value` is `u64`. `blinding` is a uniformly sampled nonzero field element. A note commitment equal to
zero is invalid even though the probability is negligible.

### Nullifier

```text
nullifier =
  P(NULLIFIER,
    pool_domain,
    application_id_hi, application_id_lo,
    note_commitment,
    leaf_index,
    spending_secret)
```

`leaf_index` is range-constrained to the configured note-tree depth. A nullifier equal to zero is
invalid. The pool records nullifiers globally within one immutable pool version.

## Prove note and policy membership

Haze v1 uses fixed-depth binary trees with depth 32. Each tree has a distinct node domain. Empty
leaves are zero, and each level's zero value is derived by hashing the previous level's zero values.
Every pair is hashed, including pairs of zero values. Trees do not use LeanIMT child propagation.

The note tree and application membership tree nodes are:

```text
note_parent = P(NOTE_TREE_NODE, level, left, right)
application_parent = P(APP_TREE_NODE, level, left, right)
```

The path uses the 32 low-order bits of the unsigned leaf index, least-significant bit at level zero.
Including the zero-based level prevents pair reuse across levels. Vectors freeze all zero hashes, leaf
conventions, path order, and empty roots.

Application membership subjects are:

```text
application_member =
  P(APP_MEMBER,
    application_id_hi, application_id_lo,
    note_public_key,
    encryption_key_hash)
```

Haze global blocklist subjects use distinct domains instead of a polymorphic subject-kind field:

```text
global_blocked_note =
  P(BLOCK_NOTE,
    chain_id,
    application_id_hi, application_id_lo,
    note_public_key,
    encryption_key_hash)

global_blocked_address =
  P(BLOCK_EVM_ADDRESS, chain_id, uint160_address)
```

The global blocklist uses a fixed-depth, sorted Merkle tree rather than the legacy full-field sparse
tree. Its leaves contain unique subject fields in ascending order. Index zero contains the lower
sentinel `0`; the final populated index contains the upper sentinel `BN254_R - 1`. A root record binds
the root, populated leaf count, policy version, activation time, and hash of the complete sorted
artifact.

A non-membership witness supplies inclusion paths for adjacent lower and upper leaves. The circuit
checks both roots, `upper_index = lower_index + 1`, and `lower_subject < queried_subject <
upper_subject`. A queried subject equal to either sentinel is invalid. Clients and independent policy
mirrors reconstruct the artifact, verify strict ordering and uniqueness, recompute the root, and reject
a root whose artifact does not match. This design uses 64 depth-32 node hashes per queried subject
instead of a depth-254 sparse path and remains subject to the published browser-proving benchmark.

Every nonzero input and output in a normal transaction proves membership in the active application
tree and non-membership in the active Haze sparse tree. A slot enable bit is constrained to
`value != 0`; a disabled slot requires every note, path, policy-subject, and output field for that slot
to equal zero. Enabled inputs and outputs bind to the transaction's public application ID and pool
version. Cross-application private value movement is invalid in v1.

Deposits and withdrawals additionally screen their public payer or recipient against
`global_blocked_address`. Emergency exit checks the spent note subject and public recipient against
the currently active Haze root but deliberately omits application membership.

## Bind normal transaction public inputs

The normal 2-input/2-output circuit exposes fields in this exact order:

```text
1   protocol_version_tag
2   chain_id
3   pool_address
4   pool_version_hi
5   pool_version_lo
6   application_id_hi
7   application_id_lo
8   note_tree_root
9   application_policy_version
10  haze_policy_version
11  application_membership_root
12  haze_blocklist_root
13  input_nullifier_0
14  input_nullifier_1
15  output_commitment_0
16  output_commitment_1
17  action
18  public_amount
19  public_recipient
20  authorized_user
21  intent_hash_hi
22  intent_hash_lo
23  recipient_ciphertext_hash_0_hi
24  recipient_ciphertext_hash_0_lo
25  recipient_ciphertext_hash_1_hi
26  recipient_ciphertext_hash_1_lo
27  audit_data_commitment
28  audit_ciphertext_hash_hi
29  audit_ciphertext_hash_lo
```

The contract checks all public inputs against calldata and current registry state before accepting a
proof. Keccak is not implemented inside the circuit; lossless limbs bind externally computed hashes.

Action-specific balance rules are:

- `DEPOSIT` and `SWAP_AND_SHIELD`: inputs are disabled, `public_amount > 0`, public recipient is zero,
  and enabled output values sum exactly to `public_amount`.
- `TRANSFER`: `public_amount == 0`, public recipient is zero, and enabled input/output sums match.
- `WITHDRAW`: `public_amount > 0`, public recipient is nonzero, and input sum equals output sum plus
  `public_amount`.
- `EMERGENCY_EXIT` uses a separate circuit and contract entry point.

## Bind audit facts to the circuit

`audit_data_commitment` commits to a fixed preimage using `P(AUDIT_DATA, …)`. Its ordered fields are:

```text
chain_id
pool_address
pool_version_hi, pool_version_lo
application_id_hi, application_id_lo
action
authorized_user
usdc_address
public_amount
public_recipient
application_policy_version
haze_policy_version
action_reference_hi, action_reference_lo
input_enabled[2]
input_values[2]
input_note_public_keys[2]
input_encryption_key_hashes[2]
input_nullifiers[2]
output_enabled[2]
output_values[2]
output_note_public_keys[2]
output_encryption_key_hashes[2]
output_commitments[2]
recipient_ciphertext_hash_limbs[2][2]
audit_salt
```

For a normal action, `action_reference` is the authorization nonce. For an emergency exit, it is the
request ID. The gatekeeper samples a nonzero `audit_salt`, constructs the normal-action facts,
encrypts the deterministic record, and signs the resulting commitment and envelope hash. The client
independently recomputes the commitment before proving. The circuit recomputes it from the actual
witness and public values.

An encrypted audit record contains two explicitly separated sections:

- `transaction_facts`: the exact circuit-bound values above plus display-safe byte encodings; and
- `application_assertions`: application KYC subject references, case tags, or internal classifications
  asserted by the gatekeeper but not claimed as circuit-proven facts.

Disclosure MUST label these sections and MUST NOT represent an application assertion as proven by the
circuit. The chain transaction hash, block number, and log index are attached by the finalized indexer
because they do not exist when authorization is signed.

The plaintext uses RFC 8949 deterministic Concise Binary Object Representation (CBOR) with integer
map keys, preferred integer encodings, definite lengths, no floating point, and no unknown v1 keys.
Disclosure re-encodes the plaintext, recomputes `audit_data_commitment`, and verifies the event's
envelope hash before releasing fields.

## Bind EIP-712 intent and authorization

The authorization domain is:

```text
EIP712Domain(
  string name,
  string version,
  uint256 chainId,
  address verifyingContract
)

name = "Haze Avalanche Compliant Pool"
version = "1"
chainId = block.chainid
verifyingContract = immutable pool address
```

Contracts expose the same domain through ERC-5267. The action intent is hashed as an EIP-712 struct
hash, not with `abi.encodePacked`:

```text
HazeIntent(
  bytes32 applicationId,
  address user,
  address pool,
  bytes32 poolVersion,
  uint8 action,
  uint256 noteTreeRoot,
  uint64 applicationPolicyVersion,
  uint64 hazePolicyVersion,
  uint256 applicationMembershipRoot,
  uint256 hazeBlocklistRoot,
  uint256 inputNullifier0,
  uint256 inputNullifier1,
  uint256 outputCommitment0,
  uint256 outputCommitment1,
  uint64 publicAmount,
  address publicRecipient,
  bytes32 recipientCiphertextHash0,
  bytes32 recipientCiphertextHash1,
  uint256 auditDataCommitment,
  bytes32 auditCiphertextHash,
  address tokenIn,
  uint256 amountIn,
  uint64 minUsdcOut,
  bytes32 routeHash,
  uint48 deadline
)
```

Non-swap actions require all swap-only fields to be zero. A deposit requires `noteTreeRoot` and input
nullifiers to be zero. The pool recomputes the intent struct hash from submitted calldata.

The gatekeeper signs:

```text
ApplicationAuthorization(
  bytes32 applicationId,
  address user,
  address pool,
  bytes32 poolVersion,
  uint8 action,
  bytes32 intentHash,
  uint64 applicationPolicyVersion,
  uint64 hazePolicyVersion,
  uint256 auditDataCommitment,
  bytes32 auditCiphertextHash,
  bytes32 nonce,
  uint48 validAfter,
  uint48 validUntil
)
```

The pool requires duplicate intent/authorization fields to match, verifies the active application
signer, enforces `validAfter <= block.timestamp <= validUntil`, and consumes the nonce exactly once.
The nonce scope is `(application_id, gatekeeper_signer, nonce)`. Signer rotation does not make an old
signer's unused authorization valid after activation of the replacement signer.

## Bind emergency exits without a gatekeeper

An emergency exit always withdraws one complete note to a public EVM address. It creates no private
change output. The user registers an opaque request ID before the seven-day cooldown:

```text
request_id = K(abi.encode(
  keccak256("HazeEmergencyExitRequest(uint256 chainId,address pool,bytes32 poolVersion,bytes32 applicationId,uint256 nullifier,address recipient,bytes32 requestSalt)"),
  chain_id,
  pool_address,
  pool_version,
  application_id,
  nullifier,
  recipient,
  request_salt
))
```

The request transaction reveals only `request_id`. Execution reveals the nullifier, recipient, and
request salt, then recomputes the ID and checks its timestamp. A request does not reserve or consume a
nullifier. Successful execution consumes the nullifier and request atomically; failed execution leaves
both unchanged.

The emergency-exit circuit exposes fields in this exact order:

```text
1   protocol_version_tag
2   chain_id
3   pool_address
4   pool_version_hi
5   pool_version_lo
6   application_id_hi
7   application_id_lo
8   note_tree_root
9   haze_policy_version
10  haze_blocklist_root
11  input_nullifier
12  action
13  public_amount
14  public_recipient
15  requester
16  request_id_hi
17  request_id_lo
18  audit_data_commitment
19  audit_ciphertext_hash_hi
20  audit_ciphertext_hash_lo
```

The circuit requires action `EMERGENCY_EXIT`, proves ownership and note-tree inclusion, sets
`public_amount` equal to the complete note value, and proves Haze global non-membership for the note
subject and public recipient. It does not accept application membership or a gatekeeper signature.
The audit preimage uses `application_policy_version = 0`, the request ID as `action_reference`,
disabled second input, disabled outputs, and zero recipient-ciphertext hashes. The record retains an
all-zero authorization nonce because no authorization exists. The requester constructs the
deterministic audit record and encrypts it to the application's active audit public key. The circuit
and contract bind the disclosed amount, recipient, request ID, audit commitment, and envelope hash.

## Encode an app-scoped Haze address

The binary app-scoped address payload is:

```text
magic "HZAV"                 4 bytes
codec_version                u8 = 1
chain_id                     u64be
application_id               32 bytes
pool_version                 32 bytes
note_public_key              canonical field32
x25519_public_key            32 bytes
checksum                     first4(K("haze/avalanche/v1/address" || prior bytes))
```

The textual form is `haze1:` followed by unpadded base64url of the entire binary payload. Decoders
reject non-canonical base64url, wrong magic, chain, application, pool version, field range, low-order
X25519 keys, checksum, trailing bytes, and alternate textual encodings.

## Encrypt recipient and audit records

Haze v1 uses RFC 9180 HPKE Base mode with this suite for both channels:

```text
KEM  0x0020  DHKEM(X25519, HKDF-SHA256)
KDF  0x0001  HKDF-SHA256
AEAD 0x0003  ChaCha20Poly1305
```

This replaces the umbrella design's custom 24-byte nonce envelope. HPKE derives its nonce and emits a
32-byte encapsulated key plus authenticated ciphertext. Implementations use reviewed HPKE libraries
and MUST NOT recreate the construction from raw ECDH primitives.

Recipient info is `haze/avalanche/v1/recipient-note`; recipient AAD is the fixed binary encoding of
chain ID, pool address/version, application ID, output index, output commitment, and envelope version.
The deterministic recipient plaintext contains value, blinding, note public key, encryption-key hash,
application ID, pool version, and commitment. A recipient accepts a record only after decryption and
commitment recomputation.

Audit info is `haze/avalanche/v1/audit-record`; audit AAD contains chain ID, pool address/version,
application ID, audit-key version, audit-data commitment, action, and action reference. The audit
plaintext is the deterministic CBOR record. Recipient and audit keys MUST be distinct and MUST NOT be
derived from each other.

Each binary envelope contains a magic value, envelope version, purpose, the three HPKE suite IDs,
application/audit key version where applicable, encapsulated-key length and bytes, ciphertext length
and bytes. Lengths are bounded and minimally encoded. `audit_ciphertext_hash` and recipient ciphertext
hashes are Keccak-256 over the complete binary envelope, not only the AEAD ciphertext.

The application's versioned audit public key is authenticated by registry and signed-manifest state.
T0.3 may select how an application-controlled Key Management Service (KMS) or hardware security
module (HSM) authorizes access to the corresponding HPKE private key, but it may not change the public
envelope or suite. A provider that cannot enforce the required key policy is incompatible with v1.

## Enforce trust boundaries

- The circuit proves note ownership, balance, application binding, policy witnesses, and committed
  transaction facts. It does not prove a real-world identity or the truth of private KYC assertions.
- The application gatekeeper may censor normal actions or make false application assertions. It
  cannot spend a note, change circuit-proven facts, or bypass the delayed emergency exit.
- Haze governance controls global policy and application/version activation through documented roles
  and delays. It has no note-spending key. Global-policy abuse remains a governance/liveness risk and
  is visible through scheduled root events.
- The application controls audit-key access. A key outage denies disclosure but cannot spend or lock
  notes. A key compromise exposes that application's retained audit records.
- The indexer is untrusted for ownership and ciphertext integrity. Clients and disclosure services
  verify commitments, hashes, roots, block provenance, and finality independently.
- Wallet signatures, proof witnesses, spending secrets, vault keys, audit salts, HPKE private keys,
  and decrypted records are secrets and are never logged.
- Public metadata includes wallet submitters, application affiliation, source-token swaps, deposits,
  withdrawals, gas, ciphertext sizes, timing, and public version migration. Product copy cannot call
  these values private.

## Reject invalid inputs

Stable error families are `ENCODING_INVALID`, `FIELD_OUT_OF_RANGE`, `VERSION_UNSUPPORTED`,
`DOMAIN_MISMATCH`, `CHAIN_MISMATCH`, `APPLICATION_MISMATCH`, `POOL_VERSION_MISMATCH`,
`POLICY_STALE`, `POLICY_WITNESS_INVALID`, `AUTHORIZATION_INVALID`, `AUTHORIZATION_EXPIRED`,
`NONCE_REPLAYED`, `CIPHERTEXT_INVALID`, `COMMITMENT_MISMATCH`, `PROOF_INVALID`, and
`RECOVERY_UNSUPPORTED`.

Errors may include bounded public context such as expected/actual version or a transaction hash. They
MUST NOT include witnesses, note values from failed decryption, salts, plaintext records, keys,
signatures used for derivation, KYC payloads, or provider secrets.

## Build one canonical vector set

The v1 vector artifact is strict JSON with a schema version, primitive metadata, parameter-file
hashes, domain labels/constants, encodings, positive vectors, and one-reason negative vectors. It
includes at minimum:

- field boundary values and rejected non-canonical encodings;
- bytes32 limb split/recombine and EVM address conversion;
- every Poseidon domain constant and padded block sequence;
- note key, encryption-key hash, commitment, nullifier, and Merkle nodes;
- application membership and both global blocklist subject types;
- enabled and disabled slot constraints;
- audit-data commitment and deterministic-CBOR record bytes;
- Haze address binary/text/checksum vectors;
- recipient and audit HPKE vectors with deterministic test randomness only;
- recipient/audit envelope hash vectors;
- EIP-712 domain, intent type hash, authorization type hash, struct hashes, and final digest;
- valid action shapes and rejected nonzero irrelevant fields; and
- version, chain, application, pool, policy, key-version, and artifact mismatches.

Rust is the initial strict vector loader. TypeScript, Solidity, and Circom harnesses must consume the
same committed artifact and reproduce their relevant values. No runtime may maintain a separate
hand-transcribed vector source.

## Reuse compatible primitives only

- **Reuse after review:** the generic BN254 Poseidon2 permutation parameters, width-3 sponge mechanics,
  Merkle test harness ideas, X25519 key lifecycle patterns, encrypted-vault redaction patterns,
  recovery state-machine tests, strict schema validation, and positive/negative fixture organization.
- **Rewrite around this spec:** all domains, preimages, byte order, wallet derivation, note/address
  codecs, policy rules, audit schemas, public-input order, and envelope cryptography.
- **Reject:** existing transaction circuits, input-only policy composition, custom raw-ECDH envelope
  KDFs, network-specific contracts/adapters/wallet flows, relayer payout/ragequit semantics, and any
  production use of legacy proving or verification keys.

## Require T0.2 exit evidence

T0.2 is complete. Exit evidence:

1. Explicit product, cryptography, and EVM approval
   (crypto/EVM: `91cfa5ee`; product: in-thread approve of
   `2026-08-17-t0.2-product-approval-packet.md` on 2026-08-17).
2. Strict vector artifact and one-reason negatives exist
   (`haze/circuits/vectors/v1/haze-protocol-v1.json`: 35 positives, 17 negatives, 2 parameter-file
   hashes).
3. Rust, TypeScript, Solidity, and Circom harnesses consume the same artifact; Circom does not
   independently reproduce the Poseidon2 permutation (deferred to T1.1, accepted in ADR-0001).
4. Domain tags and parameter-file hashes are independently reproduced by TypeScript, Solidity, and
   Circom harnesses.
5. Threat model (ADR-0003) has no unresolved critical ambiguity; residual risks are recorded in the
   product-approval packet.
6. Incompatible legacy reuse is recorded in this document and ADR-0001.
7. Implementation and testing documents contain 2026-08-17 command evidence.

Passing local tests alone would not have satisfied the independent-review requirement. That review
and product approval are now both recorded.

## Normative references

- [EIP-712 typed structured data](https://eips.ethereum.org/EIPS/eip-712)
- [ERC-5267 EIP-712 domain retrieval](https://eips.ethereum.org/EIPS/eip-5267)
- [Solidity ABI specification](https://docs.soliditylang.org/en/latest/abi-spec.html)
- [Avalanche Primary Network identifiers](https://build.avax.network/docs/primary-network)
- [RFC 9180 Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180.html)
- [RFC 8949 deterministic CBOR](https://www.rfc-editor.org/rfc/rfc8949.html)
