---
phase: design
title: "D9-SO-01 Emergency Ceremony Design Return"
description: >
  Decision-complete production-ceremony design for haze-emergency-v1.
  Documentation-only phase: no keys, no ceremony execution, no transaction
  broadcast, no contract deployment, no SC-09 approval.
---

# D9-SO-01 Emergency Ceremony Design Return

date: 2026-08-24
status: design-resolved — artifact/tooling implementation pending
feature: haze-avalanche-compliant-pool
parent-design: 2026-08-18-haze-production-ceremony-design.md
does-not-replace: emergency-operator-owned-ceremony-transcript.json

## Summary

This document is the decision-complete production-ceremony design for the
`haze-emergency-v1` circuit. It covers the emergency-exit circuit only; the
spend ceremony design remains unchanged in
`docs/ai/design/2026-08-18-haze-production-ceremony-design.md`.

This phase changes documentation only. It will not generate keys, execute a
ceremony, broadcast transactions, deploy contracts, or approve SC-09. The
existing single-machine transcript and all Fuji contracts remain explicitly
non-production.

## 1. Scope

### 1.1 In scope

- Emergency-exit Groth16 phase-2 ceremony for `haze-emergency-v1`.
- Audit freeze of Circom 2.2.3, constraint count, source/R1CS/build hashes,
  and public inputs for the emergency circuit.
- Pinned Hermez power-20 ptau with SHA-256 checksum.
- Three sequential contributors on separate machines.
- Beacon protocol with Avalanche C-Chain mainnet anchoring.
- Public output definitions and EIP-712 receipt structures.
- Future production backend, wrapper, and contract handoff.
- Validation cases for all failure modes.

### 1.2 Out of scope

- Spend ceremony design (unchanged in parent design).
- Key generation, ceremony execution, or any cryptographic material.
- Transaction broadcast or contract deployment.
- SC-09 approval or Fuji deployment changes.
- Any change to existing Fuji addresses or deployment scripts.
- Runtime API changes.

## 2. Audit Freeze

### 2.1 Emergency circuit pinning

The emergency-exit circuit must be independently audited and frozen before
ceremony tooling implementation. Until independently audited, the values
below are candidates.

```text
circuit_id:      haze-emergency-v1
circom_version:  2.2.3
n_constraints:   192,535
public_inputs:   20
```

The 20 public inputs are:

| Index | Name                    |
|------:|-------------------------|
|     0 | protocolVersionTag      |
|     1 | chainId                 |
|     2 | poolAddress             |
|     3 | poolVersionHi           |
|     4 | poolVersionLo           |
|     5 | applicationIdHi         |
|     6 | applicationIdLo         |
|     7 | noteTreeRoot            |
|     8 | hazePolicyVersion       |
|     9 | hazeBlocklistRoot       |
|    10 | inputNullifier          |
|    11 | action                  |
|    12 | publicAmount            |
|    13 | publicRecipient         |
|    14 | requester               |
|    15 | requestIdHi             |
|    16 | requestIdLo             |
|    17 | auditDataCommitment     |
|    18 | auditCiphertextHashHi   |
|    19 | auditCiphertextHashLo   |

Candidate hashes (must be independently audited):

```text
source_hash:  <pending independent compilation and audit>
r1cs_hash:    <pending independent compilation and audit>
fixture_hash: <pending independent vector verification>
build_hash:   <pending independent build hash computation>
```

The existing hashes are candidates until independently verified. Any circuit
change after audit freeze invalidates the audit and ceremony design inputs.

### 2.2 Constraint differential

The emergency circuit (192,535 constraints) is smaller than the spend circuit
(588,459 constraints) because it:

- Operates on a single input note (no second input/output pair).
- Omits application membership proof (emergency exit ignores app eligibility).
- Omits recipient ciphertext for the second output (single output).
- Omits intent hash and action reference (uses requestId instead).
- Omits USDC address binding (amount is public).

The same Hermez power-20 ptau suffices for both circuits.

## 3. Ptau Pinning

### 3.1 Hermez powers-of-tau

```text
file:     powersOfTau28_hez_final_20.ptau
power:    20  (2^20 = 1,048,576 > 192,535)
source:   Hermez
url:      https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_20.ptau
alternate: https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_20.ptau
sha256:   159d3f938d941e06767d99f30b9fe59a245400a4aae138cf8e411732d7a2f6cd
```

Any checksum mismatch aborts the ceremony. The same ptau file is used for
both the spend and emergency circuits; downloading it once suffices.

### 3.2 PSE perpetual ptau

A PSE perpetual ptau of the same power is an allowed alternate URL. The
sha256 checksum must match exactly.

## 4. Three-Party Contributor Protocol

### 4.1 Contributors

Three sequential contributors on separate machines:

| Order | Contributor | Role |
|-------|-------------|------|
| 1 | Haze | Ceremony initiator; runs phase-2 setup and first contribution |
| 2 | Independent auditor | Second contribution on a separate machine |
| 3 | Third independent organization | Third contribution on a separate machine |

Each contributor must:

- Run on a physically separate machine.
- Use a fresh CSPRNG entropy source.
- Never transmit raw entropy.
- Record only the zkey hash (SHA-256 of the output zkey) after contribution.

### 4.2 Contribution flow

1. Haze runs `snarkjs groth16 setup` to produce the initial zkey from the
   frozen `haze-emergency-v1` r1cs and the pinned ptau.
2. Contributor 1 (Haze) runs `snarkjs zkey contribute` with local CSPRNG
   entropy. Records output zkey hash.
3. Contributor 2 (auditor) receives only the previous zkey (or a hash chain
   link). Runs `snarkjs zkey contribute` with local CSPRNG entropy. Records
   output zkey hash.
4. Contributor 3 (third org) receives only the previous zkey (or a hash
   chain link). Runs `snarkjs zkey contribute` with local CSPRNG entropy.
   Records output zkey hash.

### 4.3 Linked input/output zkey hashes

Each contribution produces a linked hash chain:

```text
genesis = keccak256(domain_tag || circuit_id)
link_n  = keccak256(link_{n-1} || contributor_name || input_zkey_hash)
```

The transcript records:

```text
{
  contributor: "<name>",
  input_zkey_hash:  "0x<sha256 of input zkey>",
  output_zkey_hash: "0x<sha256 of output zkey>",
  entropy_commitment: "0x<hash of entropy, never the entropy itself>"
}
```

Raw entropy is never transmitted or logged. The entropy commitment is a
hash of the contributor's local entropy used in the snarkjs contribute
step.

## 5. Beacon Protocol

### 5.1 Precommit

After the third contribution completes:

1. Haze computes a precommit digest: `keccak256(pre_beacon_zkey_hash)`.
2. Haze's multisig broadcasts a zero-value Avalanche C-Chain mainnet
   transaction with the precommit digest as calldata.
3. The transaction is recorded as the beacon precommit anchor.

### 5.2 Target block

The target block height is:

```text
target_height = anchor_inclusion_height + 2,048
```

### 5.3 Block hash confirmation

After 64 additional blocks beyond the target height:

```text
confirmation_height = target_height + 64
```

Three independent RPC providers must agree on the target block hash. If
any RPC disagrees, the ceremony aborts and requires fresh setup and
contributions.

### 5.4 Beacon derivation

The 32-byte beacon is derived from:

```text
beacon = snarkjs_zkey_beacon(
  domain_tag    = "haze/emergency-v1/beacon",
  chain_id      = 43114,
  target_height = target_height,
  target_hash   = target_block_hash,
  pre_zkey_hash = pre_beacon_zkey_hash,
  precommit     = precommit_digest,
  iterations    = 10
)
```

The beacon is applied as:

```text
snarkjs zkey beacon <pre_beacon_zkey> <final_zkey> <beacon_hex> 10
```

### 5.5 Abort conditions

The ceremony aborts and requires fresh setup and contributions if:

- **Known target block:** The target block height or hash is known or
  predictable before the anchor transaction is mined.
- **Late anchor:** The anchor transaction is not included within 120
  seconds of broadcast (replacement or resubmission required).
- **Signature failure:** Any of the three organizational signatures on
  the final manifest fails verification.
- **Contribution-chain mismatch:** The linked hash chain of contributions
  does not match the published transcript.
- **Block-hash disagreement:** The three independent RPC providers do not
  agree on the target block hash.
- **ptau checksum mismatch:** The downloaded ptau does not match the
  pinned SHA-256.
- **Circuit hash change:** The emergency circuit source, R1CS, or build
  hash does not match the audited freeze.
- **Out-of-order signatures:** Signatures are not in the documented
  contribution order.
- **Broken zkey links:** Any intermediate zkey hash does not chain to the
  next.

## 6. Public Outputs

The ceremony produces the following public outputs:

### 6.1 Opening manifest

A JSON document published before contributions begin, containing:

```json
{
  "ceremony_id": "haze-emergency-v1-production",
  "circuit_id": "haze-emergency-v1",
  "n_constraints": 192535,
  "circom_version": "2.2.3",
  "ptau_sha256": "159d3f938d941e06767d99f30b9fe59a245400a4aae138cf8e411732d7a2f6cd",
  "ptau_power": 20,
  "source_hash": "<audited>",
  "r1cs_hash": "<audited>",
  "fixture_hash": "<audited>",
  "build_hash": "<audited>",
  "contributors": [
    {"order": 1, "organization": "Haze"},
    {"order": 2, "organization": "<independent auditor>"},
    {"order": 3, "organization": "<third organization>"}
  ],
  "beacon_chain_id": 43114,
  "beacon_offset": 2048,
  "beacon_confirmation": 64
}
```

### 6.2 Signed contribution receipts

Each contributor produces an EIP-712 signed receipt (see Section 8).

### 6.3 Beacon precommit and anchor transaction

```json
{
  "precommit_digest": "0x<keccak256 of pre_beacon_zkey_hash>",
  "anchor_tx_hash": "0x<avalanche mainnet tx>",
  "anchor_block_height": <inclusion height>,
  "target_block_height": <anchor + 2048>,
  "target_block_hash": "<from three independent RPCs>",
  "confirmation_height": <target + 64>,
  "beacon": "0x<32-byte beacon>"
}
```

### 6.4 Final transcript

Public transcript containing only contributor names, zkey hashes, and
beacon data. No entropy is included.

### 6.5 Verification key

The exported verification key JSON for the emergency circuit.

### 6.6 Generated Solidity verifier

The Solidity verifier generated from the final zkey by
`snarkjs zkey export solidityverifier`.

### 6.7 Independent verification receipt

A signed receipt from an independent verifier confirming:

- The final zkey verifies against the frozen r1cs and ptau.
- The verification key matches the final zkey.
- The Solidity verifier matches the verification key.
- The beacon was correctly applied.

### 6.8 Final artifact manifest

```json
{
  "ceremony_id": "haze-emergency-v1-production",
  "circuit_id": "haze-emergency-v1",
  "n_constraints": 192535,
  "ptau_sha256": "159d3f938d941e06767d99f30b9fe59a245400a4aae138cf8e411732d7a2f6cd",
  "source_hash": "<audited>",
  "r1cs_hash": "<audited>",
  "build_hash": "<audited>",
  "final_zkey_hash": "0x<sha256>",
  "verification_key_hash": "0x<sha256>",
  "solidity_verifier_hash": "0x<sha256>",
  "beacon": "0x<32-byte>",
  "anchor_tx_hash": "0x<hash>",
  "target_block_height": <height>,
  "target_block_hash": "0x<hash>",
  "transcript_hash": "0x<sha256 of final transcript>",
  "contribution_count": 3
}
```

### 6.9 Artifact storage

Intermediate and final zkeys remain outside git in restricted artifact
storage. Only hashes are committed. The artifact storage path is:

```text
haze/dev/artifacts/ceremony-private/emergency-v1/
```

Gitignored contents:

```text
powersOfTau28_hez_final_20.ptau
haze-emergency-0000.zkey
haze-emergency-0001.zkey
haze-emergency-0002.zkey
haze-emergency-final.zkey
haze-emergency-verification-key.json
HazeEmergencyGroth16Verifier.generated.sol
```

## 7. Rehearsal Transcript Preservation

The existing `emergency-operator-owned-ceremony-transcript.json` is
preserved as rehearsal evidence. It must not be:

- Promoted to production status.
- Relabeled as a production artifact.
- Used as a production zkey source.
- Referenced in any SC-09 production ceremony approval.

The transcript remains `not_for_production: true` and
`production_ceremony_approved: false`.

## 8. EIP-712 Structures

### 8.1 ContributionReceipt

Each contributor signs an EIP-712 receipt bound to the ceremony:

```text
ContributionReceipt(
    bytes32 ceremonyId,          // "haze-emergency-v1-production"
    bytes32 frozenManifestHash,  // keccak256 of the opening manifest
    uint256 contributionOrder,   // 1, 2, or 3
    bytes32 inputZkeyHash,       // SHA-256 of the input zkey
    bytes32 outputZkeyHash,      // SHA-256 of the output zkey
    bytes32 toolchainHash,       // hash of snarkjs version + platform
    address signer               // preregistered organizational wallet
)
```

EIP-712 domain:

```text
{
  name: "Haze Emergency Ceremony",
  version: "1",
  chainId: 43114,
  verifyingContract: "0x0000000000000000000000000000000000000000"
}
```

### 8.2 CeremonyManifestApproval

All three organizations sign the final manifest:

```text
CeremonyManifestApproval(
    bytes32 ceremonyId,
    bytes32 finalManifestHash,   // keccak256 of the final artifact manifest
    bytes32 beacon,              // the 32-byte beacon
    bytes32 finalZkeyHash,       // SHA-256 of the final zkey
    bytes32 verificationKeyHash, // SHA-256 of the verification key
    bytes32 solidityVerifierHash,// SHA-256 of the generated Solidity verifier
    address signer               // preregistered organizational wallet
)
```

### 8.3 VerificationReceipt

An independent verifier signs:

```text
VerificationReceipt(
    bytes32 ceremonyId,
    bytes32 finalZkeyHash,
    bytes32 verificationKeyHash,
    bytes32 solidityVerifierHash,
    bytes32 r1csHash,            // must match the audited freeze
    bytes32 ptauSha256,          // must match the pinned ptau
    bool    verificationPassed,
    address signer
)
```

### 8.4 Wallet allowlists

All three organizations must preregister their signing wallets before
the ceremony begins. The allowlist is part of the opening manifest.

EIP-712 uses Avalanche chain ID 43114, a versioned Haze emergency-ceremony
domain, and preregistered wallet allowlists.

## 9. Future Interfaces and Contract Handoff

### 9.1 No runtime API changes

No runtime API changes occur during this design phase. The emergency-exit
API surface remains unchanged.

### 9.2 Production emergency-exit backend

A new immutable production backend is required:

```text
contract HazeEmergencyGroth16Verifier {
    bool public constant NOT_FOR_PRODUCTION = false;
    // ... production verification key constants
    // ... 20 public input checks
}
```

### 9.3 Production wrapper

A new wrapper contract that replaces the development emergency-exit
verifier:

```text
contract EmergencyExitVerifier {
    // Retains the existing verifyProof, verify, and emergency-exit
    // external ABIs.
    //
    // Returns NOT_FOR_PRODUCTION = false.
    // Rejects development backends.
    // Pins the audited circuit, production artifact, verifying-key,
    // and build hashes.
    //
    // No proxy, owner, verifier replacement, or administrative
    // mutation path.
}
```

### 9.4 Production emergency-exit contract

A new `EmergencyExit` deployment that:

- Retains the existing `verifyProof`, `verify`, and emergency-exit
  external ABIs.
- Returns `NOT_FOR_PRODUCTION = false`.
- Rejects development backends.
- Pins the audited circuit, production artifact, verifying-key, and
  build hashes.
- Has no proxy, owner, verifier replacement, or administrative mutation
  path.
- Leaves every existing Fuji address and deployment script untouched.

### 9.5 Deployment scope

The new deployment set includes:

- `HazeEmergencyGroth16Verifier` (immutable, ceremony-bound VK).
- `EmergencyExitVerifier` (wrapper, NOT_FOR_PRODUCTION = false).
- `EmergencyExit` (production, pins circuit/artifact hashes).

All existing Fuji addresses remain unchanged. The new deployment set is
for mainnet only.

## 10. Documentation Reconciliation

### 10.1 Design reference

The main feature design at
`docs/ai/design/2026-08-10-feature-haze-avalanche-compliant-pool.md` should
reference this design document for the emergency ceremony.

### 10.2 Planning finding D9-SO-01

The planning document at
`docs/ai/planning/2026-08-10-feature-haze-avalanche-compliant-pool.md`
should update finding D9-SO-01 to:

```text
D9-SO-01: design resolved; artifact/tooling implementation pending.
```

Phases 7–9 remain blocked. The finding is not marked closed.

### 10.3 Parent ceremony design

The parent ceremony design at
`docs/ai/design/2026-08-18-haze-production-ceremony-design.md` should
note that the emergency ceremony design is now resolved in this document.

## 11. Validation Cases

The following cases must be validated during implementation:

### 11.1 Wrong ptau

If the downloaded ptau SHA-256 does not match
`159d3f938d941e06767d99f30b9fe59a245400a4aae138cf8e411732d7a2f6cd`,
the ceremony aborts with `VERSION_UNSUPPORTED`.

### 11.2 Changed circuit hashes

If the emergency circuit source, R1CS, or build hash does not match the
audited freeze, the ceremony aborts with `VERSION_UNSUPPORTED`.

### 11.3 Bad or out-of-order signatures

If any EIP-712 signature fails verification, or if signatures are not
in the documented contribution order (1, 2, 3), the ceremony aborts.

### 11.4 Broken zkey links

If any intermediate zkey hash does not chain to the next contributor's
input, the ceremony aborts with `ENCODING_INVALID`.

### 11.5 Late beacon anchoring

If the beacon precommit anchor transaction is not included within 120
seconds, the ceremony aborts and requires fresh contributions.

### 11.6 RPC disagreement

If the three independent RPC providers do not agree on the target block
hash at `anchor_height + 2048`, the ceremony aborts.

### 11.7 Verifier/VK mismatch

If the generated Solidity verifier does not match the verification key
exported from the final zkey, the ceremony aborts.

### 11.8 Unsigned final manifests

If any of the three organizations does not sign the final artifact
manifest, the ceremony is not considered complete.

### 11.9 Attempted rehearsal promotion

If anyone attempts to use the existing `emergency-operator-owned-ceremony-transcript.json`
as a production artifact, the tooling must reject it with
`VERSION_UNSUPPORTED`.

## 12. Assumptions

1. Any circuit change after audit freeze invalidates the audit and
   ceremony design inputs.
2. EIP-712 uses Avalanche chain ID 43114, a versioned Haze
   emergency-ceremony domain, and preregistered wallet allowlists.
3. Task CLI tracing remains unavailable, so lifecycle state is recorded
   in the AI documentation.
4. Test-first ceremony tooling and production-contract implementation
   begin only in the subsequent dev-implementation phase.
5. The existing emergency-exit contract and vector
   (`haze-exit-v1.json`, 20 public inputs) define the circuit interface.
6. The Hermez power-20 ptau is sufficient for both the spend circuit
   (588,459 constraints) and the emergency circuit (192,535 constraints).
7. The emergency ceremony does not make the pool production-ready. Spend
   proving, audits, incident review, Fuji approval, and the remaining
   SC-09 gates still apply.

## 13. Non-Goals

- Flipping `haze/deployments/fuji-v1.json` (`broadcast: false`,
  `spend_prove: KEYS_MISSING`).
- Flipping SC-09 or `mainnetAuthorized`.
- Calling this ceremony `production_ceremony.approved` before SC-09
  approval.
- Inventing or committing Groth16 proving keys.
- Redeploying the live Fuji verifier/pool/router/exit.
- Wrapping parent `tools/ceremony-cli` as a Haze public API.
- Changing the existing Fuji deployment set.

## 14. Implementation Pending

The following are explicitly out of this design phase and reserved for
the subsequent dev-implementation phase:

- Emergency circuit audit freeze (actual hash values).
- Ceremony tooling (ptau download, phase-2 setup/contribute/beacon/verify
  for the emergency circuit).
- EIP-712 signing and verification implementation.
- Beacon anchoring transaction construction.
- Independent RPC provider selection and validation.
- Production emergency-exit verifier contract generation.
- Production emergency-exit wrapper and exit contract deployment.
- Artifact manifest signing ceremony.
- Test suite for all validation cases in Section 11.
