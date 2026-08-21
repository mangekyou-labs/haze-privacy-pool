---
phase: implementation
title: Implementation Guide
description: Technical implementation notes, patterns, and code guidelines
---

## D6-D7 browser continuation (2026-08-21)

- D6 deployment packaging fix: the first monorepo-root Vercel archive reached the remote builder
  but failed because the local `haze/.tools` symlink was uploaded. `haze/.vercelignore` now excludes
  local toolchains, dependency/build outputs, Playwright state, environment files, and
  ceremony-private artifacts. A focused deployment-config test locks the two security-critical
  exclusions (`.tools` and `dev/artifacts/ceremony-private`).
- In progress: browser operation randomness now produces independent note secret, blinding,
  action reference, audit salt, recipient HPKE seed, and audit HPKE seed.
- Added a browser-safe Fuji orchestration boundary for policy-authority membership-root updates and
  transaction ordering. Membership changes require the exact authority wallet, a successful receipt,
  and a refetched root with an incremented version. Transaction submission waits for approval,
  performs the final preflight, persists submitted state before wallet broadcast, and delegates final
  receipt/event confirmation to reconciliation.
- Remaining before D6/D7: connect this boundary to the deployed client, construct canonical recipient
  and audit envelopes, prove/encode/sign deposit and same-note withdrawal, persist/recover complete
  bindings, issue wallet-scoped disclosure, then run all release and deployed-browser gates.

# Implementation Guide

## Progress — 2026-08-21 deployed Fuji continuation

- D2 complete: the worker entry now uses a web-platform-only session rather than the
  filesystem-capable Node prover session. Verified manifest WASM/zkey bytes are transferred to
  `snarkjs.groth16.fullProve`; request-scoped progress, success, cancellation, and typed errors are
  returned to the host. Cancellation suppresses a late proof result, and clearing zeroes retained
  artifact buffers. `generateBrowserSecrets` obtains independent note-secret, blinding, and HPKE
  ephemeral seed bytes from `crypto.getRandomValues`. Browser-native Noble HPKE reproduces the
  Rust recipient/audit vectors, canonical envelope framing, and AAD rejection behavior.
- D2 changed files so far: `haze/sdk/typescript/src/browser-worker-session.ts`,
  `prover-worker.ts`, `browser-prover.ts`, `index.ts`, and `haze/tests/browser-prover.test.mjs`.
  `browser-crypto.ts`, `browser-operation-vault.ts`, `fuji-reconciliation.ts`, and
  `render-disclosure.ts` complete D2-D4 plus the bounded disclosure client retry boundary.
- D3 complete: wallet signatures feed a chain/application/pool/wallet-bound WebCrypto HKDF key;
  AES-GCM encrypts IndexedDB operation records and metadata before broadcast through the required
  proving, ready-to-submit, submitted, and terminal states. Restart recovery is covered.
- D4 complete: approval success precedes deposits, every transaction receives a final `eth_call`,
  and receipt status plus a matching `PrivateTransaction` event jointly determine confirmation.
  Missing/reverted withdrawals leave notes spendable; disclosure status remains independent.
- D5 complete locally: the stateless Axum adapter exposes health/readiness/withdrawal routes,
  exact-origin CORS, Fuji receipt/block/event recovery, EIP-712 signer recovery, canonical
  envelope/CBOR/commitment verification, field redaction, stable errors, and production fail-close.
- Started D1 with a browser-native `loadFujiProvingArtifacts` SDK interface. Callers may supply
  immutable URLs (through `fetch`) or already-downloaded `Uint8Array` values; both paths enforce
  manifest byte size and SHA-256 before exposing the WASM or zkey.
- The accepted manifest profile is exactly `fuji-development` with `notForProduction: true`.
  Profile, size, HTTP, and digest failures close as `ARTIFACT_INVALID`.
- Changed files: `haze/sdk/typescript/src/browser-prover.ts`, its public exports in `src/index.ts`,
  and `haze/tests/browser-prover.test.mjs`.
- D1 is complete. The operator-owned Fuji artifact was recovered through the worktree's private
  ceremony-artifact link and verified with `snarkjs zkey verify` against the frozen 588459-constraint
  spend R1CS and Powers of Tau (`ZKey Ok!`). It remains a Fuji-development artifact and does not
  change production ceremony or SC-09 status.
- Vercel Blob store `haze-fuji-proving` is connected to the `haze` project for Production, Preview,
  and Development. The immutable public artifacts are:
  - WASM: 2,611,219 bytes, SHA-256
    `0fc940afbd43a8c16b34e2fd7947c4016963cdf120c7ae34d1188666069b5b57`.
  - zkey: 280,397,584 bytes, SHA-256
    `374bb2394da985ab824ce61a95b3b3409b71355139f0a6b16fb8e0bff8e508d5`.
- The committed frontend manifest is
  `haze/web/apps/haze/public/proving/fuji-development/haze-spend-v1/manifest.json`. Fresh Blob
  downloads reproduced both byte sizes and hashes. A fresh proof produced 29 public signals and a
  256-byte Groth16 payload; the Fuji production-path `eth_call` returned `true` from pairing verifier
  `0x9b82283af98124b82dE0b96587C98946a95D45E3`.

## Progress — 2026-08-20 clickable operator MVP

Operator hatch can now Shield → persist a Poseidon note → Withdraw on Fuji without flipping
SC-09 or committed `fuji-v1.json`.

- Hatch-on `/shield?live=1` plans a circuit-valid deposit (`planLiveOperatorShield`) and
  persists `fuji-poseidon-note.json` for the existing withdraw prover.
- `npm run commercial:operator` sets `HAZE_OPERATOR_PROVE=1` and refuses a missing zkey.
  Default `npm run commercial` stays `KEYS_MISSING`. Digest `/shield?live=1` is unchanged
  and must not be Groth16-spent.
- DEX chip when hatch is open: `Fuji demo · operator keys local`. `canSignAction` is still
  withdraw-only (private send stays closed).

Gates: committed `fuji-v1.json` `broadcast: false` / `spend_prove: KEYS_MISSING`. Browser
never fetches the zkey.

Headed chrome walk (playwright-cli, 2026-08-20): operator host `http://127.0.0.1:3014`
`/shield?live=1` and `/withdraw?live=1` show the hatch chip and enable Sign and submit;
`/send?live=1` stays `Spend proofs unavailable`. Submit without MetaMask is `WALLET_MISSING`.
`notification.html` unclaimed for playwright-cli. Default host 3010 stays digest-only.

Headed MetaMask operator walk attempt 1 (`dappwright:live-operator`, 2026-08-20) showed
Shield `0xf6bb4e42…5de0` and withdraw `0x673fcfdd…7e55` in the UI; both Fuji receipts
reverted (`COMMITMENT_DUPLICATE` then `ROOT_UNKNOWN`). The hatch planner reused the
fixture Poseidon commitment already on pool `0x00BEB0A5…d550`.

Fix: `planUnusedLiveCircuitDeposit` keeps the registered spending secret and picks an
unused blinding, leaf index = occupied on-chain commitments (not drifted overlay
`nextIndex`). Host prove skips persist; `shield-live.js` persists only after
`eth_getTransactionReceipt.status === 0x1`. Overlay recorder writes
`websiteOperator*` only when both receipts are `0x1`.

Attempt 2 (`HAZE_COMMERCIAL_URL=http://127.0.0.1:3014 npm run dappwright:live-operator`,
~137s): Shield `0x15a9f9c3f2223476203d95fa2acdeaf0a8d7c078aa17c4b523cc9b98700b1b4b`
and withdraw `0xb97e014e858dea1264924e3f7b53dbaecdf4b0a340a933e3f5347d565cf3f850`
both mined `status: 0x1` on Poseidon pool `0x00BEB0A5…d550` (2 logs each). Overlay
`websiteOperatorHost` `http://127.0.0.1:3014`, `nextIndex` 3. Committed
`fuji-v1.json` stays `broadcast: false` / `KEYS_MISSING`.

## Progress — 2026-08-20 DEX-first chrome

Pool-user chrome is a centered DEX card (`data-chrome="dex"`, home `/shield`), not the
2026-08-18 workstation. Compliance stays a wider secondary card. Volcanic IBM Plex tokens,
review-then-sign, and fail-closed chips are unchanged.

`KEYS_MISSING` is not a regression. Committed `haze/deployments/fuji-v1.json` is still
`broadcast: false` / `spend_prove: KEYS_MISSING`. That is the published proving package.
Operator-owned Fuji txs on the live sidecar (`fuji-v1.live.json`) are a real testnet demo
(Poseidon pool `0x00BEB0A5…d550`, deposit `0xf8322001…3036`, withdraw `0x66ff71a2…7760`,
website withdraw `0x9d251910…d5e1`). They are not a ceremony approval and they do not
flip SC-09. Default commercial host does not open `liveOperatorWithdrawAllowed`.

Tests: `haze/tests/commercial-frontend.test.mjs` chrome assertion; `npm test --prefix haze`
258 pass / 0 fail. Spec: `docs/ai/design/2026-08-20-haze-dex-first-chrome.md`.

## Progress — 2026-08-20 Code Review (Phase 9)

Holistic review found no merge-blocking defect. Remaining items are accepted deferrals
(`KEYS_MISSING`, SC-09 closed, keccak development tree, emergency Circom, MetaMask
`notification.html`) plus secret-scan follow-ups (dotfiles / >5 MB). Ready to push as a
development checkpoint, not mainnet. Full record is in **Code Review (Phase 9, 2026-08-20)**
below.

## Progress — 2026-08-20 Write Tests (Phase 8)

Closed the Phase 7 secret-scan tooling gap (`ceremony-private` / oversized binaries) with a TDD
regression, added public-input binding tests (isolated from the verifier gas snapshot), re-pinned
local Foundry `haze-gas-v1.json` measured values still under +15% budgets, and lockstepped
testing-doc integration checkboxes to existing E2E/workflow/Foundry evidence. MetaMask
connect/account-switch stays unclaimed. Next: `dev-review`. Full record is in the testing doc and
**Write Tests (Phase 8, 2026-08-20)** below.

## Progress — 2026-08-20 Check Implementation (Phase 7)

Compared shipped `haze/` against approved requirements and design. Remaining gaps are approved
overrides and documented deferrals (library-first services, commercial one-origin UI, `KEYS_MISSING`,
SC-09 closed, keccak-mod-r development tree plus Poseidon sibling, emergency Circom deferred). No
implementation-wrong or design-wrong findings that require Execute Plan or a return to `dev-design`.
Next: `dev-testing`. Full alignment record is in **Check Implementation (Phase 7, 2026-08-20)**
below.

## Progress — 2026-08-19 commercial QA harness

Blink-style persist-once MetaMask lives in `haze/dev/setup-metamask.mjs`. dAppwright
initializes the profile; playwright-cli is the walk. Commercial UI hides the role chip
until a wallet is connected, uses `closest("[data-action]")` for header clicks, and
states unauthorized workspaces as connect-first when disconnected. Committed
`fuji-v1.json` stays `broadcast: false` / `KEYS_MISSING`. MetaMask approval popups
(`notification.html`) are not reachable from playwright-cli; connect/account-switch
are not claimed as automated acceptance.

## Progress — 2026-08-18 production ceremony pipeline

Operator-owned Groth16 driver for frozen `haze-spend-v1` (588459 constraints, Circom 2.2.3,
ptau power 20). Avalanche Builder Hub / Encrypted ERC is the wrong circuit. Spec:
`docs/ai/design/2026-08-18-haze-production-ceremony-design.md`. Committed `fuji-v1.json` and
all four SC-09 gates stay closed. Proving keys stay gitignored. One-laptop setup is not
`production_ceremony.approved`. Redeploy of the immutable Fuji verifier is out of this milestone.

## Current Status

T0.1 and T0.2 are complete. T0.2 encodings, spec-minimum vectors, and four-language harnesses are
in `haze-protocol` plus the committed artifact. Independent review `91cfa5ee` accepted the
encodings; follow-ups are implemented. Product approved
`docs/ai/design/2026-08-17-t0.2-product-approval-packet.md` on 2026-08-17. No production HazePool,
or live vendor adapter has been introduced. T1.1 is complete: Circom independently reproduces the
v1 Poseidon2 sponge. T1.2 is complete: `haze/circuits/src/spend.circom` is the versioned 2-in/2-out
normal spend (actions 1–4). T1.3 is complete: proving packages exist. T1.4 is complete: ceremony
tooling and SC-09 provenance exist. T2.1 is complete: `HazeSpendVerifier` wraps 29 public-input
checks and artifact hashes; production spend Groth16 keys remain T7.4. T2.2 is complete:
`HazeAccess`, `ApplicationRegistry`, `PolicyRegistry`, and `VersionRegistry` implement
timelocked Haze governance, app-controlled membership roots, and metadata-only releases.
T2.3 is complete: `HazePool` implements deposit, transact, and `depositFromRouter`. T2.4 is
complete: `SwapAndShieldRouter` is the allowlisted adapter boundary. T2.5 is complete:
`EmergencyExit` is the immutable seven-day public-exit sibling. T2.6 is complete: Foundry invariant
handlers cover the user/governance transitions and `haze/dev/artifacts/haze-gas-v1.json` pins
provisional local budgets. T3.1 is complete: the TypeScript SDK exposes provider-neutral transport,
contract selectors, EIP-712 types, manifest hashing, quote adapters, a versioned gatekeeper client,
error taxonomy, and Fuji compatibility checks. T3.2 is complete: the TypeScript SDK derives
app-scoped shielded accounts, encodes `haze1:` addresses, opens recipient HPKE, and keeps an
encrypted local vault with wipe/replay recovery. T3.3 is complete: `createWorkflowClient` runs
quote/proof/authorization/submission/finality state machines for the six user paths, with
fail-closed cancel, reject, expiry, slippage, stale-policy resync, and reorg retry. T3.4 is
complete: the TypeScript SDK packages a node-free proving Web Worker, artifact cache/version
selection, progress/cancel host hooks, Apache-2.0 package metadata, and a reference
direct-shield example. T4.1 is complete: existing `haze-gatekeeper` is now lib+bin with
`Gatekeeper::authorize` as the `POST /v1/authorizations` semantic (no HTTP listener). T4.2 is
complete: existing `haze-indexer` is now lib+bin with `Indexer::ingest` / `Indexer::sync` as the
event-ingestion semantic (no HTTP listener). T4.2a is complete: independently verifiable
policy-witness APIs on `haze-protocol`, `Indexer::haze_witness`, and
`Gatekeeper::application_witnesses` (no HTTP listener). T4.3 is complete: existing
`haze-audit-auth` is now lib+bin with `AuditAuth::challenge` / `token` / `create_case` /
`update_case` / `delegate` / `revoke` / `authorize` as the `/v1/auth/*` and `/v1/cases`
semantic (no HTTP listener). T4.4 is complete: existing `haze-disclosure` is now lib+bin
with `Disclosure::query` / `export` / `access_log` / `verify_export` as the
`/v1/disclosures/*` and `/v1/access-log` semantic (no HTTP listener). T4.5 is complete:
shared `haze_protocol::ops` provides library `GET /health` / `GET /ready`, schema 2
migrations, idempotency, write-once retention, backup/restore, and replica sharing. T5.1 is
complete: alpine-volcanic design tokens, shared accessible primitives, role/route/API guards,
and a privacy-copy glossary for both independently deployable apps. T5.2 is complete:
`createDexApp` is the library-first Privacy Pool DEX controller (wallet onboarding and six
user workflows). Hosted Next.js remains T6.2. A local `haze/dev` host hydrates those controllers
for UI e2e; Fuji live broadcast remains fail-closed. Fuji re-measure remains required before mainnet.

## Development Setup

The Haze product lives in the nested `haze/` workspace and can be validated independently:

```sh
npm test --prefix haze
npm run build --prefix haze
cargo test --manifest-path haze/Cargo.toml --workspace
cargo clippy --manifest-path haze/Cargo.toml --workspace --all-targets --all-features -- -D warnings
forge build --root haze/contracts
```

The root repository remains unchanged as the source reference and does not supply implicit Haze
workspace dependencies.

## Code Structure

- `haze/contracts/`: isolated Foundry boundary for immutable Solidity contracts.
- `haze/circuits/`: Haze-specific Circom and canonical vector boundary.
- `haze/crates/protocol/`: provider-neutral protocol and compatibility types.
- `haze/crates/prover/`: native proving and cryptographic client boundary.
- `haze/services/`: separate gatekeeper, indexer, audit-auth, and disclosure processes.
- `haze/sdk/typescript/`: TypeScript SDK package.
- `haze/apps/privacy-pool-dex/`: independently deployable user frontend package.
- `haze/apps/compliance-portal/`: independently deployable institutional portal package.
- `haze/apps/_shared/`: library-first UX contracts re-exported by both apps (not a Node package).
- `haze/deployments/`: immutable deployment-manifest boundary.
- `haze/tests/`: architecture and future cross-component tests.

## T0.1 Implementation Notes

### Boundary enforcement

`haze/tests/product-boundary.test.mjs` is the executable architecture rule. It requires the approved
package set, checks Cargo and Node dependency manifests, and scans public Rust, TypeScript, Solidity,
and Circom imports. It rejects network-specific contracts, adapters, wallet integration, and
authentication protocol dependencies, including public re-export forms.

The first TDD red run identified every missing package. A second red run proved that the original
scanner did not recognize Rust `pub use` or TypeScript `export ... from`; the matcher was corrected
before the task was accepted.

### Reuse disposition

- Existing Poseidon2, Merkle, sparse-Merkle, encryption, vault, recovery, and conformance-test ideas
  remain candidates for reviewed adaptation in T1.1.
- Previous Haze protocol validation and stable-wire-error patterns remain candidates for a newly
  defined Avalanche schema in T0.2.
- Existing transaction circuits are not copied because their policy model does not enforce the
  approved Haze rules for every enabled input and output.
- Existing contracts, relayer flows, network adapters, wallet integration, and authentication flows
  are not Haze dependencies.
- T0.1 copied no production implementation from the previous Haze branch; it established destinations
  and an enforceable boundary for future selective ports.

## T0.2 Implementation Notes

- Rust reference: `haze/crates/protocol` (Poseidon2 sponge via path `poseidon2`/`zkhash`, Keccak-256,
  note/policy/Merkle/address/envelope/EIP-712/audit encodings, RFC 9180 HPKE Base, RFC 8949 CBOR,
  HKDF-SHA256 labels).
- Committed artifact: `haze/circuits/vectors/v1/haze-protocol-v1.json`, generated by
  `haze_protocol::vectors::build_vector_artifact` and checked for exact equality. 35 positive and 17
  one-reason negative vectors, plus Poseidon2 parameter-file hashes.
- Harnesses: Rust `haze/crates/protocol/tests/vectors.rs`, Node
  `haze/tests/protocol-vectors.test.mjs` (domain field = keccak256(label) mod r), Circom schema
  `haze/circuits/vectors/check.mjs` (parameter-file hashes, public-input names, and Circom 2.2.3
  sponge witness vs `note_public_key`), Foundry
  `haze/contracts/test/ProtocolVectors.t.sol` (all 13 domain tags, Fuji domain separator, intent and
  authorization struct hashes/digests via `abi.encode`). Foundry `via_ir` is enabled so the 25-field
  intent `abi.encode` compiles under solc 0.8.28.
- ADRs: `docs/ai/design/adr/0001-hybrid-poseidon2-keccak.md`,
  `0002-field-and-address-encodings.md`, `0003-threat-model-v1.md`.
- `bytes32` identifiers are two uint128 limbs. Domain tags may be reduced modulo \(r\).
- Clippy `too_many_arguments` is allowed on `note_commitment` and `audit_aad` because those tuples
  are the public protocol preimages, not accidental APIs.
- Address and encryption-key codecs reject RFC 7748 low-order X25519 public keys.
- `domain_field` accepts only the 13 frozen Poseidon labels; the address checksum label stays Keccak-only.
- EIP-712 `uint48` fields and non-swap swap-only fields are rejected before hashing.
- Deposit intents require `noteTreeRoot` and both input nullifiers to be zero.
- Envelope encode/decode fail closed on HPKE suite bounds, purpose/key-version mismatch, and trailing bytes.
- HPKE Base uses the reviewed `hpke` 0.14 crate (X25519 / HKDF-SHA256 / ChaCha20-Poly1305) with
  deterministic test IKM `0x51`/`0x52` and sender seeds `0x61`/`0x62`. Dummy `0x11`/`0x22` envelopes
  remain hash-only fixtures; seal/open is a separate vector.
- Spending secrets use HKDF-SHA256 extract/expand with frozen labels and counter rejection sampling
  (no modular reduction).

## Integration Points

T0.3 adds provider-neutral traits in `haze/crates/protocol/src/providers.rs` and TypeScript types in
`haze/sdk/typescript/src/providers.ts`. Mocks cover quote success, DEX/KMS/identity outages, static
Fuji RPC, and in-memory object storage. ADR-0004 records the candidate evaluation. No vendor SDK is
exported.

There are no live provider integrations. Concrete adapters remain future private modules.

## T0.4 Implementation Notes

- `haze/rust-toolchain.toml` pins Rust 1.97.1. Node engines require `>=22`. Foundry `solc` is `0.8.28`.
- Local EVM mocks: `MockUsdc` (6 decimals), `MockSourceToken`, `MockDex` (1:1).
- `haze/dev/artifacts/development-circuit-manifest.json` is tagged `not_for_production`.
  `select_circuit_artifact(Production, …)` rejects it.
- `haze/dev/postgres/migrations/0001_init.sql` creates access-log and audit-record stubs.
- `haze/dev/secret-scan.mjs` fails on PEM private keys and `AKIA` access keys.
- Staged CI: `.github/workflows/haze.yml` runs secret-scan, then node, rust, and contracts.

## Error Handling and Security

- Rust packages deny unsafe code and warn on missing public documentation.
- Clippy denies panics and `unwrap` usage across the nested Rust workspace.
- Architecture violations fail the Node test with the exact missing path, package, dependency, or
  import statement.
- Development and generated output directories are ignored inside the Haze boundary.
- Empty service binaries expose no network listeners, secrets, or permissive fallback behavior.

## Check Implementation (Phase 7, 2026-08-17)

Compared `haze/crates/protocol`, the committed vector artifact, and the four harnesses against
`docs/ai/design/2026-08-10-haze-avalanche-protocol-v1.md` and ADRs 0001–0003.

Aligned:

- Hybrid Poseidon2 / Keccak-256 boundary, BN254 `r`, 32-byte big-endian fields, lossless `bytes32`
  limbs, `uint160` addresses, actions `1..=5`, depth-32 empty roots, pool-domain binding, note /
  nullifier / membership / blocklist / audit preimages, `haze1:` `HZAV` address, `HZHP` envelope
  framing, EIP-712 type strings, emergency request-id encoding, Circle USDC Fuji
  `0x5425890298aed601595a70AB815c96711a31Bc65` and C-Chain
  `0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e`.
- Independent Node recomputation (this session): 13 domain Keccak tags, 13 `uint256(K) mod r` field
  constants, and 4 EIP-712 type hashes all match the committed JSON (`30 ok, 0 fail`).

Independent review `91cfa5ee` accepted T0.2 encodings with three follow-ups. Those follow-ups are
now implemented (not production-circuit work):

- Spec-minimum vectors: HPKE Base seal/open, RFC 8949 CBOR, HKDF labels and rejection sampling,
  Merkle zero/sentinels and a note path, adjacent blocklist sentinels, pad10* odd/even blocks,
  public-input order, and Poseidon2 parameter-file hashes.
- Deposit zero-rule is encoded in `HazeIntent::validate` with a one-reason negative vector.
- Harness independence: TypeScript reduces `keccak256(label) mod r`; Solidity recomputes all 13
  domain tags, the Fuji domain separator, and intent/authorization digests via `abi.encode`; Circom
  independently hashes parameter files, records public-input names, and compiles `sponge_1` against
  the committed `note_public_key` vector.

Product approved T0.2 on 2026-08-17. T1.1, T1.2, T1.3, T1.4, and T2.1 are complete.

## T2.1 Implementation Notes

- Still exactly six Rust packages. Public-input checks live in `haze-protocol::verifier`.
- `HazeSpendVerifier` is a versioned immutable wrapper: constructor-set `pairingBackend`, no owner,
  proxy, `upgradeTo`, `initialize`, or setter. New verifier versions are new deployments (T7.4).
- Canonical checks: 29 fields `< r`, frozen `protocol_version_tag`, actions 1–5, deposit zeros
  (`note_tree_root` and both input nullifiers), T1.3 `SPEND_ARTIFACT_HASH`.
- Valid Rust/browser proofs verify as T1.3 sameness: keys + 29 public inputs + artifact hash. The
  development proof digest is `keccak256(abi.encodePacked(uint256[29]))`. Pairing delegates to the
  T1.4 `DevelopmentEqualityVerifier` and is labeled `NOT_FOR_PRODUCTION`.
- Production selection reverts `KEYS_MISSING`. Protocol `verify_production_spend` returns
  `VERSION_UNSUPPORTED`.
- Gas snapshot: `verify()` = 15214 (`haze/dev/artifacts/verifier-gas-snapshot.json`).
- Committed vector: `haze/circuits/vectors/v1/haze-verifier-v1.json`.
- Do not generate 588459-constraint Groth16 keys or a ceremony-bound spend VK in this task.

## T1.4 Implementation Notes

- Still exactly six Rust packages. Ceremony types live in `haze-protocol`; signing lives in
  `haze-prover`. No new workspace member.
- Spend proving stays `KEYS_MISSING`. T1.4 does not generate 588459-constraint Groth16 keys.
- Two clean Circom 2.2.3 builds of `haze/circuits/test/development_equality.circom` must match r1cs
  hashes. Spend source, r1cs, fixture, and `n_constraints = 588459` are pinned in
  `haze/dev/artifacts/circuit-build-manifest.json`.
- Rehearsal contributions are a Keccak-256 hash-chain from
  `haze/avalanche/v1/ceremony || 0x00 || circuit_id`. The generated
  `DevelopmentEqualityVerifier.sol` is a hash-gated equality check labeled `NOT_FOR_PRODUCTION`.
  T2.1 owns the immutable spend verifier.
- Artifact manifests are signed as `keccak256("haze-ceremony-manifest-v1" || 0x00 || payload)` with
  the T1.3 fixture secp256k1 key. Recovered signer is `0x7e5f4552091a69125d5dfcb7b8c2659029395bdf`.
- SC-09 provenance keeps Fuji pilot, independent audit, production ceremony, and incident review
  closed. `assert_production_activation` returns `VERSION_UNSUPPORTED`.
- Production runbook `haze/dev/runbooks/production-ceremony.md` forbids T7.4 until audit freeze and
  does not reuse parent `tools/ceremony-cli` as a Haze API.

## T1.3 Implementation Notes

- Reused existing `haze-prover` (still exactly six Rust packages). No new workspace member.
- EIP-712 domain `Haze Shielded Account` / `HazeKeyDerivation(address wallet,bytes32 applicationId,bytes32 poolVersion)`.
  IKM is a 65-byte low-s recoverable signature with `v ∈ {0,1}`. Recovery must equal the declared
  wallet or `UNSUPPORTED_RECOVERY`.
- Fixture wallet for secp256k1 privkey `0x01` is `0x7e5f4552091a69125d5dfcb7b8c2659029395bdf`.
- Spend Groth16 ceremony execution is T7.4. `prove_spend` / `proveSpend` return `KEYS_MISSING`.
- Development Groth16 is a native arkworks equality circuit (`private === public`) on BN254. TypeScript
  development proofs are same-stack session proofs, not arkworks bytes. Cross-runtime sameness is
  keys, 29 spend public inputs, and artifact hash — not Groth16 proof bytes.
- Artifact hash = `keccak256(keccak256(circuit) || keccak256(fixture) || keccak256(manifest))` over
  `spend.circom`, `haze-spend-v1.json`, and `development-circuit-manifest.json`.
- Production profile still cannot select the development manifest.
- ark-relations 0.6 uses GR1CS; equality constraints call `enforce_r1cs_constraint`.
- Sessions expose cancel, progress stages, retain/clear/zeroize. Drop clears secrets.
- Committed vector: `haze/circuits/vectors/v1/haze-prover-v1.json`.
- `SC-05`: re-derive spending/encryption/vault keys from the wallet message. T3.2 restores notes
  after local-vault deletion at the SDK unit layer. `SC-06` spend P95 is T6.3; T1.3 records
  development-circuit duration in `haze/dev/artifacts/proving-benchmark.json`.

## T2.2 Implementation Notes

- `HazeAccess` holds separate `governance`, `pauseRole`, and timelocked `superAuditor` grants.
  Pause is immediate. Super-auditor status confers no registry mutation and does not bypass KMS.
- Haze governance actions (`scheduleRegister`, suspend/reactivate/retire, `schedulePolicy`,
  `scheduleRelease`, super-auditor grant) require `minDelay` before activation. Foundry tests use
  `minDelay = 2 days`.
- Application `policy_authority` updates the KYC membership root on `ACTIVE` apps only. Governance
  cannot write membership roots.
- App `admin` rotates the gatekeeper signer and manifest URI/hash immediately. Those are
  application-owned credentials, not Haze-multisig actions under `FR-11`.
- `PolicyRegistry.isActivePolicy` accepts only the current active version+root. Activating version
  `n+1` retires `n` with no grace window.
- `VersionRegistry` publishes release metadata and artifact hashes. It has no `upgradeTo`,
  `initialize`, or owner path.
- Protocol/TS helpers `policy_is_live` / `policyIsLive` match Solidity enum discriminants.
- Vector: `haze/circuits/vectors/v1/haze-registry-v1.json`.
- Emergency-exit *contract* shipped in T2.5. HazePool consumes these registries on every action.

## T2.3 Implementation Notes

- `HazePool` is immutable: constructor-set access, registries, spend verifier, USDC, approved
  router, `poolVersion`, and root-history size. No `owner`, `initialize`, or `upgradeTo`.
- Entry points: `deposit` (action 1), `transact` (actions 2–3), `depositFromRouter` (action 4,
  `msg.sender == approvedRouter`, `payer == intent.user`). Action 5 is rejected. Direct callers
  must equal the authorized user.
- EIP-712 domain is `Haze Avalanche Compliant Pool` / `1`. The pool recomputes the intent struct
  hash and 29 public inputs; development proofs are `keccak256(abi.encodePacked(uint256[29]))`.
- Nonce scope is `(application_id, gatekeeper_signer, nonce)`. Proof verification runs before
  nonce or nullifier consumption.
- Application must be `ACTIVE`. Application policy is the current `membershipVersion` +
  `membershipRoot`. Haze policy uses `PolicyRegistry.isActivePolicy` with no grace period.
- Development incremental tree: keccak parent reduced mod r, depth 32, configurable root-history
  ring. Zero dummy commitments are not inserted. Poseidon2 incremental updates remain later.
- Exact MockUsdc pull-before-insert on deposit/router paths; exact push on withdraw. Transfer
  moves no USDC.
- Vector: `haze/circuits/vectors/v1/haze-pool-v1.json`. Foundry: `haze/contracts/test/HazePool.t.sol`.
- Emergency-exit contract shipped in T2.5. Sustained invariants and gas budgets shipped in T2.6.
  Production Groth16 keys remain T7.4.

## T2.4 Implementation Notes

- `SwapAndShieldRouter` is immutable: constructor-set `HazeAccess`, `HazePool`, USDC, and seeded
  token/adapter allowlists. Constructor requires `pool.approvedRouter() == address(this)`. No
  owner, proxy, upgrade, skim, or emergency-exit path. Public types stay provider-neutral.
- `swapAndShield(TransactArgs, SwapRoute)` requires action 4, `msg.sender == intent.user`, live
  deadline, `routeHash = keccak256(abi.encode(adapter, data))` matching both the signed intent and
  `expectedRouteHash`, and allowlisted `tokenIn != usdc` plus allowlisted adapter.
- Pulls exact `amountIn` (fee-on-transfer and positive rebase revert), approves the adapter for
  that amount only, `call`s the adapter (no `delegatecall`, no user-chosen extra target), resets
  the adapter approval, requires leftover source == 0, requires USDC delta `>= minUsdcOut` and
  `== publicAmount`, approves the pool, calls `depositFromRouter(msg.sender, args)`, resets the
  pool approval, and requires zero residual source+USDC and zero leftover approvals.
- Later allowlist changes are timelocked through `HazeAccess.minDelay` (`scheduleToken` /
  `activateToken`, `scheduleAdapter` / `activateAdapter`). Governance cannot spend user notes.
- Deploy chicken-egg: predict the router CREATE address, construct `HazePool` with that
  `approvedRouter`, then deploy the router.
- Local adapter is `MockDex.swapExactIn` (1:1 raw units). No live vendor DEX.
- Vector: `haze/circuits/vectors/v1/haze-router-v1.json`. Foundry:
  `haze/contracts/test/SwapAndShieldRouter.t.sol`. TS: `haze/sdk/typescript/src/router.ts`.
- Foundry `via_ir` can hoist `block.timestamp` across `vm.warp` in the same test; helpers must use
  `vm.getBlockTimestamp()`. `_finalize` must not overwrite an explicitly expired deadline.

## T2.5 Implementation Notes

- `EmergencyExit` is immutable: constructor-set `HazeAccess`, `HazePool`, `VersionRegistry`, and
  `PolicyRegistry`. Constructor requires `pool.approvedExit() == address(this)`. No owner, proxy,
  upgrade, or pause gate on `requestEmergencyExit` / `executeEmergencyExit`.
- Request stores only `requestedAt[requestId]`. The request transaction reveals the opaque id, not
  the nullifier. Request does not reserve or consume a nullifier.
- `request_id = keccak256(abi.encode(keccak256(REQUEST_TYPE), chainId, pool, poolVersion,
  applicationId, nullifier, recipient, requestSalt))`. Frozen Fuji fixture hash
  `0xfc7450e6893c57123a3119a83330cfdd6243ed448260c3bca6a9ae484f5d4a63`.
- Execute after `COOLDOWN = 7 days` recomputes the id, requires a known note-tree root, live Haze
  policy (`isActivePolicy`, no grace), nonzero amount, and recipient not `0` / pool / this. It then
  marks `requestUsed` and calls `HazePool.exitFromEmergency`, which skips pause, consumes the
  nullifier, and pushes exact USDC. Failed execute leaves request and nullifier unchanged.
- Development emergency proof is `keccak256(abi.encodePacked(uint256[20]))`. No emergency Circom in
  this task; production Groth16 remains T7.4. Contract-layer blocked-recipient is the live Haze root
  plus the nonzero/non-self/non-exit check. Circuit non-membership waits for the later exit circuit.
- Direct `deposit` / `transact` still reject action 5. Exit events use `applicationPolicyVersion = 0`
  and the request id as the client-side action reference.
- `VersionRegistry` keeps the 3-arg `scheduleRelease` and adds a 4-arg overload with `supportUntil`.
  `isExitCapable`: Unspecified=true, Scheduled=false, Active=true, Retired=`now <= supportUntil`.
- Deploy chicken-egg: predict the exit CREATE address, construct `HazePool` with that `approvedExit`,
  then deploy `EmergencyExit`. Existing pool/router suites pass `address(0)` when they do not need
  an exit sibling.
- FR-14 MVP migration is a public withdraw from the retiring pool, then a separately authorized
  shield into a replacement `HazePool`. There is no atomic exit-and-re-shield.
- Vector: `haze/circuits/vectors/v1/haze-exit-v1.json`. Foundry:
  `haze/contracts/test/EmergencyExit.t.sol`. TS: `haze/sdk/typescript/src/emergency.ts`.
- Prebuild execute args before `vm.expectRevert`. A view helper that calls `publicInputs` consumes
  the expected revert. Use `vm.getBlockTimestamp()` after warps (`via_ir` hoist).

## T3.1 Implementation Notes

- No seventh Rust package and no production proving keys. T3.1 is TypeScript types and transports in
  `haze/sdk/typescript/src/`.
- Public APIs stay provider-neutral: `EvmTransport`, `MemoryTransport`, selector bindings, EIP-712,
  manifest hash, quote adapter, and gatekeeper client do not name ethers, viem, Alchemy, or Infura.
- Fuji pin in `FUJI_COMPATIBILITY`: chainId 43113, schema/api/manifest 1, domain version `"1"`,
  `protocolVersionTag` `0x2afe8a5679df289719eae23ad89b300434b9dfbb8194dad0b50dee97f91a3868`,
  `circuitArtifactHash` `0xac2082ecb2129c571d2ddeb170f261a0da074491773102fa4f1544e97eb19281`.
  Chain drift is `CHAIN_MISMATCH`; other pin drift is `VERSION_UNSUPPORTED`.
- EIP-712 type strings and pool domain name/version match T0.2. Deposit requires zero tree and
  input nullifiers. Non-swap intents require zero swap fields. `uint48` overflow is
  `FIELD_OUT_OF_RANGE`. Wrong domain name is `DOMAIN_MISMATCH`.
- Manifest digest is `keccak256` of canonical sorted-key JSON. `parseManifest` rejects
  `privateKey`/`secret`/`ssn`/`password`/`mnemonic`/`seed` (`ENCODING_INVALID`) before version
  (`VERSION_UNSUPPORTED`) and hash (`ENCODING_INVALID`).
- Bindings pin Foundry ABI selectors for `deposit`/`transact`/`depositFromRouter`,
  `swapAndShield`, `requestEmergencyExit(bytes32)`, `poolVersion()`, and `SPEND_ARTIFACT_HASH()`.
- Quote adapter returns `usdcOut`, `adapter`, `routeHash`, `calldataHash`, and `expiry` without a
  `vendorRoute` field. Insufficient output is `QUOTE_STALE`; down adapter is `UNAVAILABLE`.
- Gatekeeper client posts `/v1/authorizations` and gets `/v1/applications/{id}/manifest` with
  `haze-api-version`. Typed denials map to the gatekeeper taxonomy; header `2` is
  `VERSION_UNSUPPORTED`.
- Tests: `haze/tests/sdk-types.test.mjs`.

## T3.2 Implementation Notes

- No seventh Rust package and no production proving keys. T3.2 stays in `haze/sdk/typescript/src/`.
  Rust `haze-protocol` remains the codec/vector source of truth; TypeScript ports the codecs.
- Address binary is `HZAV` + version 1 + `u64be` chain + `application_id` 32 + `pool_version` 32 +
  note public key 32 + X25519 32 + first 4 of `keccak256("haze/avalanche/v1/address" || prior)`.
  Text is `haze1:` + unpadded base64url. Padded `=`, wrong magic, field-range, low-order X25519,
  checksum, and trailing bytes fail closed.
- Poseidon2 in TypeScript is the reviewed zkhash t=3 path (8 full + 56 partial, S-box `x^5`,
  external circ(2,1,1), internal `[2,1,1]/[1,2,1]/[1,1,3]`), not the Circom diagonal multiply.
  Constants live in `poseidon2-rc3.json`. Sponge is width-3 `pad10*` with domain in capacity.
- Recipient HPKE is RFC 9180 Base X25519 / HKDF-SHA256 / ChaCha20Poly1305. Open matches the
  committed `recipient_hpke_seal_open` vector via labeled `DeriveKeyPair`. Protocol text prefers a
  reviewed HPKE library; this port uses Node `chacha20-poly1305` plus `@noble/curves` X25519 so the
  sealed vector opens without adding a seventh Rust crate or a vendor SDK.
- Recipient AAD is `chain_id || pool || pool_version || application_id || output_index ||
  output_commitment || envelope_version`. Tampering `event.commitment` alone therefore fails
  `CIPHERTEXT_INVALID`. `COMMITMENT_MISMATCH` is reserved for an envelope that opens under the
  advertised commitment but whose plaintext fields hash to a different note commitment.
- `deriveVaultAccount` reuses T1.3 `deriveShieldedAccount` and adds Poseidon note/encryption keys.
  `x25519Secret` is the labeled 32-byte IKM, not the clamped scalar. Smart-wallet recovery adapters
  throw T0.2 `RECOVERY_UNSUPPORTED` (distinct from prover `UNSUPPORTED_RECOVERY`).
- Local vault blob is `HZVL` || version 1 || 12-byte nonce || ciphertext || 16-byte tag, keyed by
  `localVaultKey`, AAD `chain_id || application_id || pool_version`. Store key
  `haze/vault/${chainId}/${applicationId}`. Secrets are never written in plaintext; `clearSecrets`
  zeros retained buffers and the in-memory vault key.
- Event identity is `${chainId}:${txHash}:${logIndex}`. Duplicates are ignored. `applyReorg(n)`
  keeps only `finalized && blockNumber <= n`. Wipe + re-derive + replay recovers the same notes.
- Tests: `haze/tests/vault.test.mjs`. `E2E-10` remains T5.2/T6.2.

## T3.3 Implementation Notes

- No seventh Rust package and no production proving keys. T3.3 stays in `haze/sdk/typescript/src/`.
  Production spend proving remains `KEYS_MISSING`; workflows call `proveDevelopment` only.
- `createWorkflowClient` orchestrates quoting → authorizing → proving → submitting → finality for
  `direct-shield`, `swap-and-shield`, `private-send`, `withdraw`, `emergency-exit`, and
  `exit-and-reshield`. Public-surface warnings are listed per kind (swap, deposit, withdrawal,
  wallet address, gas).
- Wallet, policy, finality, and clock are provider-neutral interfaces. Calldata used by tests is
  selector plus the authorization nonce; the wallet adapter is not ethers/viem.
- Cancel during `proveDevelopment` returns `ProverError CANCELLED` and does not consume the
  authorization nonce. Wallet `REJECTED` and gatekeeper `USER_INELIGIBLE` fail closed the same way.
  `AUTHORIZATION_EXPIRED` is checked against `clock()` before `wallet.send`.
- Slippage and expired quotes are `QUOTE_STALE`; a down adapter is `UNAVAILABLE`. Private send
  binds the recipient `haze1` address and rejects `APPLICATION_MISMATCH`.
- Stale policy (`POLICY_STALE` on first send) resyncs a new snapshot, re-authorizes, and re-proves.
  Roots on the old authorization are never rewritten. A reorg retries the same authorized packet
  without a second nonce.
- Emergency exit skips the gatekeeper even if it would deny `USER_INELIGIBLE`. Execute before the
  seven-day cooldown is `TIMELOCK`. `EMERGENCY_SELECTORS.executeEmergencyExit` is the Foundry
  selector for the packed `ExecuteArgs` tuple.
- Exit-and-reshield is a public withdraw then a separately authorized deposit into
  `replacementPool` (`linkage: true`, two authorizations).
- Tests: `haze/tests/workflow.test.mjs`. Full-system `E2E-01`/`02`/`03`/`04`/`09`/`11`/`13` remain
  T5.2/T6.2.

## T3.4 Implementation Notes

- No seventh Rust package and no production proving keys. T3.4 stays in `haze/sdk/typescript/`.
  `proveSpend` remains `KEYS_MISSING`. Spend Groth16 P95 is T6.3; production keys are T7.4.
- `prover-session.ts` is the node-free session, derivation, verify, and
  `handleProverWorkerMessage` surface. HMAC-SHA256 uses transitive `@noble/hashes` so the worker
  import graph has no `node:` builtins. `hashArtifactSet` stays in `prover.ts` with `node:fs`.
- `prover-worker.ts` imports only `prover-session.ts`. The package exports `./worker` to that file.
- `createBrowserProver` posts `prove-development` / `prove-spend` / `cancel` / `clear`, maps worker
  `{ type: "error", code }` to `ProverError`, and reports `stages()` / `onProgress`. Cancel posts
  `{ type: "cancel" }` before prove so the worker does not emit a proof.
- `createArtifactCache` is hash-keyed. Unknown hash is `ARTIFACT_INVALID`.
  `selectCircuitArtifact("production", development/not_for_production, …)` is `SdkError
  VERSION_UNSUPPORTED`, matching Rust `select_circuit_artifact`. Hash mismatch is
  `ProverError ARTIFACT_INVALID`.
- Package license is Apache-2.0. Public dependencies remain only `@noble/curves` (MIT). README and
  `examples/direct-shield.mjs` document `createBrowserProver`, `createWorkflowClient`,
  `KEYS_MISSING`, and Web Worker use without vendor names.
- `haze/dev/artifacts/proving-benchmark.json` records development-equality via the worker
  (`worker: true`, `p95_target_ms: 15000`, `spend_keys: "T7.4"`,
  `reference_desktop: "local-development"`).
- Tests: `haze/tests/browser-prover.test.mjs`. Full-system browser E2E remains T5.2/T6.2.

## T5.5 Implementation Notes

- No seventh Rust package and no fourth Node package. `@haze-avalanche/compliance-portal`
  now exports `createGovernanceWorkspace` and `renderGovernanceHtml`. Hosted Next.js
  remains T6.2.
- Governance is super-auditor-only: `signIn` and `/governance` require
  `super-auditor`. Admins, auditors, and pool users cannot open the workspace.
  `/admin` and `/audit` stay closed. Custody `POST /v1/pool/deposit|transact` stays
  forbidden. Super-auditor grants record `custody: false`.
- Portal APIs now apply application scope to governance mutations as well. A
  foreign `applicationId` is `APPLICATION_MISMATCH`.
- Mutation is preview-then-timelock: `previewSchedule` shows exact registry
  target, timelock address, delay, kind, and calldata. `schedule` without preview
  and `execute` before `eta` are `TIMELOCK`. Execute after delay marks the
  operation executed (library `FR-11` / `E2E-08`).
- `protocolStatus` surfaces suspensions, emergency/exit, contract versions with
  artifact hash/provenance, and ceremony transcript (`SC-09`).
- `renderGovernanceHtml` emits an alpine-volcanic static shell. Tests write
  `apps/compliance-portal/public/governance.html`.
- Tests: `haze/tests/compliance-portal-governance.test.mjs` (7). Hosted portal E2E remains T6.2.

## T5.4 Implementation Notes

- No seventh Rust package and no fourth Node package. `@haze-avalanche/compliance-portal`
  now exports `createAuditWorkspace` and `renderAuditHtml` beside the T5.3 admin
  workspace. Hosted Next.js remains T6.2. Governance remains T5.5.
- Investigation is auditor-only: `signIn` and `/audit` require `application-auditor`.
  Admins, pool users, and super-auditors cannot open the workspace. `/admin` and
  `/governance` stay closed.
- Institutional sign-in is library SIWE: `startSiwe` / `completeSiwe` map to
  `POST /v1/auth/challenge` and `POST /v1/auth/token`. Assigned cases come from
  injected `auditAuth.listAssigned` and are filtered to the workspace application.
- Search and export go through T5.1 guards plus grant checks. Unassigned or foreign
  cases, extra fields, revoked grants, and expiry fail closed (`UNAUTHORIZED` /
  `AUTHORIZATION_EXPIRED` / `APPLICATION_MISMATCH`). Library `SC-04` / `E2E-07`.
- Personal access history merges disclosure `accessLog` with local denials so both
  allowed queries and field overreach appear.
- `renderAuditHtml` emits an alpine-volcanic static shell. Tests write
  `apps/compliance-portal/public/audit.html`.
- Tests: `haze/tests/compliance-portal-audit.test.mjs` (7). Hosted portal E2E remains T6.2.

## T5.3 Implementation Notes

- No seventh Rust package and no fourth Node package. `@haze-avalanche/compliance-portal`
  now exports `createAdminWorkspace` and `renderAdminHtml` on top of the T5.1 shell.
  Hosted Next.js and a live HTTP listener remain T6.2. Auditor `/audit` is T5.4;
  governance remains T5.5.
- Administration is admin-only: `signIn` and `/admin` require `application-admin`.
  Pool users, application auditors, and super-auditors are denied. `/governance`
  mutations stay out of this workspace.
- Manifest registration uses `parseManifest` / `hashManifest`. Secret keys fail
  `ENCODING_INVALID`. A foreign `applicationId` is `APPLICATION_MISMATCH`. KMS and
  gatekeeper signer status come from injected health adapters.
- T5.1 portal APIs now include admin mutations (`POST /v1/manifests`, delegations,
  cases, application reports, scoped export). Other-application resources stay
  `APPLICATION_MISMATCH`. Custody `POST /v1/pool/deposit` remains forbidden.
- Injected in-process `auditAuth`, `disclosure`, and `indexer` adapters cover
  delegate, create/list cases, scoped export, application transaction reports, and
  revoke. Non-admin mutations throw `UNAUTHORIZED` (`SC-03` / library `E2E-06`).
- `renderAdminHtml` emits an alpine-volcanic static shell (IBM Plex, skip link,
  workspace vs stack layout). Tests write `apps/compliance-portal/public/admin.html`.
- Tests: `haze/tests/compliance-portal-admin.test.mjs` (7). Hosted portal E2E remains T6.2.

## T5.2 Implementation Notes

- No seventh Rust package and no fourth Node package. `@haze-avalanche/privacy-pool-dex`
  now exports `createDexApp` and `renderDexHtml` on top of the T5.1 shell. Hosted Next.js
  and a live HTTP listener remain T6.2, matching T4 library-first services.
- Wallet onboarding is a connector boundary: connect, `REJECTED`, disconnect, and
  `wrong-chain` when `chainId` is not the expected Fuji/C-Chain id. Only a connected
  `pool-user` session may `navigate` DEX routes.
- Workflows compose `createWorkflowClient` (T3.3) plus an encrypted local vault (T3.2).
  Direct shield, swap-and-shield, private send, withdraw, emergency-exit, and
  exit-and-reshield all require `preview(kind)` before `run`; unsigned submits are
  `REJECTED`. Public warnings include deposit/swap/withdrawal amounts, wallet address,
  gas, and version-migration linkage.
- App-scoped `haze1:` addresses come from `deriveVaultAccount` + `encodeHazeAddress`.
  Cross-application recipients stay `APPLICATION_MISMATCH`. Emergency execute before
  the seven-day cooldown is `TIMELOCK`. Stale or missing quotes are `QUOTE_STALE` /
  `UNAVAILABLE`. Wallet reject during submit and prover cancel leave no local note.
- History, wipe, and recover replay `noteEvents` through `createLocalVault`. After a
  finalized shield or swap-and-shield the screen lists a private note.
- `renderDexHtml` emits an alpine-volcanic static shell (IBM Plex, skip link, `role` /
  `aria-live` / `tabindex` contracts, no portal `/admin` links). Layouts stack below 720px.
- Tests: `haze/tests/privacy-pool-dex.test.mjs` (11). Hosted browser/contract E2E remains T6.2.

## T5.1 Implementation Notes

- No seventh Rust package and no fourth Node package. Shared UX lives in
  `haze/apps/_shared/ux.ts` and is re-exported by `@haze-avalanche/privacy-pool-dex` and
  `@haze-avalanche/compliance-portal`. Next.js and live HTTP remain T6.2.
- Visual language is alpine-volcanic (warm volcanic ink, glacier primary, IBM Plex). Tokens
  reject Stellar gold `#FDBE2C`, parent-app blue `#3F8AFF`, and Stellar/Soroban/Freighter
  copy. Body/large/primary pairs compute WCAG 2.1 AA contrast in-process.
- Roles match audit-auth: `pool-user`, `application-admin`, `application-auditor`,
  `super-auditor`. DEX routes are user-only. Portal `/admin`, `/audit`, and `/governance`
  are role-bound. Hiding a nav item still returns `FORBIDDEN`, not `NOT_FOUND`.
  Cross-application portal reads are `APPLICATION_MISMATCH`. Super-auditors have no
  `POST /v1/pool/deposit` or `transact` custody.
- Privacy glossary marks swap, deposit/withdrawal amounts, application affiliation, gas, and
  version migration as public. `lintPrivacyCopy` rejects “private swap” and
  cross-application anonymity claims. Library-level `E2E-12`; hosted copy review remains
  T5.2/T7.2.
- Primitives carry `role`, accessible name, `tabIndex`, focus restore, and `aria-live`.
  Layouts are stack/split/workspace at 720/1080. Threat model forbids witness and plaintext
  note logs and treats CSP `default-src 'self'` as the frontend baseline.
- Tests: `haze/tests/frontend-ux.test.mjs` (12). Full hosted DEX/portal E2E remains T6.2.

## T4.5 Implementation Notes

- No seventh Rust package and no live PostgreSQL or vendor adapters. Shared persistence and
  operations live in `haze_protocol::ops`. Committed SQL is
  `haze/dev/postgres/migrations/0001_init.sql` plus `0002_ops.sql`
  (`haze_idempotency`, `haze_checkpoints`, `haze_retention`, `haze_compat`). The in-memory
  `MigrationCatalog` applies and rolls back the same table set.
- Compatibility pin is `SCHEMA_VERSION=2`, `API_VERSION=v1`, `CIRCUIT_VERSION=spend-v1`,
  `CONTRACT_FAMILY=avalanche-c-chain`. Mismatch is `VersionUnsupported`.
- Library-first: `health()` is `GET /health` (`Live` / `Stopping`) and `ready()` is
  `GET /ready` (`Ready` / `NotReady`). Constructors bootstrap schema 2 so T4.1–T4.4 tests
  stay ready. Shutdown and not-ready map to each service's `UNAVAILABLE`, not
  `ProtocolError::VersionUnsupported` (which would become `POLICY_STALE` on the gatekeeper).
- `IdempotencyStore` is first-write-wins; a conflicting body is `DomainMismatch`.
  `WriteOnceRetention` rejects overwrite. `DurableStore` backup/restore checks schema.
  `OpsLog` records only redacted fields plus `trace_id`. `Metrics` counts durations against
  `SERVICE_P95_TARGET_MS` (500) in-process; hosted HTTP P95 remains T6.3.
- Replicas share idempotency, durable, and retention via `ServiceOps::replica`. Indexer
  `observe_head` writes `checkpoint/head`. Disclosure `append_log` copies each access-log
  hash under `access-log/{application}/{seq}`. `MemoryKms::rotate_key` keeps historical
  unwraps and returns `rotation_id`.
- Tests: `haze/crates/protocol/tests/ops.rs` (10), disclosure 16, gatekeeper 30, indexer 28,
  audit-auth 20. Full-system E2E remains T5.2/T6.2. Live HTTP listeners remain T5.2/T6.2.

## T4.4 Implementation Notes

- No seventh Rust package and no vendor SDKs. Converted the existing empty `haze-disclosure`
  binary into lib+bin. Public unwrap stays on `haze-protocol::KeyManagement` (no AWS KMS
  types). `MemoryKms` is the in-process adapter.
- Library-first: `Disclosure::query` is `POST /v1/disclosures/query`, `export` is
  `POST /v1/disclosures/export`, `access_log` is `GET /v1/access-log`. `main.rs` is an empty
  binary with that documented; a live HTTP listener remains T5.2/T6.2.
- Disclosure revalidates via `AuditAuth::authorize` (`disclosure` audience, application,
  case, fields). Unfinalized or reorged records are `REJECTED`. Super-auditor still requires
  a per-application KMS case policy or disclosure is `REJECTED`.
- Decrypt path: unwrap IKM, `Envelope::from_bytes`, `audit_aad` + `open_base`,
  `decode_audit_record`, recompute `audit_data_commitment` and `envelope.hash()`. Mismatch
  is `INTEGRITY_FAILURE`, not a partial disclosure. Response is field-redacted and never
  includes the hidden audit salt.
- Exports are signed with keccak-256 over a canonical body, expire, and fail
  `verify_export` on mutation or expiry. Access logs are hash-chained and write-once;
  deletion, reorder, and modification are `INTEGRITY_FAILURE`. Logs never include
  plaintext, IKM, or tokens.
- KMS outage is `UNAVAILABLE`. Tests: `haze/services/disclosure/tests/disclosure.rs` (13).
  Full-system `E2E-07` remains T5.2/T6.2.

## T4.3 Implementation Notes

- No seventh Rust package and no vendor SDKs. Converted the existing empty `haze-audit-auth` binary
  into lib+bin inside the same workspace member. Public identity intake stays on
  `haze-protocol::IdentityProvider` (no Auth0/Okta/Cognito/`siwe` crate).
- Library-first: `AuditAuth::challenge` is `POST /v1/auth/challenge`, `token` is
  `POST /v1/auth/token`, `create_case` / `update_case` are `POST/PATCH /v1/cases`, plus
  `delegate`, `revoke`, and `authorize` for T4.4 grant evaluation. `main.rs` is an empty binary
  with that documented; a live HTTP listener remains T5.2/T6.2. Disclosure, KMS, exports, and
  access logs remain T4.4.
- `MemoryIdentity` implements `IdentityProvider`. Fail-closed: identity outage is `UNAVAILABLE`;
  rejected IdP is `USER_INELIGIBLE`; session past `expires_at` is `AUTHORIZATION_EXPIRED`.
  Membership on a different application is `APPLICATION_MISMATCH`.
- One-time EIP-4361 SIWE is constructed in-process. `personal_sign` recovers
  `\x19Ethereum Signed Message:\n` + len + message via keccak256 and secp256k1 (`v ∈ {0,1}`).
  Challenge replay, SIWE reuse, and recovered-wallet mismatch are `REJECTED`.
- Tokens are short-lived, audience-bound (`cases` / `disclosure`), and scoped by organization,
  role, application, optional case, fields, time, and wallet. Super-auditor grants remain
  application-scoped; KMS bypass is T4.4.
- `ApplicationAdmin` / `SuperAuditor` with audience `cases` create/approve cases and delegate
  only `ApplicationAuditor`. Auditors cannot create cases. `authorize` intersects token, case
  assignment, fields, and expiry. Revoked tokens are `REJECTED`; expired tokens/cases are
  `AUTHORIZATION_EXPIRED`.
- Logs record only `code`. Tests assert assertion, token, and `oidc-secret` strings never appear.
- Tests: `haze/services/audit-auth/tests/audit_auth.rs` (19). Full-system `E2E-05`–`E2E-07`
  remain T5.2/T6.2.

## T4.2a Implementation Notes

- No seventh Rust package and no vendor SDKs. Shared artifact/verify lives in `haze-protocol`.
  Public Haze non-membership is `Indexer::haze_witness` (`GET /v1/policy/haze-witness` semantic).
  Authenticated membership is `Gatekeeper::application_witnesses`
  (`POST /v1/policy/application-witnesses` semantic). HTTP listeners remain T5.2/T6.2.
- Global blocklist is a fixed-depth sorted Merkle tree on `BLOCK_TREE`. Leaves are unique subjects
  in ascending order with index-0 lower sentinel `0` and last-index upper sentinel `BN254_R-1`.
  `BlocklistArtifact::from_subjects` rejects missing sentinels, unsorted lists, and duplicates.
- `artifactHash` is `keccak256` of packed 32-byte subjects. `PolicyScheduled` persist stores bytes
  under `haze/{chain}/policy/{version}/artifact` only when the hash matches. Reconstruction
  requires matching hash and `root()`.
- Non-membership is adjacent lower/upper inclusion paths. `verify_non_membership` checks both
  `BLOCK_TREE` paths, `upper_index = lower_index + 1`, `lower < subject < upper`, and rejects
  sentinel queries. Membership paths verify against `APP_TREE`.
- `require_live_policy` wraps `policy_is_live` with no grace period (`VERSION_UNSUPPORTED` /
  `POLICY_STALE`). Indexer version `0` / zero root mean the live pair. Emergency-exit reconstruction
  uses only public Haze artifacts; `authorize` for action 5 remains `ENCODING_INVALID`.
- TypeScript `applicationMember` / `globalBlockedNote` / `globalBlockedAddress` /
  `requireLivePolicy` match the committed subject hashes. Circom test mains witness blocked note
  and address gadgets. Foundry pins the three committed field hexes.
- Tests: `haze/crates/protocol/tests/policy_witness.rs` (11), indexer 26, gatekeeper 29.
  Full-system `E2E-09` remains T5.2/T6.2. Production keys remain T7.4.

## T4.2 Implementation Notes

- No seventh Rust package and no vendor SDKs. Converted the existing empty `haze-indexer` binary
  into lib+bin inside the same workspace member. Public types stay on `haze-protocol` plus
  provider-neutral `BlockSource` / `ChainLog` (no ethers/viem/alchemy/infura).
- Library-first: `Indexer::ingest` is one decoded log; `Indexer::sync` pulls a `BlockSource` range
  and advances the head. `main.rs` is an empty binary with that documented; a live HTTP listener
  remains T5.2/T6.2. Policy-witness reconstruction is T4.2a.
- Identity is `(tx_hash, log_index)` on the bound `chain_id`. Duplicate delivery with the same
  payload is idempotent; a conflicting payload is `ENCODING_INVALID`.
- Finality is `OBSERVED` until `head >= block + confirmations`, then `FINALIZED`. `reorg(ancestor)`
  marks later records `REORGED` so they are never returned by `query_finalized`. A replacement fork
  can finalize exactly one successor record.
- Private-transaction audit bytes must be a purpose-`Audit` envelope whose `hash()` matches
  `audit_ciphertext_hash`; recipient slots must match `keccak256(bytes)`. Hash or envelope mismatch
  is `CIPHERTEXT_INVALID`. Ciphertexts persist under application-partitioned `ObjectStore` keys.
- Finalized read models: application membership root/version, Haze policy version/root, and router
  token allowlist. Observed/reorged events do not update those views.
- Restart uses `snapshot()` / `restore()` plus the shared object store. RPC outage is `UNAVAILABLE`;
  a later `sync` resumes without duplicates. Logs record only `code`, `kind`, and `status`.
- Tests: `haze/services/indexer/tests/indexer.rs` (21). Full-system indexer E2E remains T5.2/T6.2.
  Event-query P95 (`SC-07`) remains T6.3.

## T4.1 Implementation Notes

- No seventh Rust package and no vendor SDKs. Converted the existing empty `haze-gatekeeper` binary
  into lib+bin inside the same workspace member. Public types stay on `haze-protocol` (no
  ethers/viem/alchemy/infura/aws-sdk).
- Library-first: `Gatekeeper::authorize` is the `POST /v1/authorizations` semantic. `main.rs` is an
  empty binary with that documented; a live HTTP listener remains T5.2/T6.2, not T4.1.
- `MemoryIdentity` implements `IdentityProvider`. Fail-closed: identity/signing-key/audit-pk outage
  is `UNAVAILABLE`; rejected or ineligible KYC is `USER_INELIGIBLE`; session past `expires_at` is
  `AUTHORIZATION_EXPIRED`. Inactive application status is `USER_INELIGIBLE`.
- Client intent must carry zero `audit_data_commitment` / `audit_ciphertext_hash`. The gatekeeper
  samples a nonzero field-range salt, encodes RFC 8949 `AuditRecord` (`facts` + `case_tag`), HPKE
  Base-seals to the application audit **public** key (`AUDIT_INFO`), fills the intent, and signs
  `ApplicationAuthorization` (EIP-712 pool domain). Recoverable secp256k1 `v ∈ {0,1}` matches
  `haze-prover` and `HazePool` `ecrecover`.
- Emergency exit is `ENCODING_INVALID` (the exit path skips the gatekeeper). Contradictory client
  audit fields, action 5, and binding mismatches fail closed the same way.
- Live policy/membership/blocklist versions and roots must match; non-deposit/non-swap also binds
  the live note-tree root (`POLICY_STALE`). Swap `token_in` must be allowlisted
  (`TOKEN_NOT_ALLOWED`). Amount, rolling velocity, and per-window request rate are
  `LIMIT_EXCEEDED`.
- Eligibility: every real input/output Haze address must be an allowed member and not on the note
  blocklist; public recipients must not be on the EVM blocklist. `block_identity` makes any later
  authorize for that subject `USER_INELIGIBLE`, including new-key re-registration.
- Idempotency fingerprint is session + intent draft (audit zeros) + party values. Same fingerprint
  returns the cached outcome. Distinct requests get unique nonces (counter + ChaCha20 noise).
  `rotate_signer` replaces the key and clears the issued cache so unused old nonces are not reused.
- Logs record only `code` and `action`. Tests assert session, subject, and case-tag strings never
  appear.
- Tests: `haze/services/gatekeeper/tests/gatekeeper.rs` (26). Field-safe fixtures use bytes `< r`
  (for example `[0x13;32]`, not `[0x30;32]`). Full-system gatekeeper E2E remains T5.2/T6.2.

## T2.6 Implementation Notes

- No new production contract and no seventh Rust package. T2.6 is a Foundry invariant + gas-report
  task on the T2.1–T2.5 stack.
- `ProtocolHandler` deploys pool + router + exit together (CREATE nonce `n+1` / `n+2`) and exposes
  deposit, transfer, withdraw, swapAndShield, request/execute emergency exit, register/policy/release
  schedule+activate, pause/unpause, token schedule+activate, and a governance deposit probe.
- Development spend proofs do not bind note values. The handler ghost-accounts live notes
  (amount, nullifier, commitment) and only spends those notes. Request does not mark a note dead;
  transfer, withdraw, and execute do. Fake double-spends are therefore not offered to the pool.
- Invariants: USDC conserved across user/recipient/dex/pool/router/exit/roles/handler; router and
  exit hold no residue; live notes have unused nullifiers and spent notes have consumed ones;
  governance and pause roles cannot deposit as the authorized user.
- Foundry `[invariant] runs = 48; depth = 12; fail_on_revert = false`. Handler functions try/catch
  and early-return so ghost state stays aligned. `targetSelector` whitelist only action selectors.
- Gas report: `haze/dev/artifacts/haze-gas-v1.json` (`not_for_production`, `network=local-foundry`,
  `fuji_required_before_mainnet`). Each action stores `measured` from `gasleft()` and `budget` =
  measured + 15%. Isolated T2.1 `verify()` snapshot remains 15214; the T2.6 wrapper measures ~16480
  around `HazeSpendVerifier.verify` after building public inputs. Pin allows ±64 gas of metering noise.
- Use `vm.getBlockTimestamp()` after warps. Do not schedule the live `poolVersion` as a
  `VersionRegistry` release or `isExitCapable` becomes false while Scheduled.

## T1.2 Implementation Notes

- Spend file is `haze/circuits/src/spend.circom` with test main `haze/circuits/test/spend.circom`.
  Stellar `transaction.circom` remains rejected.
- Actions 1 DEPOSIT, 2 TRANSFER, 3 WITHDRAW, 4 SWAP_AND_SHIELD (deposit-like). Action 5 is out of
  this circuit.
- Dummy slots: `enabled ⇔ value != 0`; disabled fields forced to 0; hasher NonZero uses
  `secret + (1 - enabled)` so dummy slots hash 1.
- Deposit `note_tree_root` and both input nullifiers are zero (not the empty-tree root).
- Always 16 `MerklePath(32)`: 2 input notes, 4 app memberships, 8 note-NM paths, 2 address-NM paths.
- Field compare is 128+126-bit limbs (`FieldLessThan`). Keccak/intent hashes are public limbs only.
- Fixtures live in `haze/circuits/vectors/v1/haze-spend-v1.json` (separate from frozen T0.2 JSON),
  generated by `haze_protocol::spend::build_spend_artifact()`.
- Pinned `n_constraints = 588459` (r1cs header; Circom reports 279764 non-linear + 308695 linear).
- Rust `SparseMerkleTree` builds depth-32 note, app, and 2-sentinel blocklist witnesses.

## T1.1 Implementation Notes

- Circom 2.2.3 is installed locally at `haze/.tools/bin/circom`. PATH may still expose Circom 0.5.46;
  tests refuse anything other than the pinned 2.2.3 binary.
- Reviewed copies of `poseidon2_perm.circom` and `poseidon2_const.circom` live under
  `haze/circuits/src/poseidon2/`. Haze does **not** define `Poseidon2(n)`.
- `poseidon2_sponge.circom` implements the approved width-3 `pad10*` sponge and rejects a zero digest.
- Gadgets: note public key / commitment / nullifier, Merkle parent and depth-32 path, application
  member. Production 2-in/2-out spend circuits are T1.2 (`spend.circom`, not `transaction.circom`).
- `haze/circuits/REJECTION.md` names rejected Stellar artifacts (`transaction.circom`, `policy_tx_*`,
  SMT/ASP, `keypair.circom`, Merkle updater, legacy single permutation).
- Node harness: `haze/tests/circuit-poseidon.test.mjs` plus `haze/circuits/witness.mjs`.
- Rust differential tests: `haze/crates/protocol/tests/primitives.rs` (legacy perm ≠ sponge,
  commitment/nullifier/Merkle/policy, uint160 address field, version/chain/application mismatch).
- CI node job installs Circom 2.2.3 before `npm test --prefix haze`.

## T6.1 Implementation Notes

- Library-first stack assembler in `haze/dev/stack.mjs` (not a fourth Node package or seventh Rust
  crate). `npm run stack --prefix haze` and `node haze/dev/stack.mjs verify` check published hashes.
- Profiles `local` and `ci` share the same fixture graph: `anvil-mock` EVM, development circuit
  manifest, Postgres migrations `0001_init.sql` / `0002_ops.sql`, MockUsdc, malicious-adapter,
  replay-bot, both frontends, two isolated applications, and an `adversary` actor.
- Bootstrap writes `ready.json` plus copied migrations/artifacts into a caller-supplied root;
  teardown removes those files and is idempotent. Runtime directories are gitignored as
  `.stack-runtime/`.
- Published fixture hash lives in `haze/dev/fixtures/stack-manifest.json` (`not_for_production`,
  `profile: development`). Production vendor hostnames are rejected in assembly tests.
- Hosted Anvil, live Docker Compose, and Next.js HTTP remain T6.2.

## T6.2 Implementation Notes

- Library-first acceptance runner in `haze/dev/e2e.mjs` (not a fourth Node package).
  `npm run e2e --prefix haze` executes `E2E-01` through `E2E-13` against the T6.1 in-process stack.
- Scenarios drive `createDexApp`, admin/audit/governance workspaces, quote adapters, emergency
  cooldown, vault recover/wipe, isolation denials, privacy-copy lint, and public version migration
  linkage. Injected failures emit redacted evidence (no signing keys or note secrets).
- Hosted Anvil, live Docker, and Next.js HTTP remain out of scope.

## T6.3 Implementation Notes

- Library-first gates assembler in `haze/dev/gates.mjs`. `npm run gates --prefix haze` verifies
  `haze/dev/fixtures/gates-report.json`.
- `SC-06` records development-equality P95 from `proving-benchmark.json`, local Foundry gas vs
  budget from `haze-gas-v1.json`, and an approved spend-Groth16 deferral to T7.4 (`KEYS_MISSING`).
- `SC-07` measures in-process API and finalized-event-to-query P95 (32 samples). Hosted HTTP remains
  out of scope.
- `SC-08` requires the Foundry invariant suite, T6.2 E2E runner, and a complete SC/FR/E2E
  traceability matrix pointing at existing files.

## T6.4 Implementation Notes

- Library-first security review in `haze/dev/security-review.mjs`. `npm run security-review --prefix
  haze` verifies `haze/dev/fixtures/security-review.json`.
- The assembler inspects ten surfaces: threat model, circuit constraints, EVM attack surface, DEX
  adapter, signature domains, governance, key management, access control, PII/logging, and
  dependencies/licenses. Live checks reject Ownable/proxy paths, treat nav as non-authoritative,
  deny custody APIs, require Apache-2.0 / MIT licenses, and pin independent review `91cfa5ee`.
- Zero open critical or high findings. Five mediums have owners and approved release dispositions:
  `M-01` spend keys (`T7.4`, `KEYS_MISSING`), `M-02` secret-scan scope (`T7.1`), `M-03` Fuji gas
  (`T7.1`), `M-04` hosted HTTP (`T7.1`), `M-05` external audit (`T7.3`).
- Still exactly six Rust packages and three Node packages. No production proving keys or live vendor
  adapters.
- Remediation: `haze/tests/prover.test.mjs` no longer overwrites the SC-06 browser benchmark.
  `haze/dev/gates.mjs` hashes policy/gas budgets, not live proving duration, so the published
  gates fixture no longer flakes across `npm test` runs.

## T6.5 Implementation Notes

- Library-first runbook catalog in `haze/dev/runbooks.mjs`. `npm run runbooks --prefix haze`
  verifies `haze/dev/fixtures/runbooks.json`.
- Ten procedures: deploy/rollback-by-version, pause, signer/KMS/policy rotation, RPC/indexer
  recovery, database restore, app suspension, emergency exit, disclosure incident, user
  communication, and dashboards/alerts. Each names an owner and escalation path.
- Local tabletop inspects T4.5 `DurableStore` backup/restore, `rotation_id`, `HazeAccess.pause`,
  `EmergencyExit` cooldown, and `redactEvidence`. T7.1 completed the Fuji-configured rehearsal.
- Secret-scan now also matches `ghp_` tokens and raw `x25519Secret` hex. T7.1 closed `M-02`.

## T7.1 Implementation Notes

- Library-first Fuji release assembler in `haze/dev/fuji-release.mjs`. `npm run fuji-release --prefix
  haze` verifies `haze/dev/fixtures/fuji-release.json`.
- Public provenance is `haze/deployments/fuji-v1.json`: Fuji `43113`, Circle USDC
  `0x5425890298aed601595a70AB815c96711a31Bc65`, `FUJI_COMPATIBILITY` pins, development ceremony
  artifacts, immutable contract set, configured services/frontends, and dashboards/alerts. The
  package does not broadcast; live RPC stays operator-owned.
- Smoke reuses the T6.1 stack hash and `checkCompatibility`. E2E coverage is the existing
  `E2E-01`–`E2E-13` scenario list. Gas stays the local Foundry candidate with
  `fuji_required_before_mainnet`. Coverage recorded: `SC-01`, `SC-06`, `SC-07`.
- Secret-scan now also matches Slack `xox[baprs]-`, `github_pat_`, Stripe `sk_live_`, and
  `aws[_-]secret[_-]access[_-]key`. `M-02` is remediated. `M-03` live remasure is retargeted to
  T7.5. `M-04` hosted HTTP was remediating in T7.2. Still exactly six Rust packages and three Node
  packages.

## T7.2 Implementation Notes

- Library-first Fuji pilot assembler in `haze/dev/pilot.mjs`. `npm run pilot --prefix haze` verifies
  `haze/dev/fixtures/pilot.json`.
- One representative application `APP_A` (`fintech-payment-payroll`) validates integration against
  the T7.1 Fuji pins, administrator/auditor/governance workspaces, privacy-copy lint, runbook
  operations, vault-wipe recovery evidence, and disclosure reporting. Assets are non-real. Hosted
  HTTP stays `library-first` / operator-owned.
- Coverage recorded: `SC-03`, `SC-04`, `SC-05`. Accessibility and compliance reviews pass from
  existing WCAG/privacy-copy tests. Internal stakeholder sign-off is recorded. `M-04` is remediated
  (removed from open mediums). SC-09 `fuji_pilot.approved` stays false.
- Still exactly six Rust packages and three Node packages. No production proving keys or live
  vendor adapters.

## T7.3 Implementation Notes

- Library-first independent audit assembler in `haze/dev/audit.mjs`. `npm run independent-audit
  --prefix haze` verifies `haze/dev/fixtures/audit.json`. The script is not named `audit` so it
  does not replace `npm audit`.
- Eight surfaces are reviewed: circuits, ceremony tooling, contracts, SDK key handling, services,
  frontends, governance, and operational controls. The spend circuit is frozen at `haze-spend-v1`,
  `n_constraints = 588459`, Circom 2.2.3, and the committed source/r1cs/build hashes.
- Zero open critical or high findings. `M-05` is remediating. Remaining accepted mediums are
  `M-01` (`T7.4`, `KEYS_MISSING`) and `M-03` (`T7.5`, `FUJI_GAS`). The security bug policy lives
  in `haze/SECURITY.md`. Coverage recorded: `SC-08`, `SC-09`.
- SC-09 `independent_audit.approved` stays false. Production spend keys stay `KEYS_MISSING`.
  Still exactly six Rust packages and three Node packages.

## T7.4 Implementation Notes

- Library-first production ceremony assembler in `haze/dev/ceremony-release.mjs`. `npm run
  ceremony-release --prefix haze` verifies `haze/dev/fixtures/ceremony-release.json`.
- Public contribution process is `documented-rehearsed` (not a live MPC). Independent transcript
  verification reuses T1.4 `verifyTranscript` against `haze/dev/artifacts/rehearsal-ceremony.json`.
  The signed rehearsal manifest and `DevelopmentEqualityVerifier` stay `NOT_FOR_PRODUCTION`.
- T7.3 circuit freeze is pinned: `haze-spend-v1`, `n_constraints = 588459`, Circom 2.2.3, and the
  committed source/r1cs/build hashes. Production spend proving stays `KEYS_MISSING`.
- `M-01` is remediating by retargeting `KEYS_MISSING` to T7.5 (operator-owned production keys).
  Remaining accepted mediums are `M-01` (`T7.5`, `KEYS_MISSING`) and `M-03` (`T7.5`, `FUJI_GAS`).
  Coverage recorded: `SC-09`. SC-09 `production_ceremony.approved` stays false.
- Still exactly six Rust packages and three Node packages. No 588459-constraint proving keys.

## T7.5 Implementation Notes

- Library-first operational-readiness assembler in `haze/dev/readiness.mjs`. `npm run readiness
  --prefix haze` verifies `haze/dev/fixtures/readiness.json`.
- Eleven checks: governance-owners, KMS, identity, RPC, backups, monitoring, on-call,
  incident-legal, deployment-manifests, audit-remediation, and ceremony-evidence. Owners and
  providers stay `operator-owned`. Public APIs stay vendor-neutral.
- `haze/deployments/mainnet-v1.json` is the unauthorized 43114 plan (`authorized: false`,
  `broadcast: false`, `spend_prove: KEYS_MISSING`). Production-config smoke rejects Fuji
  compatibility on 43114 (`CHAIN_MISMATCH`) and keeps the development circuit out of production.
- `M-01` and `M-03` are remediating as operator-owned hard stops (not a claim that keys exist or
  that Fuji gas was remasured). Security-review mediums are empty (`verdict: pass`). Audit
  remaining is empty. SC-06 spend Groth16 is `{ status: "operator-owned", reason: "KEYS_MISSING" }`.
  Coverage recorded: `SC-09`. SC-09 `incident_review.approved` and `production_ceremony.approved`
  stay false. `mainnetAuthorized` stays false.
- Still exactly six Rust packages and three Node packages. No production proving keys, live vendor
  adapters, or mainnet broadcast.

## Hosted UI (H0–H5) Implementation Notes

- Local hosted surfaces live in `haze/dev/host.mjs` (`npm run host --prefix haze`). This is not a
  fourth Node package and not Next.js. Profiles: `local` hydrates T6.1 `assembleStack` adapters plus
  `createDexApp` / portal workspaces; `fuji` fail-closes.
- Wallet connector is injected `window.ethereum` only (`/host.js` mock). CSP is
  `default-src 'self'`. Native library `Sign and submit` is wired to `POST /api/run` by the host.
- Portal GET `/admin`, `/audit`, and `/governance` authorize through the portal
  `authorizeRoute(session, path, resource)` wrapper against the workspace session. A first host
  revision called the shared four-arg form and 403ed after a successful `signIn`; the page-level
  assertions in `haze/tests/hosted-ui.test.mjs` catch that.
- Each portal workspace keeps its own session. Signing in as auditor does not clear the admin
  session. Route checks stay role-isolated per workspace; they are not a single shared cookie.
- Fuji attempt (2026-08-18): public `https://api.avax-test.network/ext/bc/C/rpc` returned
  `eth_chainId=0xa869` and Circle USDC `0x5425890298aed601595a70AB815c96711a31Bc65` has bytecode.
  `haze/deployments/fuji-v1.json` still has `broadcast: false`, `spend_prove: KEYS_MISSING`,
  `live_rpc: operator-owned`, and no 20-byte `HazePool` address. `createHost({profile:"fuji"})`
  throws `FUJI_NOT_READY`. No live broadcast, deploy, or proving-key invention. SC-09 stays closed.
- Still exactly six Rust packages and three Node packages.

## Validation Evidence

Evidence below is from a fresh 2026-08-18 T7.5 verification in this worktree. T0.2 through T7.5
are complete. M2, M4, M5, and library-layer M6 are complete. There is no T7.6.

- No new Rust workspace members; still exactly six packages (`haze-audit-auth`,
  `haze-disclosure`, `haze-gatekeeper`, `haze-indexer`, `haze-protocol`, `haze-prover`).
- `cargo clippy --manifest-path haze/Cargo.toml --workspace --all-targets --all-features --
  -D warnings`: exit 0.
- `cargo test --manifest-path haze/Cargo.toml --workspace`: exit 0. Protocol `policy_witness`
  11/11; indexer 28/28; gatekeeper 30/30; audit-auth 20/20; disclosure 16/16; prover 9/9
  (2 ignored write helpers).
- `npm test --prefix haze`: exit 0. 193 Node tests passed, 0 failed (includes 5 T6.1 + 4 T6.2 +
  7 T6.3 + 5 T6.4 + 4 T6.5 + 4 T7.1 + 4 T7.2 + 4 T7.3 + 4 T7.4 + 4 T7.5 tests).
- `node --experimental-strip-types haze/dev/readiness.mjs verify`:
  `readiness-verify ok 0x7680e48d1e65a7f67bde7f4bcc3d0ae47ac8dddff3d33e80358748b067d4e4d6`.
- `node --experimental-strip-types haze/dev/ceremony-release.mjs verify`:
  `ceremony-release-verify ok 0x025aa4aab56781d78f76672311fa7541c44756bb5d2b91cc13515737ac334f01`.
- `node --experimental-strip-types haze/dev/audit.mjs verify`:
  `independent-audit-verify ok 0xfb0347cd05523c5eb7dec1411d0405d7097254abbb6e8bb6d65d7d6f6e7d5b06`.
- `node --experimental-strip-types haze/dev/pilot.mjs verify`:
  `pilot-verify ok 0x36ce386c4c3f9c555eac6b2914f7528b7f9ff1b27f287981d6e536873b3b5af3`.
- `node --experimental-strip-types haze/dev/fuji-release.mjs verify`:
  `fuji-release-verify ok 0x138324aa4dc36c61c0056411e832913601f41a0afa4a260e5bc79fb696a9763d`.
- `node --experimental-strip-types haze/dev/runbooks.mjs verify`:
  `runbooks-verify ok 0x86ac81fd5053564ce3d366f3aaa44bf94e7cb6f31797e289f3e40023ed13952a`.
- `node --experimental-strip-types haze/dev/security-review.mjs verify`:
  `security-review-verify ok 0x55f5bebca26a5167148822d8aa9f11f100886c201edb8634a3c2bc5082394562`.
- `node --experimental-strip-types haze/dev/gates.mjs verify`: `gates-verify ok 0x098de1a328e476bfaf5536c54634fcf25d0d22771ae2264e963a8be1e73fbed1`.
- `node haze/dev/stack.mjs verify`: `stack-verify ok 0xeb11b314bbbc2956cb9765a98094e0fe43a86933af08e431b9b9242cf10943ae`.
- `npm run build --prefix haze/sdk/typescript`: exit 0 (`node --experimental-strip-types --check
  src/index.ts`).
- `node haze/circuits/vectors/check.mjs`: `circom vector harness ok` (included in `npm test`).
- `npx ai-devkit@latest lint --feature haze-avalanche-compliant-pool`: all checks passed.
- `node haze/dev/secret-scan.mjs`: `secret-scan ok`.
- Circom 2.2.3 is pinned at `haze/.tools/bin/circom`. Task tracing unavailable:
  `npx ai-devkit@latest task` is not a command in this environment.

H0–H5 hosted-UI continuation evidence (2026-08-18, this worktree):

- `npm test --prefix haze`: exit 0. 208 Node tests passed, 0 failed (includes 9 hosted-ui and 6
  fuji-live-deploy tests).
- `node --experimental-strip-types haze/dev/host.mjs fuji`: exit 2. Reasons
  `broadcast:false`, `KEYS_MISSING`, `operator-owned-rpc`, `missing-HazePool`.
- Public Fuji RPC `eth_chainId` = `0xa869`. Circle USDC has code. No HazePool address in
  `haze/deployments/fuji-v1.json`.
- playwright-cli session `haze` against `http://127.0.0.1:8787` exercised local DEX (wrong-chain,
  connect, public preview, native Sign and submit finalized, foreign send `APPLICATION_MISMATCH`,
  emergency `TIMELOCK`, wipe/recover), portal 403 then admin/audit/governance, SIWE, scoped export,
  field overreach `UNAUTHORIZED`, glossary public-copy, and `?width=390` `data-layout="stack"`.
  Explorer hashes on the local profile are in-process (`0x11…`), not Fuji C-Chain transactions.

## Live Fuji deploy (development verifier)

Approved 2026-08-18. Not T7.6. Production spend keys stay `KEYS_MISSING`. SC-09 and
`mainnetAuthorized` stay closed. `haze/deployments/fuji-v1.json` still has `broadcast: false`.

- Planner: `haze/dev/fuji-live-deploy.mjs`. Scripts: `haze/contracts/script/DeployFujiLive.s.sol`
  and `ActivateFujiLive.s.sol`. Tests: `haze/tests/fuji-live-deploy.test.mjs`.
- Proving decision: on-chain `HazePool` already calls `HazeSpendVerifier.verify(..., false)` and
  accepts the 32-byte development digest. No production Groth16 keys were generated.
- Broadcast deployer `0xeD37FD0d6F0f69236E7472B36796e133D20EcC32` on chainId `43113`.
- `HazePool` `0x919b338f189B1e564Af34A26fC002138f308f7dE` (create
  `0x2cd6cdefc084dbd716a7809378d7f29a5fa05961b823309a6188c7cb7f89fe9c`, receipt status `0x1`,
  16722 bytes of code). Wired to Circle USDC, predicted router, and predicted exit.
  `NOT_FOR_PRODUCTION() == true`. `minDelay == 1`.
- Application `0x…0a11` is active. Policy version 1 is active
  (`activateRegister` `0x909a43cc…`, `activatePolicy` `0xb79595a2…`).
- Sidecar `haze/deployments/fuji-v1.live.json` records addresses. The hosted `fuji` profile still
  fail-closes on the committed T7.5 package (`broadcast: false`, `KEYS_MISSING`).
## Commercial one-origin frontend (2026-08-18)

Approved override of the two-deployment UI split. Pool and Compliance share one origin.

- Spec: `docs/ai/design/2026-08-18-haze-commercial-frontend-design.md`
- Site controller: `haze/web/packages/ui/src/site.ts`
- Host: `npm run commercial --prefix haze` (`haze/dev/commercial-host.mjs`)
- Next.js app shell: `haze/web/apps/haze`
- Tests: `haze/tests/commercial-frontend.test.mjs` (one origin, wallet-address grants, no public role select, review-then-sign, fail-closed, live planner, fuji-v1 untouched)
- Session: fixture Anvil accounts 0–3 map to pool-user / application-admin / application-auditor / super-auditor. GET `?address=` sets `haze-address`; POST APIs use cookie or connected wallet. `?role=` is a hidden test/dev map onto those fixtures only.
- Wallet: Connect wallet / Disconnect. No public role dropdown. No ack checkboxes — one Review public facts step.
- dappwright: `npm run dappwright --prefix haze` plans local seed `test … junk` only; refuses production seeds and fuji-v1 writes. `--launch` requires optional `@tenkeylabs/dappwright` (not installed; npm test never launches MetaMask).
- Fonts: self-hosted IBM Plex Sans/Mono woff2 via `/fonts/plex.css`.
- Live `/shield?live=1`: `planLiveShieldDeposit` + `encodeLiveDeposit` + `/shield-live.js` (injected wallet only)
- Host APIs: `POST /api/live-deposit/plan`, `POST /api/live-deposit/encode` (sidecar overlay only)
- Live typed-data must include `types.EIP712Domain` (name, version, chainId, verifyingContract).
  Omitting it makes MetaMask 13 hash `EIP712Domain()`; `ecrecover` then misses `gatekeeperSigner`
  and `HazePool.deposit` reverts `UNAUTHORIZED`. Snapshot roots come from on-chain
  `getApplication` / `activeVersion` / `activeRoot` (not dummy `applicationId` / zero blocklist).
- playwright-cli walked `/shield`, `/admin` FORBIDDEN as pool-user, `/admin` as application-admin, `/swap` KEYS_MISSING, `/audit`, `/governance`, mobile 390×844, live sidecar banner
- `fuji-v1.json` remains `broadcast: false`, `spend_prove: KEYS_MISSING`
- 2026-08-20: pool chrome is DEX-first (`data-chrome="dex"`). Home `/shield`. No inspector column.
  See `docs/ai/design/2026-08-20-haze-dex-first-chrome.md`. Operator Fuji withdraw is sidecar-only.

- User shield (development digest, 1 USDC): `DepositFujiLive.s.sol` approved then called
  `HazePool.deposit`. Approve `0x1789ea0044500a4603ca7a3cdd388c4ffa00d005340bc0478a97e9112f223926`
  (status `0x1`). Deposit `0xdbfbeb63cfda4bbd03abf2d55303b758dc950fd33b24733af135611ab81a151e`
  (status `0x1`, block `0x372479f`). Pool USDC `1_000_000`; wallet remainder `19_000_000`.
  Production Groth16 keys were not generated. SC-09 stays closed.

## Check Implementation (Phase 7, 2026-08-20)

Compared shipped `haze/` in worktree `feature-haze-avalanche-compliant-pool` against
`docs/ai/requirements/2026-08-10-feature-haze-avalanche-compliant-pool.md`,
`docs/ai/design/2026-08-10-feature-haze-avalanche-compliant-pool.md`,
protocol v1, T0.2 product-approval packet, commercial frontend design, production-ceremony
design, and planning T0.1–T7.5. Feature slug is `haze-avalanche-compliant-pool` (not
`haze-compliant-pool`). This check did not generate proving keys, flip SC-09, broadcast,
or authorize mainnet.

### Design summary (what shipped)

Shared USDC-only Groth16 BN254 2-in/2-out privacy pool for Avalanche C-Chain/Fuji. Notes bind
application ID. Normal actions require gatekeeper EIP-712 auth. Policy is two-tier ASP
(application membership + Haze blocklist) with no stale-root grace. Spend circuit
`haze/circuits/src/spend.circom` is actions 1–4, 588459 constraints, Circom compiler 2.2.3
with source pragma 2.2.2. Contracts are immutable Foundry Solidity. TypeScript SDK
`createWorkflowClient` covers the six user paths. Services are library-first Rust
(gatekeeper/indexer/audit-auth/disclosure; no HTTP listeners). Frontends: library DEX/portal
plus approved 2026-08-18 one-origin Next.js commercial app. Production spend proving stays
`KEYS_MISSING`. Committed `fuji-v1.json` stays `broadcast: false`. All four SC-09 gates stay
false.

### FR / SC alignment

| ID | Status | Evidence |
|---|---|---|
| FR-01 Pool | Aligned (local/dev) | `HazePool` deposit/transact; 2-in/2-out spend; USDC-only |
| FR-02 Application binding | Aligned | Spend membership on every enabled I/O; cross-app rejected in circuit/SDK tests |
| FR-03 Authorization | Aligned | Gatekeeper constructs EIP-712 intent; pool verifies signature |
| FR-04 Policy | Aligned | Live roots only; no grace (`requireLivePolicy`, `HazeAccess`/registries, policy_witness) |
| FR-05 Swap-and-shield | Aligned (adapter mocks) | `SwapAndShieldRouter`; mock DEX; no live vendor SDK |
| FR-06 Audit binding | Aligned | Gatekeeper builds commitment; circuit recomputes; emergency skips gatekeeper |
| FR-07 Indexing | Aligned (library) | `Indexer::ingest`/`sync`; reorg/idempotency tests |
| FR-08 Auditor access | Aligned (library + mocks) | OIDC/SIWE in `haze-audit-auth`; no live IdP |
| FR-09 Disclosure | Aligned (library + mocks) | Field redaction; super-auditor still needs app KMS case policy |
| FR-10 Portals | Aligned via override | Library apps remain; commercial one-origin is the approved hosted UI |
| FR-11 Governance | Aligned | `HazeAccess` timelock + pause role; registries immutable |
| FR-12 Emergency exit | Aligned with deferral | Seven-day `EmergencyExit`; development 20-input digest; emergency Circom deferred |
| FR-13 Recipient delivery | Aligned | `haze1:` / HPKE in protocol + SDK vault |
| FR-14 Version migration | Aligned | Public withdraw then re-shield; private cross-version deferred |
| SC-01 Fuji six paths | Local/E2E yes; committed Fuji fail-closed | Hosted `fuji` profile exit 2 |
| SC-02 Contract rejects | Aligned | Foundry + Node + Rust negative coverage |
| SC-03 Portal workspaces | Aligned | Admin/audit/governance isolation tests |
| SC-04 Isolation | Aligned | Cross-app denials; super-auditor KMS policy |
| SC-05 Recovery | Aligned | Vault wipe/replay tests |
| SC-06 Proving P95 | Dev-equality recorded; spend Groth16 `KEYS_MISSING` | gates fixture |
| SC-07 Service P95 | In-process recorded; hosted HTTP out of scope | gates fixture |
| SC-08 Coverage | Aligned at library/E2E layer | 255 Node tests; Rust workspace; invariants exist |
| SC-09 Production gates | Closed as required | `mainnet-v1.json` all four `false` |
| SC-10 Privacy copy | Aligned | Privacy-copy tests; public-fact warnings |

### Deviations

| Deviation | Severity | Class | Disposition |
|---|---|---|---|
| Services are lib+bin APIs, not HTTP listeners | Low | Approved override | T4 notes; no `TcpListener`/`axum` in `haze/services` |
| DEX/portal library-first, then one-origin Next.js | Low | Approved override | `docs/ai/design/2026-08-18-haze-commercial-frontend-design.md` |
| Extra npm workspaces `haze/web/apps/*` and `haze/web/packages/*` beyond the three Node packages | Low | Approved override | Architecture test still requires exactly six Rust packages and the original three Node packages (`sdk`, `privacy-pool-dex`, `compliance-portal`). Commercial packages are additional private workspaces, not a fourth required product package |
| Production spend proving `KEYS_MISSING` | Expected | Documented deferral | SC-09 / T7.4 / T7.5; `HazeSpendVerifier.verify(..., true)` reverts |
| SC-09 four gates false; `mainnet-v1.json` `authorized: false` | Expected | Required gate | Do not flip |
| Committed `fuji-v1.json` `broadcast: false`; live sidecar `fuji-v1.live.json` | Expected | Approved split | Hosted `fuji` profile fail-closes on the committed package |
| Development `HazePool` keccak-mod-r Merkle; `HazePoolPoseidon` is a sibling, not an upgrade | Medium accepted | Documented development tree | Comment on `HazePool.sol`; Poseidon live planner refuses keccak pool |
| Emergency Circom deferred; `EmergencyExit` uses 20-input keccak digest | Medium accepted | Documented deferral | Contract `@dev` and T2.5 notes |
| No live vendor DEX/KMS/OIDC/RPC SDK | Expected | Approved constraint | Mock providers; architecture test rejects vendor names |
| Commercial header: wallet grants, no public role dropdown; `?role=` hidden | Low | Approved refinement | Implementation 2026-08-19; tests assert grants. Planning/commercial-design still say “role switcher”; connected wallets with multiple grants see a workspace `<select>` of those grants only |
| Circom sources `pragma circom 2.2.2`; compiler/docs pin 2.2.3 | Low | Toolchain convention | `haze/.tools/bin/circom` is 2.2.3; constraint count 588459 |
| Planning M3 header was unchecked while T3.1–T3.4 were complete | Low | Doc drift | Flipped M3 to `[x]` in this check |
| Planning M7 header remains unchecked while T7.1–T7.5 are checked | None | Intentional | Tasks delivered gates/tooling; SC-09 approvals do not exist, so M7 stays open |
| `node haze/dev/secret-scan.mjs` crashed `ERR_STRING_TOO_LONG` on gitignored ceremony binaries | Low | Tooling follow-up (closed Phase 8) | Scanner now skips `ceremony-private`, `.ptau`/`.zkey`/`.r1cs`/`.sym`/`.wasm`, and files >5 MB |

No deviation is implementation-wrong (return to Execute Plan) or design-wrong (return to `dev-design`).

### Follow-ups (do not do in this phase)

- Keep Circom 2.2.3 at `haze/.tools/bin/circom`.
- Do not generate or commit production spend keys.
- Do not flip SC-09, `fuji-v1.json` `broadcast`, or `mainnet-v1.json` `authorized`.
- Emergency Circom and live vendor adapters remain later work.
- MetaMask `notification.html` connect/account-switch is not playwright-cli acceptance.

### Fresh evidence (this check)

- `npx ai-devkit@latest lint --feature haze-avalanche-compliant-pool`: all checks passed.
- `npm test --prefix haze`: exit 0. `tests 255`, `pass 255`, `fail 0`. `circom vector harness ok`.
- `cargo test --manifest-path haze/Cargo.toml --workspace`: exit 0. audit-auth 20, disclosure 16,
  gatekeeper 30, indexer 28, protocol units + ceremony/dev_env/ops/policy_witness/primitives/
  providers/spend/vectors/verifier, prover 9; 2 ignored write helpers.
- `cargo clippy --manifest-path haze/Cargo.toml --workspace --all-targets --all-features -- -D warnings`:
  exit 0.
- `node --experimental-strip-types haze/dev/host.mjs fuji`: exit 2. Reasons `broadcast:false`,
  `KEYS_MISSING`, `operator-owned-rpc`, `missing-HazePool`.
- `node haze/dev/secret-scan.mjs`: exit 1, `ERR_STRING_TOO_LONG` (reads
  `powersOfTau28_hez_final_20.ptau` / spend zkeys as UTF-8). Scoped equivalent skipping
  `ceremony-private` and files >5 MB: 530 files scanned, `scoped-secret-scan ok`.
- Task tracing unavailable: `npx ai-devkit@latest task` is not a command in this environment.

### Next phase

`dev-testing`, then `dev-review`.

## Write Tests (Phase 8, 2026-08-20)

### What changed

- `haze/dev/secret-scan.mjs` skips directory `ceremony-private`, Groth16/circuit binary extensions,
  and files larger than 5 MB so operator ptau/zkeys/r1cs do not crash UTF-8 reads. Pattern
  detectors are unchanged.
- `haze/tests/dev-foundations.test.mjs` runs the official scanner and requires `secret-scan ok`.
- `haze/tests/verifier.test.mjs` and `HazeSpendVerifierPublicInputBindingTest` reject a
  development proof when pool version, public recipient, public value, intent hash, or audit
  ciphertext hash differs from the submitted public inputs. The binding test is a sibling of
  `HazeSpendVerifierTest` so `testVerifyDepositGasSnapshot` stays 15214.
- `haze/dev/artifacts/haze-gas-v1.json` measured values match current local Foundry
  `gasleft()` (deposit 504243, transfer 205448, withdraw 145527, swapAndShield 382632,
  scheduleRegister 306207). Budgets remain measured + 15%. `fuji_required_before_mainnet`
  stays true. Gates fixture hash updated to
  `0xf454911a26d5159021b7c88a92a5d842011ae15c19403ba6500ce33cf8580f55`.

### Fresh evidence

- TDD revert of the skip restored `ERR_STRING_TOO_LONG`; restoring the skip passed.
- `node haze/dev/secret-scan.mjs`: exit 0, `secret-scan ok`.
- `npm test --prefix haze`: exit 0, `tests 257`, `pass 257`, `fail 0`.
- `forge test --root haze/contracts`: exit 0, `113 tests passed`, `0 failed`.
- `node --experimental-strip-types haze/dev/security-review.mjs verify`:
  `security-review-verify ok 0x55f5bebca26a5167148822d8aa9f11f100886c201edb8634a3c2bc5082394562`.
- `node --experimental-strip-types haze/dev/gates.mjs verify`:
  `gates-verify ok 0xf454911a26d5159021b7c88a92a5d842011ae15c19403ba6500ce33cf8580f55`.
- `npx ai-devkit@latest lint --feature haze-avalanche-compliant-pool`: all checks passed.

### Next phase

`dev-review`.

## Code Review (Phase 9, 2026-08-20)

Holistic pre-push review of shipped `haze/` plus the Phase 8 delta. Findings first.

### Findings

| Severity | File | Issue | Recommendation |
|---|---|---|---|
| None blocking | — | No P0/P1 correctness or secret-commit bugs in the Phase 8 delta. Development equality binds all 29 public inputs via keccak digest; pool `publicInputs()` derives those fields from the signed intent. | Proceed to PR when the operator wants the first commit. |
| Important (accepted deferral) | `haze/contracts/src/HazeSpendVerifier.sol:81-83`, `haze/deployments/mainnet-v1.json` | Production Groth16 stays `KEYS_MISSING`. SC-09 four gates stay false. Committed `fuji-v1.json` stays `broadcast: false`. | Do not invent keys or flip gates. M7 remains open. |
| Important (accepted) | `haze/circuits/src/spend.circom:113-127` | `intentHash*` and `auditCiphertextHash*` are range-checked only. Binding is Groth16 public inputs / development digest, not algebraic equality. | Keep the Phase 8 mismatch tests. Do not treat development equality as a production VK. |
| Important (accepted) | `haze/contracts/src/HazePool.sol`, `haze/deployments/fuji-v1.live.json:24-25` | Development pool is keccak-mod-r Merkle; live sidecar aliases `HazePool` to the Poseidon deployment. | Operators must not load the sidecar as the committed Fuji package. |
| Follow-up | `haze/dev/secret-scan.mjs:21` | `walk()` skips every dotfile, so a local `.env` is never scanned. CI still relies on gitignore for `.env`. | Later: scan `.env*` while still skipping `.git` / `.tools`. Do not weaken pattern detectors. |
| Follow-up | `haze/dev/secret-scan.mjs:9` | Files larger than 5 MB are skipped (needed to avoid `ERR_STRING_TOO_LONG`). | Acceptable for ceremony binaries; a huge text dump would also be skipped. |
| Follow-up | MetaMask `notification.html` | E2E-05/06 connect/account-switch still unclaimed. | Do not fake connect or use `?role=` as acceptance. |
| Nice-to-have | `HazeSpendVerifier.sol:87-88` vs `prover-session.ts:451-452` | Digest mismatch is `ENCODING_INVALID` on-chain and `PROOF_INVALID` in TypeScript. | Leave unless a shared taxonomy pass is scheduled. |

### Checklist

- Design match: yes, with the approved overrides recorded in Phase 7.
- No logic gaps in the Phase 8 secret-scan skip or public-input binding tests.
- Security: production keys missing; SC-09 closed; committed Fuji does not broadcast.
- Integration: Node 257, Foundry 113, gates and security-review fixtures verify.
- Tests cover the Phase 8 changes. MetaMask connect remains out of playwright-cli.
- Docs updated for Phases 7–9.

The feature is ready to push as a **development / library** checkpoint. It is **not** ready for mainnet activation.

### Fresh evidence

- `npx ai-devkit@latest lint --feature haze-avalanche-compliant-pool`: all checks passed.
- `npm test --prefix haze`: exit 0, 257 pass / 0 fail.
- `forge test --root haze/contracts`: exit 0, 113 pass / 0 fail.
- `node haze/dev/secret-scan.mjs`: `secret-scan ok`.
- `node --experimental-strip-types haze/dev/gates.mjs verify`:
  `gates-verify ok 0xf454911a26d5159021b7c88a92a5d842011ae15c19403ba6500ce33cf8580f55`.
- `node --experimental-strip-types haze/dev/security-review.mjs verify`:
  `security-review-verify ok 0x55f5bebca26a5167148822d8aa9f11f100886c201edb8634a3c2bc5082394562`.
- Task tracing unavailable: `npx ai-devkit@latest task` is not a command.

### Next phase

`dev-pr` / first commit when the operator is ready. Do not flip SC-09, `fuji-v1.json` `broadcast`, or `mainnet-v1.json` `authorized`.

## D7 Browser Spend Implementation (2026-08-21, uncommitted)

- Replaced the legacy withdrawal-only live runner with a D7 production acceptance runner locked to
  `https://haze-mu-flax.vercel.app`. It rejects every alternate origin, accepts the exact policy
  authority key only through `PRIVATE_KEY`, deletes that environment entry after capture, and never
  records key material, wallet approvals, or transaction payloads.
- The runner creates one fresh headed Chromium/MetaMask profile, imports and verifies the exact Fuji
  authority wallet, performs `/shield`, reloads after the persisted deposit hash, records encrypted
  IndexedDB recovery, then performs `/withdraw` against that same profile and requests wallet-scoped
  disclosure without conflating its result with transaction confirmation.
- Attempt 1 exposed an environment compatibility edge before browser launch: `PRIVATE_KEY` was a
  valid unprefixed 32-byte hex value. A focused regression now requires both prefixed and unprefixed
  forms; the runner validates either and adds the prefix only to the in-memory MetaMask import value.
- Attempt 2 exposed a MetaMask navigation compatibility edge before any Fuji transaction: the
  imported-account flow did not return to the account home expected by dappwright's network helper.
  The runner now unwinds through current back/escape controls until the account-options control is
  visible before switching networks. This correction is locally regression-tested but was not used
  for a third live attempt because D7 explicitly caps deployed acceptance at two attempts.
- The subsequent non-transactional deployed inspection is recorded as the third pre-transaction
  failure: `renderHazePage` supplied a complete standalone document to `dangerouslySetInnerHTML`
  inside the Next document. Browser parsing and React hydration disagreed, causing `/shield` and
  `/withdraw` to disappear after initial paint. A production-build Chromium check then exposed a
  second blocker: the static CSP rejected Next's inline hydration bootstrap. The repair permits
  that framework bootstrap, resolves Plex font URLs through the imported global stylesheet, adds an application-only fragment,
  preserves the complete standalone commercial document, emits one Fuji mount slot with no legacy
  controls or `KEYS_MISSING` state, and portals the sole browser transaction client into that slot.
  D7 wallet selection is scoped to the named Fuji transaction region and exact connect button.
- The authorized gate exception permits deploying this verified UI repair before D7 solely to
  validate the production artifact and non-transactional hydration/reload behavior. Once verified,
  the post-fix headed budget resets to at most three attempts, with diagnosis, regression, gates,
  exact-SHA deployment, and reporting required between failures.
- Post-fix attempt 1 remained CPU-active in the Haze renderer through the 20-minute deposit
  observation window and terminated `D7_DEPOSIT_TIMEOUT` without an observed transaction. The
  corrective runner doubles the bounded proving window to 40 minutes and emits only route, status,
  error code, and observed transaction kinds on terminal deposit failure.
- Post-fix attempt 2 stopped before transaction submission because MetaMask rendered an
  `alert-modal` above the confirmation footer and Playwright correctly refused the obscured click.
  The final-attempt correction detects and dismisses that modal before selecting confirmation controls.
- A page-bound observer retains only transaction hash, destination, and four-byte selector. The final
  evidence enriches those observations from Fuji receipts with status, block, decoded matching
  `PrivateTransaction` fields, and Snowtrace links, then writes redacted JSON plus deposit-recovery,
  withdrawal, and disclosure screenshots under `haze/output/playwright/`.
- Added browser-random note, blinding, action-reference, audit-salt, and independent recipient/audit
  HPKE seeds. The browser derives the note X25519 public key, seals the recipient record, derives
  canonical audit facts, seals the Rust-compatible CBOR audit record to the published Fuji audit
  key, and rebuilds the final witness with the real envelope bytes and hashes.
- Added browser-safe Groth16 proof encoding, Fuji spend ABI encoding, gatekeeper EIP-712 planning,
  ERC-20 approval encoding, and membership-root update encoding.
- The Fuji client now reconstructs ordered note leaves from `PrivateTransaction` logs, updates the
  application membership root with the exact policy-authority wallet, waits for a successful receipt,
  refetches the incremented version, proves with immutable verified artifacts in a Web Worker, signs
  in the connected wallet, waits for approval, performs a final `eth_call`, persists submission before
  broadcast, and confirms only a status-1 receipt with the matching event.
- Withdrawal uses the persisted deposit note and leaf index, preserves it for missing/reverted/mismatched
  receipts, and consumes it only after matching confirmation. Submitted operations retain the actual
  transaction hash for restart recovery.
- Wallet disclosure uses the exact Rust `WithdrawalDisclosure` typed data and only service-supported
  fields (`user`, `amount`, `counterparty`, `tx_hash`, `policy_version`). Transaction and disclosure
  states remain independent, including after recovery.
- Webpack pins `web-worker` to its browser implementation; the production worker graph no longer pulls
  the Node fallback. No localhost, `?live=1`, server-side proving, or filesystem recovery path was added.
- No commit, push, deployment, or ceremony action was performed. D7 remains open until fresh deployed
  Chromium deposit/restart/withdraw/disclosure evidence exists.

### Fresh local evidence

- `npm test` from `haze/`: 312 passed, 0 failed; `circom vector harness ok`.
- `cargo test --workspace`: exit 0; two fixture-writing tests ignored, no failures.
- `cargo build --release -p haze-disclosure`: exit 0.
- `cargo clippy -p haze-disclosure --all-targets -- -D warnings`: exit 0.
- SDK build and Next production build: exit 0; Next compiled without the prior Node worker warning.
- `node dev/secret-scan.mjs`: `secret-scan ok`.
- AI DevKit base and feature lint: all checks passed.
- `npm audit --json`: six high / zero critical. Reachability and upgrade follow-up are recorded in
  the testing document; no dependency mutation or force-fix was performed.
