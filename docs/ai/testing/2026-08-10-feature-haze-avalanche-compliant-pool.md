---
phase: testing
title: Haze Avalanche Compliant Pool Testing Strategy
description: Verification strategy for Haze circuits, EVM contracts, services, SDK, and product portals
---

# Haze Avalanche Compliant Pool Testing Strategy

## Deployed Fuji continuation evidence (2026-08-21)

- [x] D6 Vercel packaging TDD: `tests/vercel-deployment.test.mjs` first failed `ENOENT` while
  `.vercelignore` was absent. It passes after excluding `.tools`, ceremony-private material,
  environment files, local dependency/build outputs, and Playwright state from deployment uploads.
- [x] D7 continuation red/green: deployed-browser tests first failed on the absent browser Fuji
  orchestration module, then pass for authority-only membership update, successful-receipt wait,
  post-update version/root binding, approval receipt ordering, final preflight, persistence before
  broadcast, event reconciliation, and withdrawal-note preservation on incomplete outcomes.
- [x] D2 continuation red/green: browser-operation randomness first exposed only three values; it now
  produces six independent 32-byte values for note, blinding, action reference, audit salt, and the
  separate recipient/audit HPKE channels.

- [x] D2 TDD red: the browser-prover suite failed because `generateBrowserSecrets` was not exported;
  the next red failed because `loadFujiArtifacts` did not exist on the browser prover.
- [x] D2 green: `node --experimental-strip-types --test tests/browser-prover.test.mjs` passes 13/13.
  It covers a Node-built-in/`Buffer`-free worker graph, browser CSPRNG secret separation,
  request-scoped progress and success, cancellation, fake-runtime Groth16 compatibility, and
  transfer of manifest-verified WASM/zkey bytes only. The SDK syntax build exits 0.
- [x] D2 audit-envelope browser/Rust compatibility and recipient recovery pass, including wrong
  AAD and non-canonical envelope rejection.
- [x] D3 wallet derivation, encrypted persistence, legal transitions, pre-broadcast persistence,
  and simulated browser-restart recovery pass.
- [x] D4 approval ordering, immediate final `eth_call`, every receipt/event reconciliation outcome,
  note preservation, and transaction-hash/log-scan recovery pass.
- [x] D5 Rust tests cover authorized redaction, unsuccessful receipts, unauthorized fields, wrong
  and expired wallet identities, missing/production keys, application/pool-version/action-reference/
  commitment/envelope/canonical-CBOR failures. The Render client tests cover bounded cold-start
  retries, HTTPS-only origin enforcement, stable errors, and no local fallback.
- [x] Fresh D2-D5 targeted run (2026-08-21): 28 Node tests and 19 disclosure tests pass; SDK build,
  `cargo clippy -p haze-disclosure --all-targets -- -D warnings`, and `git diff --check` pass.
- [x] TDD red: `node --experimental-strip-types --test tests/browser-prover.test.mjs` exited 1
  because `loadFujiProvingArtifacts` was not exported.
- [x] TDD green: the same targeted suite passes 9/9, including URL and byte inputs, exact-size
  rejection, SHA-256 rejection, and rejection of a non-Fuji/non-development manifest.
- [x] SDK syntax build: `npm run build --workspace @haze-avalanche/sdk` exits 0.
- [x] TDD manifest red: `node --test tests/fuji-artifact-manifest.test.mjs` failed `ENOENT` before
  the public manifest existed; the green targeted run passes 10/10 with browser-prover coverage.
- [x] Verified the committed immutable manifest against fresh Vercel Blob downloads. WASM:
  2,611,219 bytes / SHA-256 `0fc940afbd43a8c16b34e2fd7947c4016963cdf120c7ae34d1188666069b5b57`;
  zkey: 280,397,584 bytes / SHA-256
  `374bb2394da985ab824ce61a95b3b3409b71355139f0a6b16fb8e0bff8e508d5`.
- [x] `snarkjs zkey verify` reports `ZKey Ok!`. A fresh full proof has 29 public signals and a
  256-byte Groth16 payload, and the Fuji pairing verifier production-path `eth_call` returns true.
- [x] Fresh release gates: `npm test` passes 275/275 plus the Circom vector harness; `cargo test
  --workspace` passes all Rust suites; the SDK syntax build and Next production build pass. The
  Next gate first exposed and then closed an invalid shared-theme import plus missing explicit
  TypeScript build dependencies.

## Test Coverage Goals

- Cover every acceptance criterion in the requirements and every trust boundary in the design.
- Require 100% branch and failure-mode coverage for new security-critical circuit helpers, contract
  authorization/policy/accounting code, disclosure authorization, and key-handling code. Any
  unreachable generated-verifier branch requires a documented exception.
- Require contract unit, fuzz, and invariant tests; circuit valid/invalid witness tests; Rust service
  unit/integration tests; TypeScript SDK/frontend tests; and full-system end-to-end tests.
- Treat cross-language encoding vectors, authorization replay, value conservation, nullifier
  uniqueness, application isolation, policy freshness, swap atomicity, and disclosure isolation as
  release-blocking test areas.
- Run development proving keys only in local/Fuji tests. Mainnet release tests must verify production
  artifact hashes without publishing toxic-waste material.

## Implementation Evidence

### T0.1 — Haze product boundary

- [x] The architecture test requires independent Haze packages for contracts, circuits, protocol,
  prover, four services, TypeScript SDK, Privacy Pool DEX, Compliance Portal, deployments, and tests.
- [x] Cargo metadata is inspected to reject prohibited network-specific dependencies from every Haze
  Rust package.
- [x] Node manifests and public Rust, TypeScript, Solidity, and Circom imports are inspected for
  prohibited dependencies, including Rust `pub use` and TypeScript re-export forms.
- [x] The minimal Rust, Node, and Foundry package boundaries build independently.
- [x] Protocol and manifest compatibility behavior is assigned to T0.2 (now complete) and is not
  implied by the T0.1 package scaffold.

The first red run failed because all required Haze packages were absent. A second focused red run
showed that the initial detector missed public re-exports; the detector was extended before T0.1 was
accepted. No existing test scenario was invalidated.

### T0.2 — Canonical protocol encodings (complete)

- [x] Rust vector loader fails when `haze/circuits/vectors/v1/haze-protocol-v1.json` is absent, then
  passes against the generated reference.
- [x] Committed artifact equals `build_vector_artifact()`; every negative vector is executed by the
  Rust harness, including low-order X25519, unknown Poseidon labels, `uint48` overflow,
  oversized envelopes, deposit nonzero tree/nullifiers, disabled-slot nonzero, and HPKE open with
  the wrong AAD.
- [x] TypeScript harness recomputes domain Keccak tags, `keccak256(label) mod r` field constants,
  EIP-712 type hashes, limb split, envelope hashes, and parameter-file hashes.
- [x] Circom harness checks Poseidon2 parameters, independently hashes parameter files, and records
  public-input field names. T1.1 extends it to compile Circom 2.2.3 and witness `note_public_key`.
- [x] Solidity harness recomputes EIP-712 type hashes, all 13 domain tags, the Fuji domain separator,
  and intent/authorization struct hashes and typed-data digests via `abi.encode`.
- [x] Independent cryptography and EVM review `91cfa5ee` accepted encodings with follow-ups; those
  follow-ups are implemented. Product approved
  `docs/ai/design/2026-08-17-t0.2-product-approval-packet.md` on 2026-08-17. T0.2 is complete.

New scenarios: padded `haze1:` addresses, zero audit salt, key-domain used as pool domain, Fuji vs
C-Chain mismatch, low-order X25519, unknown Poseidon domain prefix, `uint48` overflow, oversized
HPKE encapsulated keys, deposit zero-rule, HPKE seal/open, wrong-AAD open, RFC 8949 audit CBOR,
HKDF labels, Merkle path/sentinels, pad10* blocks, public-input order, and parameter-file hashes.
No T0.1 architecture scenario was invalidated.

### T0.3 — Provider-neutral interfaces

- [x] Mock DEX returns a deterministic quote and fails closed when unavailable.
- [x] Mock KMS and identity fail closed on outage.
- [x] Mock RPC reports Fuji chain id 43113 without a vendor URL type.
- [x] In-memory object store round-trips ciphertext.
- [x] Architecture test rejects named vendor SDKs in public Rust and TypeScript sources.

No T0.2 vector scenario was invalidated.

### T0.4 — Deterministic development and CI

- [x] Production runtime profile rejects a development circuit manifest.
- [x] Development runtime profile accepts the committed development manifest.
- [x] Toolchain files, staged Haze workflow, secret scan, and Postgres `0001_init.sql` exist.
- [x] Mock USDC uses six decimals; mock DEX swaps source token for USDC.

Adversarial fee-on-transfer tokens and a full local Anvil compose stack remain later T6 work.

### T1.1 — Reviewed privacy primitives

- [x] `haze/circuits/REJECTION.md` names rejected Stellar artifacts, including `Poseidon2(n)` as a
  single permutation. Architecture tests fail if those names appear in `haze/circuits/src`.
- [x] Circom 2.2.3 compiles the v1 sponge and matches committed `note_public_key` and
  `encryption_key_hash` vectors.
- [x] Circom note commitment, nullifier, and application-member gadgets match committed vectors.
- [x] Circom Merkle parent plus a depth-32 path match `merkle_note_path` and `empty_note_root`.
- [x] Rust differential tests prove legacy `Poseidon2(2)` ≠ the v1 sponge, lock commitment /
  nullifier / Merkle / policy, treat EVM addresses as `uint160` fields, and reject version / chain /
  application binding mismatches.
- [x] `node haze/circuits/vectors/check.mjs` independently witnesses `sponge_1` against
  `note_public_key`.

No T0.2 vector scenario was invalidated. T1.2 spend-circuit checklist items below are complete.

### T1.2 — Versioned 2-in/2-out spend circuit

- [x] `haze/circuits/test/spend.circom` public-input names match frozen `NORMAL_PUBLIC_INPUTS`.
- [x] Valid deposit, 2-in/2-out transfer, and variable-value withdraw witnesses succeed.
- [x] Invalid witnesses fail: wrong Merkle root, wrong owner secret, value inflation, mixed
  application id, dummy-slot value, and mismatched audit salt.
- [x] Enabled slots prove application membership and global note non-membership; deposit/withdraw
  also prove address non-membership; dummy slots force zero fields.
- [x] Audit-data commitment is recomputed in-circuit from the 40-field preimage.
- [x] `n_constraints` pinned at 588459 in `haze/circuits/vectors/v1/haze-spend-v1.json`.
- [x] Rust `spend` tests lock the fixture, deposit zero-rule, and two-sentinel blocklist tree.

T0.2 `haze-protocol-v1.json` was not mutated. Policy-registry freshness is T2.2 (complete at the
registry; pool consume remains T2.3). Proving-key artifact hashes are T1.4. Emergency exit is a
separate circuit.

### T1.3 — Rust and browser proving packages

- [x] Derive the same shielded spending, X25519, vault, and membership-blinding keys twice from the
  documented EIP-712 wallet message (Rust and TypeScript against `haze-prover-v1.json`).
- [x] Reject a derivation signature that does not recover the declared wallet (`UNSUPPORTED_RECOVERY`).
- [x] Extract the 29 spend public inputs in frozen Circom order; deposit `noteTreeRoot` is zero and
  action is `"1"`.
- [x] Production profile cannot select the development circuit manifest.
- [x] Spend proving without ceremony keys returns `KEYS_MISSING` (T7.5 owns operator production keys).
- [x] Cancelled sessions do not emit a proof (`CANCELLED`).
- [x] Development equality proof verifies in Rust; TypeScript session records a development proof,
  then `clear()` zeros retained secrets.
- [x] Artifact set hash of `spend.circom` + `haze-spend-v1.json` + development manifest matches the
  committed `artifactHash`.
- [x] Initial development-circuit duration is written to `haze/dev/artifacts/proving-benchmark.json`
  and is below 15000ms. Spend P95 (`SC-06`) remains T6.3.

No T1.2 spend-circuit scenario was invalidated. Production proving-key hashes remain T7.4. Solidity
spend-verifier integration remains T2.1. Local-vault note restore after deletion is T3.2.

### T1.4 — Reproducible artifact and ceremony tooling

- [x] Two clean Circom builds of the development-equality circuit match r1cs hashes.
- [x] Spend circuit-build manifest pins source hash, fixture hash, Circom 2.2.3, and
  `n_constraints = 588459`.
- [x] Rehearsal contribution hash-chain verifies; a broken link is rejected.
- [x] Generated `DevelopmentEqualityVerifier` is `NOT_FOR_PRODUCTION` and hash-gated.
- [x] Signed rehearsal manifest recovers the fixture wallet; tampered payloads fail.
- [x] SC-09 provenance keeps all four gates closed; production activation is
  `VERSION_UNSUPPORTED`.
- [x] Production runbook forbids T7.4 until audit freeze.
- [x] Spend proving remains `KEYS_MISSING`.

### T2.1 — Immutable Groth16 spend verifier wrapper

- [x] Versioned `HazeSpendVerifier` pins 29 public-input names, `SPEND_ARTIFACT_HASH`, and
  `CIRCUIT_BUILD_HASH`.
- [x] Deposit, transfer, and withdraw fixture public inputs verify in Solidity, Rust, and TypeScript
  against the committed artifact hash.
- [x] Field-out-of-range, unknown action, deposit non-zero root/nullifiers, wrong protocol version
  tag, wrong artifact hash, and malformed/mismatched development proofs fail.
- [x] Production selection is `KEYS_MISSING`; no proxy/admin/`upgradeTo`/`initialize` mutation path.
- [x] `verify()` gas snapshot is 15214. Production pairing spend verifier remains T7.4.

No T1.4 ceremony scenario was invalidated.

### T2.2 — Application, policy, and version registries

- [x] Distinct `governance`, `pauseRole`, and timelocked super-auditor capabilities. Pause is
  immediate; super-auditor grants confer no schedule/pause/membership mutation.
- [x] Application register/suspend/reactivate/retire, Haze policy roots, and version publications
  schedule then activate only after `minDelay`.
- [x] Prior application configuration is preserved until activation; provenance events fire.
- [x] App `policy_authority` updates membership roots; Haze governance cannot.
- [x] App admin rotates gatekeeper signer and manifest hash. Suspend leaves keys intact and adds no
  spend/withdraw/transfer path.
- [x] `isActivePolicy` accepts only the live version+root. Activating the next root retires the
  previous one with no grace period (Foundry fuzz included).
- [x] `VersionRegistry` publishes artifact hashes and has no `upgradeTo`/`initialize`/`owner` path.

Emergency-exit contract scenarios shipped in T2.5. `E2E-08` remains later.

### T2.3 — HazePool deposit and private transaction paths

- [x] Deposit pulls exact USDC before inserting a commitment and emits the bound audit/ciphertext
  event.
- [x] Unregistered, pending, suspended, and retired applications are rejected.
- [x] Missing, malformed, wrong-domain, expired, not-yet-valid, and wrong-signer EIP-712
  authorizations are rejected.
- [x] Authorization nonces are consumed once and rejected on replay.
- [x] Direct callers must equal the authorized user. Only the approved router may call
  `depositFromRouter`, with original-payer binding.
- [x] Historical roots in the configured ring are accepted; unknown and expired roots fail.
- [x] Only the live application membership version/root and live Haze policy version/root are
  accepted; activation has no grace period.
- [x] Invalid proofs do not consume nonces or insert commitments; reused nullifiers fail.
- [x] USDC is conserved across deposit, private transfer, and withdraw. Emergency exits are T2.5.
- [x] Duplicate commitments and both-zero deposit outputs are rejected.
- [x] Recipient and audit ciphertext hashes bind the submitted bytes.
- [x] Immutable pool exposes version/artifact hashes and has no proxy path. Action 5 is rejected.

### T2.4 — Swap-and-shield router

- [x] An approved allowlisted source token and adapter swap, then atomically deposit the exact USDC
  balance delta into the intended Haze commitment.
- [x] Unallowlisted tokens/adapters, substituted calldata, mismatched `routeHash`, USDC-as-source,
  wrong action, and stranger callers revert.
- [x] Expired deadlines revert `AUTH_WINDOW`; output below `minUsdcOut` reverts `SLIPPAGE`.
- [x] Invalid proof, suspended application, and pause revert both swap and deposit with no residue.
- [x] Successful routes leave zero residual source and USDC and zero leftover adapter/pool approvals.
- [x] Reentrancy, leftover source, diverted recipient, and missing USDC revert. Fee-on-transfer and
  rebasing sources revert. Allowlist changes are timelocked.
- [x] Frozen `routeHash` vector matches `keccak256(abi.encode(adapter, data))` for adapter `0x1` and
  data `0xaabb`. No proxy, vendor name, or emergency-exit path on the router.
- Full-system `E2E-02` / `E2E-11` remain later (T5.2 / T6.2). T2.6 shipped sustained
  invariants and local gas budgets.

### T2.5 — Pause, emergency exit, and version migration

- [x] Anyone can register an opaque request without proving application outage or suspension.
  Duplicate request ids revert `STATUS_INVALID`. Request does not consume a nullifier.
- [x] Execute before seven days reverts `AUTH_WINDOW` and leaves the nullifier unused. Execute after
  seven days withdraws exact USDC under the live Haze policy.
- [x] Pause blocks pool/router/registry mutations but not `requestEmergencyExit` /
  `executeEmergencyExit`.
- [x] Invalid Haze policy, zero/self/exit recipient, invalid 20-input digest, mismatched audit
  ciphertext hash, reused nullifier, and used request all revert. Failed execute leaves both
  request and nullifier unchanged.
- [x] A normal gatekeeper-authorized withdraw during cooldown succeeds; the later exit then hits
  `NULLIFIER_USED`.
- [x] Governance cannot spend notes or shorten the current request cooldown.
- [x] Suspended and retired applications can still exit. Retired versions stay exit-capable through
  `supportUntil`, then revert `VERSION_UNSUPPORTED`.
- [x] Public withdraw from a retiring pool plus a separately authorized deposit into a replacement
  `HazePool` covers FR-14 MVP migration.
- Contract-level `E2E-09` / `E2E-13` coverage lives in `EmergencyExit.t.sol`. Full frontend E2E
  remains T5.2 / T6.2. Reconstructing Haze non-membership witnesses from public policy
  events is T4.2a (library APIs; no emergency Circom). T2.6 shipped sustained invariants and local gas.

### T2.6 — Protocol invariants and gas budgets

- [x] Foundry `[invariant]` campaign targets a handler covering deposit, transfer, withdraw,
  swapAndShield, request/execute emergency exit, register/policy/release schedule+activate,
  pause/unpause, and token schedule+activate.
- [x] `invariant_usdcConserved` holds across the local stack (user, recipient, dex, pool, router,
  exit, roles, handler).
- [x] `invariant_routerHasNoResidue` and exit residue stay zero.
- [x] `invariant_nullifiersConsumedOnce` matches ghost live/dead notes to `nullifierUsed`.
- [x] `invariant_rolesCannotSpendNotes`: governance/pause cannot deposit as the authorized user.
- [x] Ghost accounting prevents development-proof double-spends of note value.
- [x] `haze/dev/artifacts/haze-gas-v1.json` records local measured gas and +15% budgets for every
  required user/governance action. `fuji_required_before_mainnet` is true.
- Fuji re-measure still required before mainnet. Production Groth16 pairing gas remains T7.4.

### T3.1 — Canonical TypeScript SDK types and transports

- [x] TypeScript EIP-712 types recompute committed protocol type hashes, the Fuji domain separator,
  and deposit intent/authorization struct hashes and typed-data digests.
- [x] EIP-712 validation rejects `uint48` overflow (`FIELD_OUT_OF_RANGE`), nonzero swap fields on a
  deposit, nonzero deposit tree/nullifiers, and a wrong pool domain name (`DOMAIN_MISMATCH`).
- [x] `checkCompatibility` accepts the Fuji pin and rejects C-Chain, schema, API, domain, product,
  circuit, protocol-tag, and manifest version drift.
- [x] SDK error taxonomy includes protocol, contract, and gatekeeper codes; contract messages and
  gatekeeper JSON map to typed codes; unknown gatekeeper codes are `ENCODING_INVALID`.
- [x] Manifest hashing is deterministic; `parseManifest` rejects version drift, secret fields, and
  digest mismatch.
- [x] Static quote adapter is provider-neutral (no `vendorRoute`) and fails closed on slippage and
  unavailability.
- [x] Gatekeeper client uses `POST /v1/authorizations`, `GET /v1/applications/{id}/manifest`, and
  `haze-api-version`; typed denials and API-version drift fail closed.
- [x] Memory transport plus selector bindings read `poolVersion` and `SPEND_ARTIFACT_HASH` and reject
  the wrong chain.

No T2.6 invariant or gas scenario was invalidated. Workflows and production keys remain later
tasks. Vault note restore after deletion is T3.2.

### T3.2 — Non-custodial shielded account and local vault

- [x] Protocol error taxonomy includes `COMMITMENT_MISMATCH` and `RECOVERY_UNSUPPORTED`.
- [x] TypeScript encodes and decodes the committed `haze1:` address and rejects padding, low-order
  X25519, and chain/application/pool-version binding drift.
- [x] TypeScript opens the committed recipient HPKE vector, parses the 200-byte plaintext, and
  hashes the dummy `HZHP` envelope. Wrong AAD is `CIPHERTEXT_INVALID`.
- [x] Note public key, encryption-key hash, and note commitment match `haze-protocol-v1.json`;
  zero blinding is `FIELD_OUT_OF_RANGE`.
- [x] Wallet-derived vault account matches `haze-prover-v1.json` spending, X25519, vault, note, and
  encryption keys. Smart-wallet recovery is `RECOVERY_UNSUPPORTED`.
- [x] Encrypted persist hides spending, X25519, vault-key, and commitment hex; `retainSecret` plus
  `clearSecrets` zeros buffers.
- [x] Wipe + re-derive + replay recovers the same spendable notes (`SC-05` / `FR-13` unit path).
- [x] Duplicate events are ignored. An envelope whose opened plaintext does not recompute to the
  advertised commitment is `COMMITMENT_MISMATCH`.
- [x] `applyReorg` drops unfinalized notes.

`E2E-10` remains T5.2/T6.2. User workflow SDK coverage is T3.3. Production keys remain T7.4.

### T3.3 — User transaction workflows

- [x] Public-surface warnings list swap, deposit, withdrawal, wallet address, and gas per kind.
- [x] Direct shield authorizes, development-proves, submits `deposit`, and finalizes with zero
  deposit tree/nullifiers and a matching authorization `intentHash`.
- [x] Swap-and-shield quotes then submits the router; slippage, expired quotes, and a down adapter
  fail closed (`QUOTE_STALE` / `UNAVAILABLE`).
- [x] Private send binds the recipient Haze address, submits `transact` with a zero public amount
  and recipient, and rejects a cross-application address (`APPLICATION_MISMATCH`).
- [x] Withdraw submits a public recipient amount on `transact` and keeps change private.
- [x] Emergency exit skips the gatekeeper, records `requestId`, rejects execute before seven days
  (`TIMELOCK`), and then submits `executeEmergencyExit`.
- [x] Exit-and-reshield is a public withdraw then a separately authorized deposit into the
  replacement pool (`linkage: true`, two authorizations).
- [x] Cancel during prove is `CANCELLED` and does not consume the authorization nonce.
- [x] Wallet rejection is `REJECTED` without nonce consume. Expired authorization is
  `AUTHORIZATION_EXPIRED` before send. Gatekeeper `USER_INELIGIBLE` issues no authorization.
- [x] Stale policy resyncs and re-proves with a new nonce and new roots (never rewrites the old
  authorization). A reorg retries the same authorized calldata.

Full-system `E2E-01`/`02`/`03`/`04`/`09`/`11`/`13` remain T5.2/T6.2.

### T3.4 — Browser proving and integrator APIs

- [x] The worker module graph (`prover-worker.ts` plus local imports) has no `node:` builtins.
- [x] `createBrowserProver` proves development-equality through a worker, reports `onProgress`
  including `development`, and exposes `stages()`.
- [x] Host `cancel()` then `proveDevelopment` is `ProverError CANCELLED` and does not emit a proof.
- [x] Browser `proveSpend` is `KEYS_MISSING`.
- [x] Artifact set hash of `spend.circom` + `haze-spend-v1.json` + development manifest matches the
  committed `artifactHash`. Cache hit returns the stored bytes; unknown hash is `ARTIFACT_INVALID`.
- [x] `selectCircuitArtifact("production", development/not_for_production, …)` is `SdkError
  VERSION_UNSUPPORTED`. Hash mismatch is `ProverError ARTIFACT_INVALID`.
- [x] Package `license` is Apache-2.0; exports include `.` and `./worker`; `files` include `src`,
  `README.md`, `LICENSE`, and `examples`. README and `examples/direct-shield.mjs` name
  `createBrowserProver`, `createWorkflowClient`, `KEYS_MISSING`, and Web Worker without vendor
  names.
- [x] Direct dependencies remain only `@noble/curves`; lockfile `@noble/curves` and
  `@noble/hashes` are MIT.
- [x] Five worker `proveDevelopment` samples write `haze/dev/artifacts/proving-benchmark.json`
  with `worker: true`, `p95_target_ms: 15000`, `spend_keys: "T7.4"`. Recorded P95 is below 15000ms
  on `local-development`. Spend Groth16 P95 (`SC-06` spend) remains T6.3.

Full-system browser E2E remains T5.2/T6.2. Production keys remain T7.4.

### T4.2a — Independently verifiable policy-witness APIs

- [x] Committed `application_member`, `global_blocked_note`, and `global_blocked_address` fields
  match Circom, Rust, TypeScript, and the Foundry hex pin.
- [x] Sorted blocklist artifacts require both sentinels, unique ascending subjects, matching
  `artifactHash`, and a depth-32 `BLOCK_TREE` root.
- [x] Adjacent-leaf non-membership witnesses verify locally; blocked subjects, sentinels, and
  tampered indexes fail.
- [x] Application membership paths verify against `APP_TREE`.
- [x] `require_live_policy` / indexer `haze_witness` / gatekeeper `application_witnesses` reject
  unknown, future, stale, and mismatched roots with no grace (`VERSION_UNSUPPORTED` /
  `POLICY_STALE`).
- [x] `Indexer::haze_witness` returns verifiable note-key and EVM-address paths after
  `PolicyScheduled` + `PolicyActivated` finality and persists the scheduled artifact.
- [x] An independent Haze policy mirror reconstructs the same witnesses from stored artifact bytes
  without the gatekeeper. `authorize` emergency exit remains `ENCODING_INVALID`.
- [x] Logs record only codes/counts/versions, never artifact hex or secrets.

Library-level `E2E-09` reconstruction is covered here. Full frontend/contract `E2E-09` remains
T5.2/T6.2. HTTP listeners remain T5.2/T6.2.

### T4.3 — Institutional audit authorization

- [x] Mock OIDC/SAML `IdentityProvider` plus one-time SIWE issues an audience-bound token with
  organization, role, application, wallet, field, and time scopes.
- [x] Challenge replay, SIWE reuse, requested-wallet mismatch, and recovered-wallet mismatch are
  `REJECTED`.
- [x] Identity outage is `UNAVAILABLE`; rejected IdP is `USER_INELIGIBLE`; expired IdP/token/case
  is `AUTHORIZATION_EXPIRED`.
- [x] Audience, role, application, case, and overbroad-field denials fail closed. Super-auditor
  grants remain application-scoped.
- [x] Application admin creates/approves a case and delegates an auditor; an auditor cannot create
  a case. Revocation denies later `authorize`.
- [x] Logs record only `code` and never include assertion, token, or signature material.

Library-level `E2E-05`–`E2E-07` auth binding is covered here. Disclosure/KMS/export/access-log
library coverage is T4.4. Full frontend/contract `E2E-05`–`E2E-07` remain T5.2/T6.2. HTTP
listeners remain T5.2/T6.2.

### T4.4 — Disclosure, KMS, exports, and access logs

- [x] Deny cross-application, expired, revoked, overbroad-field, cases-audience, and
  unfinalized/reorged-record disclosure requests.
- [x] Deny a Haze super-auditor when the target application's KMS case policy is absent;
  allow only after the application configures that policy.
- [x] Decrypt with the mock application KMS key, redact ungranted fields, and omit audit
  salt / IKM from responses and access-log views.
- [x] Recompute the canonical audit-data commitment and ciphertext hash after decryption;
  treat stored-commitment mismatch as `INTEGRITY_FAILURE`.
- [x] Record successful and denied decisions without decrypted payloads; detect hash-chain
  mutation and deletion.
- [x] Fail closed on KMS outage (`UNAVAILABLE`). Signed exports carry scope/provenance and
  expire.

Library-level `E2E-07` disclosure is covered here. Full frontend/contract `E2E-07` remains
T5.2/T6.2. HTTP listeners remain T5.2/T6.2.

### T4.5 — Service persistence and operations

- [x] Committed `0001_init.sql` and `0002_ops.sql` match the in-memory catalog; apply
  forward to schema 2 and roll back to empty.
- [x] Incompatible schema or circuit pins fail closed (`VERSION_UNSUPPORTED`).
- [x] Bootstrap becomes ready; shutdown is live-but-not-ready and denies traffic with
  `UNAVAILABLE` on gatekeeper, indexer, audit-auth, and disclosure.
- [x] Idempotent first-write-wins replay; conflicting request hash is `DOMAIN_MISMATCH`.
- [x] Backup/restore rejects a foreign schema; replicas share durable checkpoints and
  idempotency.
- [x] Write-once retention rejects overwrite; disclosure copies access-log hashes into
  retention independent of export plaintext.
- [x] Structured logs record codes/fields/`trace_id` and never include `oidc-secret` or
  private-key material.
- [x] In-process load baseline of 128 idempotent puts stays under the 500ms service P95
  target. Hosted HTTP P95 remains T6.3.
- [x] KMS rotation keeps historical unwraps and returns a deterministic `rotation_id`.

Library-level service reporting and restart coverage is here. Full-system outage and hosted
HTTP remain T5.2/T6.2.

### T5.1 — Haze UX, design system, and authorization boundaries

- [x] Privacy Pool DEX and Compliance Portal remain independently named products and share
  the alpine-volcanic Haze language rather than a Stellar reskin.
- [x] Ordinary pool users cannot load portal routes or portal APIs; DEX `POST /v1/authorizations`
  remains available to `pool-user`.
- [x] Hidden navigation is not authorization: requesting `/admin` without a portal role is
  `FORBIDDEN`.
- [x] Application auditors cannot load governance or other-application disclosure data
  (`APPLICATION_MISMATCH`).
- [x] Application administrators cannot reach other-application or pool-custody controls.
- [x] Super-auditors may open governance but cannot deposit, transact, or obtain DEX
  authorizations.
- [x] Privacy-copy glossary refuses “private” labels for swap, deposit/withdrawal amounts,
  application affiliation, gas, and version migration, and rejects cross-application
  anonymity claims (library-level `E2E-12`).
- [x] Design tokens meet WCAG 2.1 AA contrast; primitives expose name, role, focus restore,
  and `aria-live`; layouts stack below 720px.

Hosted Next.js, wallet, and screen-reader E2E remain T6.2/T7.1.

### T5.2 — Privacy Pool DEX frontend

- [x] Wallet onboarding connects a `pool-user` session, records `REJECTED` on connector
  denial, disconnects to an anonymous session, and refuses a wrong-chain wallet
  (`wrong-chain` / no DEX navigation).
- [x] Public deposit, swap, withdrawal, wallet-address, gas, and version-migration
  warnings appear on `preview` and must be acknowledged before `run` (unsigned submit is
  `REJECTED`).
- [x] Direct shield authorizes, proves, submits, and lists a private note after finality
  (library-level `E2E-01`).
- [x] Swap-and-shield reviews a public quote, finalizes a private note, and fails closed
  on `QUOTE_STALE` and `UNAVAILABLE` (library-level `E2E-02` / `E2E-11`).
- [x] Private send encodes an app-scoped `haze1:` address and rejects a foreign
  application (`APPLICATION_MISMATCH`; library-level `E2E-03` / `E2E-05`).
- [x] Withdrawal and exit-and-reshield keep public amount and version-migration copy;
  migrate reports `linkage: true` (library-level `E2E-04` / `E2E-13`).
- [x] Emergency request then early execute is `TIMELOCK`; execute after seven days
  finalizes (library-level `E2E-09`).
- [x] Wipe plus replay recovers the same spendable notes and history (library-level
  `E2E-10`).
- [x] DEX navigation never includes portal `/admin` routes; hidden nav is still
  `FORBIDDEN` (library-level `E2E-05`).
- [x] Wallet reject and proof cancel leave no note; the static HTML shell uses
  alpine-volcanic tokens and keyboard/screen-reader contracts.

Hosted Next.js and full-system contract/indexer E2E remain T6.2.

### T5.3 — Application administration workspace

- [x] Only `application-admin` can sign in and stay on `/admin`; pool users, auditors,
  and super-auditors are denied; `/governance` stays closed (library `SC-03`).
- [x] Admin APIs (`POST /v1/manifests`, delegations, cases, reports, scoped export)
  allow the home application and return `APPLICATION_MISMATCH` for another
  application; custody and governance schedule stay forbidden (library `E2E-05`).
- [x] Manifest register pins `hashManifest`, rejects secret fields, and records KMS
  plus gatekeeper signer health (library `E2E-06`).
- [x] Transaction reports are filtered to the signed-in application.
- [x] Delegate auditor, create/list cases, field-scoped export, and revoke complete
  in one administrator session (library `E2E-06`).
- [x] Non-admin mutation throws `UNAUTHORIZED`.
- [x] Static admin HTML uses alpine-volcanic tokens, skip link, and stack/workspace
  layouts.

Hosted Next.js administrator E2E remains T6.2.

### T5.4 — Auditor investigation workspace

- [x] Only `application-auditor` can sign in and stay on `/audit`; SIWE challenge/token
  bind a wallet; `/admin` and `/governance` stay closed (library `SC-04`).
- [x] Auditor APIs allow query/export/cases/access-log on the home application and
  return `APPLICATION_MISMATCH` for another application; admin mutations, governance,
  and custody stay forbidden (library `E2E-05`).
- [x] Assigned cases hide foreign-application rows; unassigned case search is
  `UNAUTHORIZED`.
- [x] Field-limited search/export omit ungranted columns; extra fields fail closed
  (library `E2E-07`).
- [x] Expired or revoked grants surface on the screen and fail search.
- [x] Personal access history records allowed queries and denied field overreach.
- [x] Static audit HTML uses alpine-volcanic tokens, skip link, and stack/workspace
  layouts.

Hosted Next.js investigation E2E remains T6.2.

### T5.5 — Haze governance workspace

- [x] Only `super-auditor` can sign in and stay on `/governance`; `/admin` and
  `/audit` stay closed.
- [x] Governance APIs allow schedule/execute/status/super-auditor grants; custody
  and admin delegations stay forbidden; foreign application is
  `APPLICATION_MISMATCH` (library `E2E-05` / `FR-11`).
- [x] Preview shows exact registry target, timelock, and delay; execute without a
  scheduled operation is `TIMELOCK`.
- [x] Schedule then execute before `eta` is `TIMELOCK`; execute after delay
  activates (library `E2E-08`).
- [x] Status exposes suspensions, emergency/exit, version artifact hash, and
  ceremony provenance (`SC-09`). Super-auditor grant has `custody: false`.
- [x] Non-super-auditor schedule is `UNAUTHORIZED`.
- [x] Static governance HTML uses alpine-volcanic tokens, skip link, and
  stack/workspace layouts.

Hosted Next.js governance E2E remains T6.2.

## Unit Tests

### Circuits and cryptography

- [x] Prove a valid direct USDC deposit commitment for a registered application.
- [x] Prove a valid 2-input/2-output same-application transfer with change.
- [x] Prove a valid variable-value withdrawal with the correct public recipient and value.
- [x] Reject an input note whose commitment is absent from the submitted Merkle root.
- [x] Reject an incorrect owner secret, leaf index, nullifier, output commitment, or blinding value.
- [x] Reject input/output value inflation, underflow, overflow, negative private values, and values
  outside the constrained integer range.
- [x] Reject mixed application IDs across inputs, outputs, public inputs, and intent hashes.
- [x] Require every enabled input and output note key to prove active application membership and
  active Haze global non-membership; constrain zero-value dummy-slot enable bits.
- [x] Match canonical membership and global blocklist subject hashes across Circom, Rust, Solidity,
  and TypeScript for note-key and EVM-address subject kinds.
- [x] Reject unknown, future, stale, retired, or mismatched application/Haze policy roots and versions
  immediately after activation, with no grace period.
- [x] Reject a proof whose pool version, public recipient, public value, intent hash, or audit
  ciphertext hash differs from the submitted action (`haze/tests/verifier.test.mjs`;
  `HazeSpendVerifier.t.sol` `testRejectsProofWhenActionPublicInputsDiffer`). Development
  equality binds the keccak proof digest to the submitted 29 public inputs.
- [x] Recompute the audit-data commitment from real private transfer fields and the hidden audit salt;
  reject altered amount, initiator, counterparty, action, application, or salt.
- [x] Verify deterministic cross-language vectors for Poseidon domains, commitments, nullifiers,
  policy leaves, audit tags, and EVM address-to-field encoding.
- [x] Verify proving and verifying key artifact hashes and reject circuit/verifier version mismatch.

### HazePool and verifier contracts

- [x] Deposit exact USDC backing before inserting a commitment and emitting its bound audit event.
- [x] Reject unregistered, pending, suspended, or retired applications.
- [x] Reject missing, malformed, wrong-domain, expired, not-yet-valid, or wrong-signer EIP-712
  authorizations.
- [x] Consume each authorization nonce once and reject replay across actions, users, pools, versions,
  applications, and chain IDs.
- [x] Require direct pool callers to equal the authorized user; allow only the approved router to use
  `depositFromRouter`, bind its original payer, and reject generic forwarding/relaying.
- [x] Accept configured historical Merkle roots and reject unknown or expired roots.
- [x] Accept only the application and Haze policy versions active at execution and reject future,
  stale, or retired policy without a post-activation grace rule.
- [x] Verify a valid proof before consuming nullifiers and reject a reused nullifier.
- [x] Preserve USDC value conservation across deposits, private transfers, and withdrawals.
  Emergency-exit conservation is covered in T2.5. Sustained invariant campaign is T2.6.
- [x] Reject duplicate commitments and malformed zero/padding outputs outside circuit rules.
- [x] Bind recipient ciphertext hashes, audit-data commitment, and audit ciphertext hash to the proof,
  authorization, and event; reject omitted, substituted, or altered data.
- [x] Restrict pause, application, policy, and version actions to their separate governance roles.
- [x] Verify immutable deployments expose the expected version and artifact hashes with no proxy path.

### SwapAndShieldRouter

- [x] Execute an approved source-token route, enforce `min_usdc_out`, and atomically deposit the exact
  USDC balance delta into the intended Haze commitment.
- [x] Reject source tokens, adapters, calldata hashes, applications, or routes outside configured
  policy.
- [x] Reject expired quotes and output below the signed slippage floor.
- [x] Revert both swap and deposit when the pool, token transfer, adapter, proof, policy, or
  authorization fails.
- [x] End every successful transaction with zero residual user source token and USDC in the router.
- [x] Prevent reentrancy, approval reuse, arbitrary external calls, route substitution, recipient
  substitution, and malicious-token callback attacks.
- [x] Reject fee-on-transfer and rebasing behavior unless a future adapter explicitly supports it.

### Registries and emergency exit

- [x] Schedule and activate application, Haze policy, and version changes only after the configured
  timelock. App-admin gatekeeper and manifest updates are immediate (`FR-11` Haze-multisig scope).
- [x] Preserve prior configuration until activation and emit complete change provenance.
- [x] Suspend an application without granting governance the ability to spend its users' notes.
- [x] Register an eligible emergency-exit request and enforce the full seven-day cooldown.
- [x] Allow any note owner to register an emergency-exit request without proving application outage
  or suspension.
- [x] Reject early, duplicate, invalid-Haze-policy, blocked-recipient, invalid-proof, and
  reused-nullifier emergency exits without requiring application membership or signature.
- [x] Reconstruct active Haze non-membership witnesses from public policy events and complete an exit
  while the application gatekeeper and application witness endpoint are unavailable.
- [x] Bind a client-constructed emergency-exit audit envelope to the exit proof and public
  amount/recipient; reject false plaintext, salt, commitment, ciphertext hash, or key version.
- [x] Allow a normal gatekeeper-authorized withdrawal during the cooldown.
- [x] Verify timelocked governance cannot shorten the current request ad hoc.
- [x] Keep retired immutable versions exit-capable for their published support window and verify that
  migration uses public withdrawal plus a separately authorized shield into the new version.

### Gatekeeper service

- [x] Authorize an eligible application session for each supported action with exact typed fields and
  active application/Haze policy versions.
- [x] Validate every real input/output Haze address against application KYC membership and Haze global
  policy before signing; reject blocked-identity key re-registration through the application adapter.
- [x] Construct the canonical audit plaintext, hidden salt, audit-data commitment, versioned envelope
  ciphertext, and EIP-712 binding; reject client-supplied contradictory audit fields.
- [x] Reject failed/stale KYC, inactive applications, unsupported source tokens, policy mismatch,
  amount/velocity limits, stale roots, and malformed audit hashes.
- [x] Issue unique nonces and bounded validity windows under concurrent requests.
- [x] Return stable non-sensitive error codes and never log KYC payloads, witnesses, or secrets.
- [x] Verify signer rotation, key-unavailable behavior, rate limiting, and idempotent retries.

### Indexer, auth, and disclosure services

- [x] Ingest each pool/router event idempotently by chain, transaction hash, and log index.
- [x] Track observed/finalized/reorged state and compensate a simulated C-Chain reorg correctly.
- [x] Reject ciphertext whose content hash or event binding is invalid.
- [x] Complete OIDC/SAML login plus one-time SIWE binding and reject challenge replay or wallet mismatch.
- [x] Issue short-lived audience-bound grants with the correct organization, role, application, case,
  field, time, and wallet scopes.
- [x] Deny cross-application, cross-case, expired, revoked, overbroad-field, and unfinalized-record
  disclosure requests.
- [x] Deny a Haze super-auditor when any target application's KMS case policy is absent; verify the
  grant cannot bypass application-controlled decryption authority.
- [x] Decrypt with the correct application KMS key, redact ungranted fields, and zero temporary
  plaintext/key material after response construction.
- [x] Recompute the canonical audit-data commitment and ciphertext hash after decryption; treat false
  plaintext, wrong salt, wrong key version, and hash mismatch as integrity failures.
- [x] Record successful and denied disclosure decisions without recording decrypted payloads; detect
  hash-chain deletion, reordering, or modification and verify write-once retention copies.
- [x] Fail closed during KMS, identity-provider, database, or token-validation outages.

### SDK and frontends

- [x] Derive the same app/pool-domain-separated note and X25519 keys from the documented wallet message
  and restore notes after local-vault deletion (SDK unit; `E2E-10` remains T5.2/T6.2).
- [x] Encode/decode/checksum app-scoped Haze addresses, reject wrong-application/version addresses,
  decrypt authenticated recipient ciphertexts, and reject notes whose commitment does not recompute.
- [x] Encrypt the local vault, clear witness buffers, and never persist shielded secrets in plaintext.
- [x] Normalize direct shield, swap quote, proof, authorization, submission, finality, and resync state
  transitions with actionable error codes.
- [x] Warn that source-token swaps, deposits, withdrawals, wallet addresses, and gas are public.
- [x] Package a node-free proving Web Worker, hash-keyed artifact cache, production/development
  artifact selection, progress/cancel hooks, Apache-2.0 package docs, and a direct-shield example
  (SDK unit; hosted browser E2E remains T5.2/T6.2).
- [x] Prevent an ordinary user from loading portal APIs and prevent an application auditor from
  loading governance or other-application data (library-level T5.1; hosted remains T5.2/T6.2).
- [x] Test keyboard navigation, focus restoration, screen-reader labels, contrast, reduced motion,
  and responsive layouts as component contracts (T5.1).
- [x] Wallet rejection, reconnect, wrong-chain, and unsigned-submit denial (library-level T5.2;
  hosted remains T6.2).
- [x] Application administrator registers a hash-pinned manifest/KMS config, delegates an
  auditor, reviews application-only reports, exports scoped fields, and revokes access
  (library-level T5.3; hosted `E2E-06` remains T6.2).
- [x] Application auditor completes SIWE, opens an assigned case, receives field-scoped
  records, exports, and sees allowed plus denied access history (library-level T5.4;
  hosted `E2E-07` remains T6.2).
- [x] Super-auditor previews a timelocked policy/application schedule with exact
  on-chain targets, cannot execute early, and has no custody authority (library-level
  T5.5; hosted `E2E-08` remains T6.2).

## Integration Tests

- [x] Generate a proof in the Rust/browser prover and verify it with the exact deployed Solidity
  verifier using shared canonical vectors (`haze/tests/verifier.test.mjs`,
  `haze/crates/prover`, `HazeSpendVerifier.t.sol`). Production pairing remains `KEYS_MISSING`.
- [x] Direct-shield mock USDC through gatekeeper authorization, HazePool, event ingestion, note sync,
  and encrypted audit retrieval (`haze/dev/e2e.mjs` E2E-01, `haze/tests/workflow.test.mjs`,
  `haze/tests/e2e-acceptance.test.mjs`; hosted Anvil/Next.js remains out of scope).
- [x] Swap an approved mock token through a mock aggregator adapter, shield the resulting USDC, and
  reconcile the public swap receipt with the encrypted pool audit record (`haze/dev/e2e.mjs`
  E2E-02, `haze/tests/workflow.test.mjs`; mock aggregator only).
- [x] Submit a private transfer and withdrawal through SDK, gatekeeper, contracts, indexer, and local
  note-state updates (`haze/dev/e2e.mjs` E2E-03/E2E-04, `haze/tests/workflow.test.mjs`).
- [x] Rotate a gatekeeper key, update an application membership root, and activate a timelocked Haze
  blocklist root; verify historical note-tree roots remain bounded while stale policy roots are
  rejected immediately and require re-proof (`haze/services/gatekeeper/tests/gatekeeper.rs`
  `rotate_signer`, `ApplicationRegistry.updateMembershipRoot`,
  `HazePool.t.sol` `testAcceptsOnlyActivePolicyVersionsAndRootsWithoutGrace`,
  `haze/tests/workflow.test.mjs` stale-policy re-proof).
- [x] Suspend an application, register an emergency exit, advance seven days, and complete the exit
  without a gatekeeper signature under current Haze policy (`haze/dev/e2e.mjs` E2E-09,
  `EmergencyExit.t.sol`, `haze/tests/privacy-pool-dex.test.mjs`).
- [x] Authenticate an auditor through mock OIDC plus SIWE, approve a case, decrypt through a mock KMS,
  recompute the audit-data commitment/ciphertext hash, export limited fields, and verify the access log
  (library-level T4.4; hosted/HTTP and full-system remain T5.2/T6.2).
- [x] Simulate duplicate delivery, service restart, RPC failover, and a short reorg without duplicate
  records, lost checkpoints, or stale-final data (library-level T4.2/T4.5; hosted/HTTP remains
  T5.2/T6.2).
- [x] Verify all services reject incompatible contract, circuit, API, manifest, and database schema
  versions during startup or request handling (library-level T4.5 pin; hosted/HTTP remains
  T5.2/T6.2).

## End-to-End Tests

Library-first runner: `haze/dev/e2e.mjs` (`npm run e2e --prefix haze`) on the T6.1 in-process
stack. Failures emit redacted evidence. Hosted Anvil/Next.js is still out of scope.

- [x] **E2E-01 Direct shield:** approved user deposits USDC in the Privacy Pool DEX frontend, sees the
  public amount warning, proves/submits successfully, and sees the private note after finality.
- [x] **E2E-02 Swap-and-shield:** approved user selects an allowlisted token, reviews a public quote and
  slippage, performs one atomic swap-and-shield transaction, and receives a USDC private note.
- [x] **E2E-03 Private send:** sender transfers private USDC to another user in the same application;
  only the intended recipient recognizes the output note.
- [x] **E2E-04 Normal withdrawal:** user withdraws a variable amount to the authorized public address
  and change remains private.
- [x] **E2E-05 Application isolation:** cross-application transfer, gatekeeper signature, note, audit
  query, and portal-navigation attempts all fail.
- [x] **E2E-06 Application administration:** administrator registers the manifest/KMS configuration,
  delegates an auditor, reviews application transactions, and revokes access.
- [x] **E2E-07 Investigation:** auditor opens an approved case, receives field-scoped records, exports a
  report, and sees both successful and denied access attempts in the log.
- [x] **E2E-08 Governance:** multisig schedules policy/application changes, timelock activates them, and
  the portal displays version and artifact provenance.
- [x] **E2E-09 Emergency exit:** a note owner requests an exit without application suspension, waits
  the seven-day cooldown, and exits under current Haze global policy without application membership
  or signature while an early attempt fails.
- [x] **E2E-10 Recovery:** user clears local state, re-derives the shielded account, replays events, and
  decrypts recipient ciphertexts, verifies commitments, and recovers the correct spendable balance
  without duplicating spent notes.
- [x] **E2E-11 Adversarial route:** malicious/expired DEX route, slippage breach, and failed pool deposit
  each revert without leaving funds or approvals in the router.
- [x] **E2E-12 Privacy copy:** user and portal surfaces accurately distinguish public swap/deposit/
  withdrawal and application-affiliation data from hidden private-transfer data, without claiming a
  cross-application anonymity set.
- [x] **E2E-13 Version migration:** user publicly exits a retiring immutable pool and separately
  shields into the replacement; both frontends disclose the linkage and the old pool remains
  exit-capable throughout its support window.

## Test Data

- [x] T6.1 in-process assembler `haze/dev/stack.mjs` (`assembleStack` / `bootstrapStack` /
  `teardownStack` / `verifyStack`) plus published hashes in
  `haze/dev/fixtures/stack-manifest.json`. Profiles `local` and `ci` use `anvil-mock`, two isolated
  applications (`APP_A` / `APP_B`), MockUsdc, malicious-adapter, both frontends, and adversary
  actors. No production vendor endpoints. Live Anvil/HTTP/Next.js remains T6.2.
- Local EVM chain plus Fuji configuration with deterministic deployment manifests.
- Mock USDC with six decimals, ordinary source tokens, and adversarial fee-on-transfer, rebasing,
  callback, false-return, and non-standard approval tokens.
- Mock DEX quote service, approved aggregator adapter, malicious adapter, and configurable slippage.
- At least two registered applications, each with administrators, gatekeeper signers, KMS keys,
  eligible/ineligible users, auditors, and isolated cases; include a Haze super-auditor grant.
- Deterministic valid/invalid notes, app-scoped Haze addresses, recipient ciphertexts, application
  membership trees, Haze global blocklists, strict policy versions, canonical audit records/salts,
  EIP-712 vectors, SIWE challenges, and seven-day emergency-exit fixtures.
- Mock OIDC/SAML and KMS adapters for CI; no real customer identity, KMS material, production keys,
  or ceremony secrets in fixtures.
- Versioned development proving/verifying keys whose hashes cannot be mistaken for production.

## Test Reporting & Coverage

- [x] T6.3 publishes `haze/dev/fixtures/gates-report.json` via `haze/dev/gates.mjs`. The report maps
  `SC-01`–`SC-10`, `FR-01`–`FR-14`, and `E2E-01`–`E2E-13` to existing evidence. Spend Groth16 P95 is
  an approved deferral to T7.4 (`KEYS_MISSING`). Hosted HTTP P95 remains out of scope. The published
  gates hash ignores live proving duration (T6.4 remediations) so `npm test` cannot flake the fixture.
- [x] T6.4 publishes `haze/dev/fixtures/security-review.json` via `haze/dev/security-review.mjs`.
  Ten surfaces are reviewed with live source checks. Open critical/high count is zero. `M-01`
  and `M-03` are remediating in T7.5 as operator-owned hard stops (`KEYS_MISSING` / `FUJI_GAS`;
  `M-02` remediating in T7.1; `M-04` remediating in T7.2; `M-05` remediating in T7.3). Open
  mediums are empty. Regression coverage lives in `haze/tests/security-review.test.mjs`.
- [x] T6.5 publishes `haze/dev/fixtures/runbooks.json` via `haze/dev/runbooks.mjs`. Ten procedures
  have owners, escalation paths, and a local tabletop pass. T7.1 completed the Fuji-configured
  rehearsal. Regression coverage lives in `haze/tests/runbooks.test.mjs`.
- [x] T7.1 publishes `haze/dev/fixtures/fuji-release.json` via `haze/dev/fuji-release.mjs` and public
  provenance at `haze/deployments/fuji-v1.json`. The package pins Fuji `43113`, Circle USDC, development
  ceremony artifacts, immutable contracts, services/frontends, policy roots, smoke/E2E/gas evidence,
  and `SC-01`/`SC-06`/`SC-07`. It does not broadcast. Regression coverage lives in
  `haze/tests/fuji-release.test.mjs`.
- [x] T7.2 publishes `haze/dev/fixtures/pilot.json` via `haze/dev/pilot.mjs`. APP_A is the
  representative fintech/payment/payroll application. Acceptance covers integration, administrator,
  auditor, privacy copy, operations, recovery, and reporting with non-real assets. Coverage
  `SC-03`–`SC-05`. SC-09 `fuji_pilot.approved` stays false. `M-04` is remediating. Regression
  coverage lives in `haze/tests/pilot.test.mjs`.
- [x] T7.3 publishes `haze/dev/fixtures/audit.json` via `haze/dev/audit.mjs`. Eight surfaces are
  reviewed. The spend circuit is frozen. Critical/high findings are zero. `M-05` is remediating.
  T7.5 remediates remaining mediums `M-01` and `M-03` as operator-owned hard stops. Coverage
  `SC-08`/`SC-09` and `haze/SECURITY.md`. SC-09 `independent_audit.approved` stays false.
  Regression coverage lives in `haze/tests/audit.test.mjs`.
- [x] T7.4 publishes `haze/dev/fixtures/ceremony-release.json` via `haze/dev/ceremony-release.mjs`.
  The public contribution process is documented-rehearsed. The T1.4 rehearsal transcript verifies.
  The T7.3 spend freeze is pinned. The generated verifier and signed manifest stay
  `NOT_FOR_PRODUCTION`. `M-01` is remediating by retargeting `KEYS_MISSING` to operator-owned.
  Coverage `SC-09`. SC-09 `production_ceremony.approved` stays false. Regression coverage lives in
  `haze/tests/ceremony-release.test.mjs`.
- [x] T7.5 publishes `haze/dev/fixtures/readiness.json` via `haze/dev/readiness.mjs` and the
  unauthorized mainnet plan at `haze/deployments/mainnet-v1.json`. Eleven checks pin
  operator-owned owners/providers and T7.2–T7.4 hashes. `M-01` and `M-03` are remediating.
  Production-config smoke rejects Fuji compatibility on 43114 and keeps development fixtures out
  of production. Coverage `SC-09`. SC-09 `incident_review.approved` stays false.
  `mainnetAuthorized` stays false. Regression coverage lives in `haze/tests/readiness.test.mjs`.
- [x] Live Fuji development deploy (`haze/tests/fuji-live-deploy.test.mjs`). Planner predicts
  CREATE addresses, refuses production keys and T7.5 flips, and writes a sidecar without changing
  `fuji-v1.json` `broadcast: false`. On-chain creates and activate txs are recorded in
  `haze/deployments/fuji-v1.live.json`.
- [x] Live Fuji development deposit (`haze/tests/fuji-live-deploy.test.mjs`,
  `haze/contracts/script/DepositFujiLive.s.sol`). 1 USDC Circle transfer into
  `HazePool` `0x919b338f189B1e564Af34A26fC002138f308f7dE`. Deposit receipt
  `0xdbfbeb63cfda4bbd03abf2d55303b758dc950fd33b24733af135611ab81a151e` status `0x1`.
  Hosted `fujiGate` stays fail-closed.
- [x] Hosted UI H0–H5 (`haze/dev/host.mjs`, `haze/tests/hosted-ui.test.mjs`). Local profile serves
  alpine-volcanic DEX and portal HTML with CSP and skip links. Fuji profile throws `FUJI_NOT_READY`
  when broadcast, proving keys, operator RPC, or `HazePool` are missing. After `signIn`, GET
  `/admin` / `/audit` / `/governance` return 200 for the matching workspace role and stay 403 for a
  pool-user. playwright-cli walked connect, public preview, native Sign and submit, isolation,
  emergency TIMELOCK, wipe/recover, admin manifest/delegate, auditor SIWE/export overreach,
  governance preview/early TIMELOCK, glossary, and mobile `?width=390`. Live Fuji txs are blocked.
- Circuits report constraint counts, valid/invalid witness suites, artifact hashes, and proving-time
  distributions for each version.
- Foundry reports unit/fuzz/invariant results, gas snapshots, and line/branch coverage for handwritten
  contracts; generated verifier exceptions are listed separately.
- Rust reports workspace tests and coverage for Haze services; TypeScript reports SDK/frontend unit,
  integration, accessibility, and browser end-to-end results.
- CI publishes an acceptance matrix mapping `SC-01` through `SC-10`, `FR-01` through `FR-14`, and
  `E2E-01` through `E2E-13` to fresh test evidence.
- Any security-critical coverage gap, changed gas snapshot beyond the agreed budget, circuit-artifact
  mismatch, or flaky critical-path test blocks release.

## Manual Testing

- [x] Clickable operator MVP unit coverage in `haze/tests/commercial-frontend.test.mjs` and
  `haze/tests/operator-circuit-live.test.mjs`: hatch persist writes a spendable Poseidon note;
  digest shield commitment differs from the circuit note; default host `/api/live-deposit/prove`
  and persist stay `KEYS_MISSING`; `npm run commercial:operator` requires a local zkey and does
  not flip `fuji-v1.json`; DEX copy is `Fuji demo · operator keys local` when hatch is open.
  `canSignAction` send stays false. MetaMask `notification.html` unclaimed.
- [x] Unique-note hatch coverage (`haze/tests/operator-circuit-live.test.mjs`,
  `haze/tests/commercial-frontend.test.mjs`, 2026-08-20): hatch plan does not reuse
  `depositCommitment` / `deposit1Commitment`; leaf index is occupied-leaf count;
  overlay records mined `0x1` receipts only; `shield-live.js` waits
  `eth_getTransactionReceipt`. `npm test` in `haze/` 267 pass / 0 fail.
- [x] Headed MetaMask operator walk attempt 2
  (`HAZE_COMMERCIAL_URL=http://127.0.0.1:3014 npm run dappwright:live-operator`,
  2026-08-20, ~137s). Connect `0xeD37…cc32` on hatch `/shield?live=1`. Shield
  `0x15a9f9c3f2223476203d95fa2acdeaf0a8d7c078aa17c4b523cc9b98700b1b4b` and withdraw
  `0xb97e014e858dea1264924e3f7b53dbaecdf4b0a340a933e3f5347d565cf3f850` both Fuji
  `status: 0x1` to pool `0x00BEB0A5…d550` (2 logs each). Overlay
  `websiteOperatorHost` `http://127.0.0.1:3014`. Attempt 1 hashes `0xf6bb4e42…` /
  `0x673fcfdd…` reverted (`COMMITMENT_DUPLICATE` / `ROOT_UNKNOWN`) and are not
  success. Committed `fuji-v1.json` still `broadcast: false` / `KEYS_MISSING`.
  playwright-cli `notification.html` unclaimed; dappwright `confirmAny` owned the
  popups.
- [x] playwright-cli walk of the operator hatch host (`PORT=3014 npm run commercial:operator`,
  `http://127.0.0.1:3014`, 2026-08-20) at 1440×900 and 390×844. Pool-user
  `?address=0xf39F…2266` + `?live=1`: `/shield` `/withdraw` `/send` are `data-chrome="dex"`.
  Chip `Fuji demo · operator keys local` (`data-code="operator-demo"`). After review, `/shield`
  and `/withdraw` submit `Sign and submit`. `/send` stays disabled `Spend proofs unavailable`.
  Sign without injected `ethereum` surfaces `WALLET_MISSING`. Mobile card width 366px at
  390×844. Default `npm run commercial` on 3010 still shows live-sidecar digest copy, not the
  hatch chip. MetaMask `notification.html` unclaimed. Committed `fuji-v1.json` still
  `broadcast: false`, `spend_prove: KEYS_MISSING`.
- [x] playwright-cli walk of the commercial host (`http://127.0.0.1:3010`, 2026-08-20) at 1440×900
  and 390×844 after DEX-first chrome. Pool-user `?address=0xf39F…2266`: `/shield` `/send`
  `/withdraw` `/swap` are `data-chrome="dex"` / `data-card="pool"`, USDC amount hero, no inspector.
  After review, spend submit is disabled `Spend proofs unavailable` with `data-code="KEYS_MISSING"`.
  Pool-user `/admin` is `FORBIDDEN`. Application-admin `/admin` is `data-chrome="compliance"`;
  Register manifest → `0xmanifest`. Mobile card width 366px at 390×844. Favicon `data:` SVG is
  blocked by CSP (`default-src 'self'`); pre-existing. MetaMask `notification.html` unclaimed.
  Committed `fuji-v1.json` still `broadcast: false`, `spend_prove: KEYS_MISSING`.
- [x] playwright-cli walk of the commercial host (`http://127.0.0.1:3010`, 2026-08-18) at 1440×900
  and 390×844. Fixture `?address=` sessions (Anvil 0–3). Routes: `/swap` `/shield` `/send`
  `/withdraw` `/history` `/emergency-exit` `/migrate`; pool-user `/admin` FORBIDDEN; admin
  `/admin` (Register manifest → `0xmanifest`); auditor `/audit`; super-auditor `/governance`.
  Shield: Review public facts then Sign and submit. Withdraw submit stays disabled
  (`Spend proofs unavailable`). Fonts 200 after host serve.
  dappwright `--launch` exit 2: `@tenkeylabs/dappwright` not installed; no MetaMask popup.
  Committed `fuji-v1.json` still `broadcast: false`, `spend_prove: KEYS_MISSING`.
- [x] Headed `npm run dappwright:live --prefix haze` (2026-08-18, host `:3011`): Connect as
  `0xeD37…`, `/shield?live=1&reviewed=1`, Sign and submit → USDC approve + typed-data + deposit.
  Receipt `0x5c2bfc90a6601c36de6daa93c4af3d08db0493fd4df2553fdbeed63aa06e278b` status `0x1`,
  recovered signer `0xeD37…`, pool USDC 2→3. Planner test requires `types.EIP712Domain`.
  Committed `fuji-v1.json` still `broadcast: false`, `spend_prove: KEYS_MISSING`.
- [x] playwright-cli walk of the local `haze/dev` host (`http://127.0.0.1:8787`) for Privacy Pool
  DEX and Compliance Portal: injected `window.ethereum` only, public-fact acknowledgments, native
  Sign and submit, role-isolated portal pages, glossary, and 390px stack layout. Fuji host profile
  and the hosted Fuji profile remain fail-closed on the committed T7.5 package (`KEYS_MISSING`,
  `broadcast: false`). A separate development sidecar recorded live create/activate hashes; no
  user shield was sent because the deployer has 0 Circle USDC.
- Review both frontends on supported desktop browsers with injected and WalletConnect-compatible EVM
  wallets, including rejection, chain switch, disconnect, locked-wallet, and stale-session behavior.
- Complete a WCAG 2.1 AA audit of all critical paths with keyboard-only and screen-reader passes.
- Have compliance stakeholders validate administrator/auditor terminology, case workflow, report
  provenance, least-privilege defaults, and public/private boundary copy.
- [x] Local tabletop of deploy/rollback, pause, rotation, RPC/indexer recovery, database restore,
  app suspension, emergency exit, disclosure, user communication, and dashboards/alerts
  (`haze/dev/runbooks.mjs`).
- [x] Fuji-configured rehearsal of those runbooks against chainId 43113, Circle USDC, and
  `haze/deployments/fuji-v1.json` (`haze/dev/fuji-release.mjs`). Live broadcast remains operator-owned.
- [x] Library-first Fuji pilot acceptance for APP_A (fintech/payment/payroll, non-real assets)
  covering administrator/auditor workflows, privacy copy, operations, recovery, reporting,
  accessibility/compliance reviews, and internal stakeholder sign-off (`haze/dev/pilot.mjs`).
  SC-09 `fuji_pilot.approved` remains closed.
- [x] Library-first independent audit of circuits, ceremony tooling, contracts, SDK key handling,
  services, frontends, governance, and operational controls (`haze/dev/audit.mjs`). Spend circuit
  frozen; `M-05` remediating; SC-09 `independent_audit.approved` remains closed.
- [x] Library-first production ceremony package (`haze/dev/ceremony-release.mjs`). Public
  contribution process documented-rehearsed; rehearsal transcript independently verified; T7.3
  freeze pinned; generated verifier `NOT_FOR_PRODUCTION`; `M-01` remediating to operator-owned
  `KEYS_MISSING`; SC-09 `production_ceremony.approved` remains closed. No 588459-constraint
  proving keys.
- [x] Library-first operational-readiness checklist (`haze/dev/readiness.mjs`). Eleven surfaces
  recorded; unauthorized `mainnet-v1.json` on 43114; `M-01`/`M-03` remediating as operator-owned
  hard stops; production-config smoke rejects development fixtures and Fuji compatibility;
  SC-09 `incident_review.approved` remains closed. Mainnet is not authorized.
- Exercise multisig/timelock, application suspension, KMS rotation/outage, policy rotation, circuit
  version activation, and emergency-exit runbooks on Fuji.
- Verify the production ceremony manifest, independent audit findings, remediations, deployment hashes,
  and operational sign-offs before mainnet approval.

## Performance Testing

- Benchmark browser proof generation across the documented reference desktop and supported browsers;
  require P95 at or below 15 seconds and report memory peaks and artifact download/cache behavior.
- [x] Record local development-equality P95 through the SDK worker loopback in
  `haze/dev/artifacts/proving-benchmark.json` (`worker: true`, target 15000ms,
  `reference_desktop: local-development`). Spend Groth16 P95 remains `KEYS_MISSING` as an
  operator-owned hard stop in `haze/dev/fixtures/gates-report.json`.
- [x] Record local Foundry gas for direct shield, private send, withdrawal, swap-and-shield,
  registry changes, pause/unpause, token allowlist, and emergency exit
  (`haze/dev/artifacts/haze-gas-v1.json`). Establish release budgets from Fuji measurements
  before mainnet.
- [x] Load gatekeeper, indexer, auth, and disclosure APIs at expected MVP concurrency and at 2x burst;
  require non-proving P95 at or below 500 ms without authorization leakage (in-process T4.5
  baseline of 128 samples; hosted HTTP P95 remains out of scope).
- [x] Measure finalized-event-to-query latency and require the normal-operation P95 at or below 10 seconds
  (in-process T6.3 samples in `haze/dev/gates.mjs`).
- Stress reorg reconciliation, backlog catch-up, KMS latency, export size, policy rotation, and
  concurrent authorization nonce issuance.

## Check Implementation (Phase 7, 2026-08-20)

No new product acceptance scenario was invalidated. Two documentation/tooling notes:

- Commercial authorization is wallet-address grants, not a public role dropdown. Connected wallets
  with more than one grant see a workspace `<select>` of those grants. `?role=` stays hidden
  test/dev mapping. MetaMask `notification.html` connect/account-switch remains unclaimed.
- Official `node haze/dev/secret-scan.mjs` crashed `ERR_STRING_TOO_LONG` when gitignored
  `haze/dev/artifacts/ceremony-private/` binaries were present. Phase 8 closed this: skip
  `ceremony-private`, `.ptau`/`.zkey`/`.r1cs`/`.sym`/`.wasm`, and files larger than 5 MB.

## Write Tests (Phase 8, 2026-08-20)

Coverage gaps closed without new product behavior except the secret-scan skip.

- TDD: `haze/tests/dev-foundations.test.mjs` `execFileSync`s `node haze/dev/secret-scan.mjs`
  and requires `secret-scan ok`. Red: `ERR_STRING_TOO_LONG`. Green: skip `ceremony-private`,
  Groth16/circuit binaries, and files >5 MB. Revert of the skip restored the crash. Required
  `PRIVATE KEY` / `AKIA` / `github_pat_` / `xox[baprs]` strings remain for security-review.
- Added development-equality tests that a proof fails when pool version, public recipient,
  public value, intent hash, or audit ciphertext hash is mutated
  (`haze/tests/verifier.test.mjs`, `HazeSpendVerifier.t.sol`).
- Integration checklist items 1–6 were already covered by T6.2 E2E, workflow, Foundry, and
  gatekeeper tests; checkboxes lockstepped to those files. Hosted Anvil/Next.js and MetaMask
  `notification.html` connect/account-switch remain unclaimed.
- Fresh evidence: `node haze/dev/secret-scan.mjs` exit 0 `secret-scan ok`;
  `npm test --prefix haze` 257 pass / 0 fail; `forge test --root haze/contracts` 113 pass /
  0 fail; `npx ai-devkit@latest lint --feature haze-avalanche-compliant-pool` all passed;
  `haze/dev/security-review.mjs verify` ok
  `0x55f5bebca26a5167148822d8aa9f11f100886c201edb8634a3c2bc5082394562`;
  `haze/dev/gates.mjs verify` ok
  `0xf454911a26d5159021b7c88a92a5d842011ae15c19403ba6500ce33cf8580f55`. Task tracing
  unavailable.
- Foundry closeout: adding the binding test to `HazeSpendVerifierTest` shifted
  `testVerifyDepositGasSnapshot` from 15214 to 15226 (test-contract CALL overhead). The
  binding test now lives on `HazeSpendVerifierPublicInputBindingTest` so the snapshot
  stays 15214. `GasBudgets` pin failures were pre-existing local-Foundry drift vs
  `haze-gas-v1.json` (deposit/transfer/swapAndShield ~880 gas, withdraw 175, all still
  under +15% budgets). Measured values were re-pinned; Fuji remeasure remains required
  before mainnet.

## Code Review (Phase 9, 2026-08-20)

No new product acceptance scenario. Review found no blocking test gap in the Phase 8 delta.
MetaMask `notification.html` connect/account-switch stays unclaimed. Secret-scan still skips
dotfiles (including local `.env`) and files larger than 5 MB; gitignore remains the commit
control for `.env`. Next: first commit / `dev-pr` when the operator is ready.

## Commercial frontend (2026-08-18)

- [x] One origin serves Pool and Compliance routes
- [x] Wallet-address grants: `application-admin` can open `/admin`; `pool-user` gets `FORBIDDEN`
- [x] Fail-closed banners for `KEYS_MISSING` and `broadcast:false`
- [x] playwright-cli desktop + mobile walk (disconnected routes)
- [x] `fuji-v1.json` remains `broadcast: false`
- [x] Persist-once MetaMask: `npm run qa:wallet:setup` then `npm run qa:cli`
- [x] DEX-first pool chrome (`data-chrome="dex"`, centered card, USDC amount, no inspector)
- [ ] Connect + account-switch (E2E-05/06): blocked — MetaMask `notification.html` is
      not a playwright-cli page; do not fake connect or use `?role=` as acceptance

## Bug Tracking

- **Critical:** fund loss/inflation, proof or policy bypass, secret/plaintext leakage, unauthorized
  disclosure, governance takeover, or unrecoverable pool lock. Stop deployment and begin incident
  response immediately.
- **High:** cross-application access, replay, incorrect accounting/history, non-atomic swap residue,
  emergency-exit failure, or persistent audit omission. Block release.
- **Medium:** recoverable workflow failure, degraded performance beyond target, incomplete report, or
  accessibility failure in a non-critical path. Fix before the affected milestone exits.
- **Low:** cosmetic or documentation issue with no security, privacy, accessibility, or accounting
  impact. Track for the next release unless it creates misleading privacy claims.
- Every defect receives a regression test at the lowest effective layer plus end-to-end coverage when
  it affects a user or compliance workflow.

## D7 Browser Spend Coverage (2026-08-21)

- D7 headed-runner TDD red: `node --test tests/d7-deployed-acceptance-runner.test.mjs`
  failed 3/3 against the withdrawal-only local/query-hatch runner for the intended missing
  production-origin, route/recovery, and evidence behaviors.
- D7 headed-runner green/refactor: the same command passes 3/3; `node --check
  dev/dappwright-live-spend-walk.mjs` and `git diff --check` exit 0. The contract excludes
  local origins, query hatches, sidecars, filesystem note input, shared key loaders, and
  operator proving, while requiring separate transaction/disclosure statuses and screenshots.
- D7 deployed attempt 1 stopped before Chromium launch or Fuji activity with
  `D7_PRIVATE_KEY_REQUIRED`: the worktree environment contains an unprefixed 64-hex-character key.
  Corrective TDD first failed 1/3 on missing key normalization, then passed 3/3 after accepting both
  canonical 32-byte environment forms and normalizing only in memory.
- D7 deployed attempt 2 launched headed Chromium but stopped before Fuji activity when the current
  MetaMask UI remained inside imported-account navigation and dappwright timed out waiting for
  `sort-by-networks`. The two-attempt limit is exhausted; no deposit, withdrawal, or disclosure
  acceptance claim is recorded. A follow-up regression failed 1/4, then passed 4/4 after requiring
  an explicit return to account home before Fuji network switching.
- Third pre-transaction failure: a non-wallet Vercel browser inspection showed `/shield` and
  `/withdraw` briefly paint and then disappear after hydration. Root cause is the complete HTML
  document injected inside the Next React tree, compounded by a static CSP that rejected Next's
  inline hydration bootstrap. Renderer regressions now require a document-free,
  script-free Next fragment; a complete standalone document; one Fuji mount slot with no legacy
  wallet/form controls or misleading key state; portal mounting; and a region-scoped exact connect
  locator; a CSP regression pins the required framework bootstrap policy. Production Chromium now
  keeps both routes visible across reload with one connect control and zero console errors. The
  authorized repair-deployment exception precedes D7, after which at most three new
  headed attempts are allowed under diagnose/fix/redeploy-before-retry rules.
- Post-fix attempt 1 failed `D7_DEPOSIT_TIMEOUT` after the page renderer stayed CPU-active for the
  full 20-minute observation budget; no deposit transaction or evidence file was observed. The
  runner regression now pins a 40-minute proving budget and redacted terminal diagnostics before
  attempt 2. No D7 acceptance claim is recorded from this attempt.
- Post-fix attempt 2 failed before transaction submission when MetaMask's `alert-modal` intercepted
  its confirmation footer. The runner regression requires alert detection/dismissal to precede the
  confirmation locator. Attempt 3 remains the final allowed run; no acceptance claim is recorded.
- Post-fix attempt 3 exhausted the budget before transaction submission on the same alert overlay.
  Diagnosis: the overlay appeared between the pre-check and underlying confirmation click. A
  regression now pins a two-second click bound and post-interception alert recheck, but no fourth
  attempt is permitted. D7, final evidence, Render deployment, and the release PR remain incomplete.
- Browser witness tests bind one action reference across witness, audit facts, authorization nonce,
  and real recipient/audit envelope hashes.
- Membership tests require a successful root-update receipt and the refetched incremented policy
  version before final witness construction.
- Transaction tests require approval receipt ordering, final preflight, encrypted persistence before
  pool broadcast, actual hash persistence, and matching receipt/event reconciliation.
- Withdrawal failure cases cover missing, reverted, and event-mismatched receipts without consuming
  the deposit note. Recovery covers submitted operations and linked-note consumption only on confirmation.
- Disclosure compatibility tests pin the Rust-supported field set and its canonical NUL-delimited hash.
- Browser graph tests reject Node builtins, localhost/server hatches, and `?live=1`; Next aliases the
  transitive worker dependency to its browser implementation.
- Fresh gates: Node 324/324 plus Circom vectors; Rust workspace tests green; disclosure release build
  and warning-denying clippy green; SDK and Next production builds green; secret scan and AI DevKit
  feature lint green.
- D7.1 Candidate Hardening unit tests:
  - `haze/tests/wallet-confirmation-helper.test.mjs`: verifies bounded retries for visible and racing alert modals while propagating unrelated click errors.
  - `haze/tests/render-disclosure.test.mjs`: verifies `DEFAULT_HAZE_DISCLOSURE_ORIGIN` constant export.
  - `haze/tests/d7-deployed-acceptance-runner.test.mjs`: verifies candidate Git SHA, Vercel deployment ID, imported helper use, and fail-closed disclosure check (`D7_ACCEPTANCE_FAILED_CLOSED`).

## D7 npm Audit Assessment (2026-08-21)

- `npm audit --json` reports six high-severity dependency findings and no critical findings:
  `next@15.5.23` through `postcss@8.4.31` and `sharp@0.34.5`, plus `snarkjs@0.7.6`
  through `bfj@7.1.0`, `jsonpath@1.3.0`, and `underscore@1.13.6`.
- The application has no runtime `next/image` import and no path that accepts attacker-controlled
  CSS or image-processing input. The generated `next-env.d.ts` image type reference is not runtime
  reachability. Upgrade Next/sharp/PostCSS together in a separately tested framework migration.
- `snarkjs` is used by the SDK prover and ceremony/operator tooling, but repository search found no
  direct `bfj`, `jsonpath`, or `underscore` application import. The browser uses the dedicated
  `snarkjs/build/browser.esm.js` worker entry; the vulnerable JSON-processing chain is therefore not
  demonstrated in the deployed browser or disclosure-service request paths. Upgrade `snarkjs` and
  revalidate proof vectors/bundles separately.
- No dependency was changed and no force-fix was run. A newly demonstrated production-reachable
  exploit path remains a release blocker; on current evidence these findings are tracked follow-up
  work and do not replace the missing D7 acceptance evidence.
