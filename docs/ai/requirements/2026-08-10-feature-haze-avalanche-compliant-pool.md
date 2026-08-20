---
phase: requirements
title: Haze Avalanche Compliant Pool Requirements
description: Product requirements for an application-gated private USDC pool and compliance portal on Avalanche
---

# Haze Avalanche Compliant Pool Requirements

## Problem Statement

The current repository is a Stellar/Soroban reference implementation of private payments. A
network change or visual reskin would not create a differentiated product, and the reference app
does not provide the institutional onboarding, application authorization, encrypted audit data,
case management, or role-scoped disclosure needed by regulated payment products.

Regulated fintech, payment, and payroll applications need a way to offer shielded USDC transfers
without becoming blind to activity they are legally required to investigate. Their users need
non-custodial privacy and fund-liveness guarantees; application administrators need policy and
auditor controls; auditors need authenticated, attributable access to application-scoped records.

Haze solves this as a distinct Avalanche C-Chain product. It combines a shared zero-knowledge
USDC pool with application gatekeepers, ASP-style association-set policy, encrypted audit events,
and a separate compliance portal. It reuses cryptographic ideas from the Stellar codebase but does
not port Stellar contracts, SEP authentication, or the existing demo frontend.

## Goals & Objectives

### Primary goals

- Deliver an EVM-native, non-custodial USDC privacy pool on Avalanche C-Chain using Groth16 over
  BN254, note commitments, Merkle proofs, and nullifiers.
- Require every normal deposit, private transfer, and withdrawal to be associated with a registered
  application and authorized by its gatekeeper through an expiring, replay-protected EIP-712
  authorization.
- Apply two-tier compliance: Haze-governed, timelocked ASP-style association sets plus each
  application's own KYC/AML eligibility decision.
- Ship a user-facing Privacy Pool DEX frontend for direct USDC shielding, public swap-and-shield
  into USDC, same-application private transfers, withdrawals, and private history.
- Ship a separate Compliance Portal frontend with application-administrator, auditor, and Haze
  governance workspaces.
- Produce full encrypted, application-scoped audit records that authorized institutional auditors
  can investigate and export without exposing those records publicly.
- Provide an integration SDK, a reference application gatekeeper, and documented APIs so regulated
  applications can embed Haze without adopting the Haze frontend.

### Secondary goals

- Operate one shared USDC reserve and commitment tree instead of fragmenting contracts per
  application, while acknowledging that public application authorization can make the effective
  anonymity set application-local and cryptographically preventing cross-application private value
  movement in the MVP.
- Support policy-checked fund recovery through a seven-day emergency-exit cooldown when an
  application is suspended or unavailable.
- Keep contracts immutable and versioned so circuit, verifier, and trusted-setup changes are
  independently deployable and auditable.
- Establish a Fuji-first release process with explicit security and operational gates before
  C-Chain mainnet activation.

### Non-goals

- Private execution of the source-token swap. Swap-and-shield routing is public; privacy starts
  when the resulting USDC is committed to the pool.
- A multi-asset shielded pool, arbitrary private swaps, an in-pool AMM, lending, liquidity
  positions, or other private DeFi adapters in the MVP.
- Cross-application private transfers. A future version may require authorization from both
  applications.
- A Haze-operated KYC provider or shared customer identity database.
- Gas sponsorship, mandatory relayers, or account-abstraction paymasters in the MVP.
- Deployment to a dedicated Avalanche L1.
- Proxy-upgradeable pool or verifier contracts.
- Production use before the required Fuji pilot, independent audit, production trusted ceremony,
  and operational-readiness review are complete.

## User Stories & Use Cases

### End user

- As an approved application user, I want to connect an EVM wallet and derive or recover my Haze
  shielded account locally so that the application never controls my private spending key.
- As a user, I want an app-scoped Haze address containing separate spending and note-encryption
  public keys so that another approved user can send me a note that only I can discover and decrypt.
- As a user holding USDC, I want to shield a variable USDC amount into Haze after application and
  policy checks so that I receive a private note.
- As a user holding another application-approved Avalanche token, I want one swap-and-shield flow
  that publicly swaps the token into USDC and atomically deposits the USDC into Haze.
- As a user, I want to privately send USDC to another Haze user in the same application without
  exposing note ownership, the transfer amount, or transaction linkage.
- As a user, I want to withdraw a variable USDC amount to a public EVM address with application
  approval during normal operation.
- As a user, I want a policy-checked emergency exit after a seven-day cooldown if my application is
  suspended or unavailable, so that the gatekeeper cannot strand my funds.
- As a user, I want to restore my notes from chain data and view my own private transaction history.

### Application administrator

- As an application administrator, I want my application registered with its gatekeeper key,
  manifest, policy reference, and audit-key configuration so that its Haze permissions are
  verifiable.
- As an administrator, I want my existing KYC/AML system to decide user eligibility and the
  gatekeeper to issue narrow EIP-712 transaction authorizations.
- As an administrator, I want to assign or revoke auditors, configure disclosure scopes, review my
  application's full transaction history, and export reports.
- As an administrator, I want audit-key ownership to remain under my organization's governance/KMS.
- As an administrator, I want a versioned audit public key and application-membership root published
  through authenticated configuration so clients can encrypt records and prove recipient eligibility
  without exposing decryption keys or KYC data.

### Application auditor

- As an institutional auditor, I want to authenticate with organizational identity and bind my
  EVM address through SIWE so that access is attributable to both me and my organization.
- As an auditor, I want case- and application-scoped access to decrypted transaction identifiers,
  initiators, counterparties, assets, amounts, timestamps, and policy versions.
- As an auditor, I want denied and successful disclosure attempts recorded in a tamper-evident,
  write-once access log and exports marked with their scope and provenance.

### Haze governance operator

- As a Haze governance operator, I want a multisig and timelock to register applications, activate
  contract versions, update association-set roots, suspend compromised applications, and trigger
  documented incident procedures.
- As a Haze super auditor, I want explicitly granted cross-application case access without turning
  ordinary application auditors into global viewers.

### Application integrator

- As an integrator, I want a TypeScript SDK and a reference gatekeeper with stable contracts and API
  schemas so that I can add Haze to an existing regulated application.

### Functional requirements

- **FR-01 — Pool:** one shared, USDC-only pool shall support direct deposits, 2-input/2-output
  private transactions with change, variable public withdrawals, recipient note ciphertexts, and
  historical Merkle roots.
- **FR-02 — Application binding and eligibility:** notes and transaction proofs shall bind to an
  application ID; every nonzero input and output note key shall prove membership in the active
  application eligibility root and non-membership in the active Haze global blocklist root. The MVP
  shall reject cross-application private spends and outputs.
- **FR-03 — Authorization:** normal pool actions shall require a registered gatekeeper's EIP-712
  authorization containing the user, application, pool, action, intent hash, application and Haze
  policy versions, audit-data commitment, audit ciphertext hash, nonce, and expiry.
- **FR-04 — Policy:** normal proofs shall bind to the application membership root and Haze global
  non-membership root active at execution. Stale, future, or unrecognized roots and versions shall
  fail closed with no post-activation grace period. Haze blocklist subjects shall cover app-scoped
  note keys and public EVM addresses through canonical domain-separated encodings.
- **FR-05 — Swap-and-shield:** an adapter-based router shall accept only configured source tokens
  and routes, enforce slippage/deadline limits, swap publicly to USDC, and atomically shield the
  result without retaining user funds.
- **FR-06 — Truthful audit binding:** for normal actions, the gatekeeper shall construct a canonical
  audit record, envelope-encrypt it to the application's versioned audit public key, and authorize
  both its ciphertext hash and an `audit_data_commitment`. The circuit shall recompute that commitment
  from the real private transaction fields and a hidden salt. An emergency exit shall use the same
  circuit/contract-bound canonical commitment but may construct its envelope client-side because no
  gatekeeper participates. Disclosure shall verify the commitment and ciphertext hash after decryption.
- **FR-07 — Indexing:** the audit indexer shall reconcile finalized C-Chain events, handle reorgs and
  retries idempotently, retain recipient and audit ciphertexts, and expose application-scoped query
  APIs.
- **FR-08 — Auditor access:** the authorization service shall combine organizational OIDC/SAML
  identity with SIWE wallet binding and issue short-lived tokens scoped by role, application, case,
  fields, and time range.
- **FR-09 — Disclosure:** the disclosure service shall revalidate every request, use
  application-controlled envelope keys, return only authorized fields, and append an access log for
  success and denial.
- **FR-10 — Portals:** the Privacy Pool DEX frontend and the separate Compliance Portal shall be
  independently deployable and shall never expose administrative or auditor controls to ordinary
  users.
- **FR-11 — Governance:** application registration, policy-root activation, version activation, and
  emergency actions shall be executed by a Haze multisig subject to a timelock except where a
  narrowly scoped pause role is explicitly documented.
- **FR-12 — Emergency exit:** any note owner shall be able to register an exit request at any time.
  After a seven-day cooldown, the user may withdraw through a valid ownership/nullifier proof and
  the current Haze global blocklist policy for both note key and public recipient, without an
  application membership proof or gatekeeper signature. Public policy events or independent mirrors
  shall make the required Haze witnesses obtainable without the application.
- **FR-13 — Recipient delivery:** an app-scoped Haze address shall encode the recipient note and
  X25519 encryption public keys plus application/version/checksum data. Every real output shall emit
  an authenticated recipient ciphertext; the recipient shall decrypt it and recompute the note
  commitment before accepting it. No public wallet-to-shielded-key registry is required.
- **FR-14 — Version migration:** immutable pool versions shall remain exit-capable for a documented
  support window. The MVP migration path is a public withdrawal followed by a new shield into the
  replacement version; private cross-version migration is deferred.

## Success Criteria

- **SC-01:** On Fuji, an approved user can complete direct shield, swap-and-shield, same-application
  private send, normal withdrawal, seven-day emergency exit, and public exit-and-re-shield migration
  simulations through the Privacy Pool DEX frontend.
- **SC-02:** The contracts reject invalid proofs, reused nullifiers, inflation, expired or replayed
  gatekeeper authorizations, unregistered applications, stale policy roots, cross-application
  spends, ineligible inputs or outputs, unauthorized source tokens, unbound audit payloads, and audit
  commitments that do not represent the proven private transaction.
- **SC-03:** The Compliance Portal supports application onboarding, auditor delegation, case-scoped
  investigation, least-privilege field disclosure, report export, and governance operations under
  the intended roles.
- **SC-04:** An ordinary application auditor cannot query another application's records; a Haze
  super-auditor grant is explicit, case-bound, expiring, and logged.
- **SC-05:** Losing local indexed state does not lose funds: a user can re-derive the domain-separated
  spending/encryption keys, decrypt recipient note events, verify their commitments, and reconstruct
  owned notes from indexed chain events.
- **SC-06:** Browser proof generation is P95 at or below 15 seconds on the documented reference
  desktop, and proof verification plus pool execution remains within the published Avalanche gas
  budget established before Fuji release.
- **SC-07:** Non-proving service APIs are P95 at or below 500 ms under the documented MVP load;
  finalized audit events are queryable within 10 seconds under normal operation.
- **SC-08:** Security-critical circuits, contracts, authorization, disclosure, and key-handling code
  have tests for every branch and failure mode, plus contract fuzz/invariant coverage and end-to-end
  regression coverage for every workflow in SC-01 through SC-05.
- **SC-09:** No production deployment can activate until the Fuji pilot, independent
  smart-contract/circuit audit, production Groth16 multi-party ceremony, and operational incident
  review have recorded approvals and artifact hashes.
- **SC-10:** Product copy and documentation state accurately that source-token swaps and public
  deposits, withdrawals, application affiliation, and version migrations are observable and do not
  claim end-to-end amount or cross-application privacy.

## Constraints & Assumptions

### Technical constraints

- Avalanche C-Chain and its EVM execution environment are the MVP deployment target; Fuji is the
  pre-production network.
- The shielded asset is the configured native USDC contract for each environment. Source tokens in
  swap-and-shield are never represented as private notes.
- Groth16 over BN254 requires circuit-specific proving/verifying keys and a production multi-party
  setup ceremony before mainnet.
- Existing Circom/Poseidon2, note, ASP, and disclosure concepts may be adapted after compatibility
  and security review. Stellar/Soroban contracts, SEP-01/SEP-10 flows, Freighter integration, and
  network-specific SDK code shall not define the new product architecture.
- Users pay C-Chain gas and submit transactions directly in the MVP.
- Application KYC status and personal identity data stay outside Haze contracts and encrypted event
  payloads shall contain only the minimum investigation data approved by policy.
- Pool, verifier, and registry releases are immutable and versioned; migrations deploy new versions
  and use a publicly linkable exit-and-re-shield flow in the MVP.
- Application membership roots may be updated by the registered application policy authority.
  Haze global blocklist roots are activated through Haze governance. The pool accepts only the roots
  active at execution; a scoped pause is the emergency control while a scheduled root update waits.

### Business and rollout constraints

- The initial customer is a regulated fintech, payment, or payroll application able to operate a
  gatekeeper and application-controlled KMS integration.
- Haze supplies compliance infrastructure and auditability but does not make legal claims that an
  integration is compliant in every jurisdiction.
- Mainnet rollout is gated by the four approvals in SC-09. Development/test proving keys must be
  visibly labeled non-production.

### Named assumptions and explicit deferrals

- The Privacy Pool DEX frontend and Compliance Portal are separate deployments, while administrator,
  auditor, and Haze-governance experiences are role-gated workspaces within the portal.
- The first transaction circuit uses two inputs and two outputs to support consolidation and change;
  circuit sizing may be revisited only through a new version and benchmark evidence.
- Shielded keys are derived locally from a domain-separated wallet signature and cached in an
  encrypted local vault; smart-contract-wallet support may require a later recovery adapter.
- App-scoped Haze addresses carry note and X25519 encryption public keys. Applications map those
  keys to their private KYC subject records and must prevent a blocked identity from bypassing policy
  by registering a fresh key. Haze does not become a global identity or sanctions provider.
- Recipient note encryption and auditor encryption are separate channels. Recipient ciphertexts
  support note discovery; gatekeeper-generated auditor ciphertexts support attributable disclosure.
- Emergency exit is always requestable and deliberately limits application custody power. It still
  requires the current Haze global blocklist proof and produces a full encrypted audit event.
- The exact DEX aggregator, cloud KMS, OIDC/SAML provider, hosting platform, and infrastructure vendor
  are intentionally deferred. Their interfaces must be provider-neutral and selected before the
  corresponding implementation milestone.
- Product dates and team-size estimates are deferred until staffing and audit/vendor availability
  are known. The implementation plan shall use dependency-ordered milestones instead of unsupported
  calendar promises.

## Questions & Open Items

No material product or architecture questions remain for the requirements phase. Provider selection,
gas-budget measurement, infrastructure procurement, legal review, and production ceremony scheduling
are explicitly deferred to their named implementation or rollout milestones and cannot silently change
the requirements above.

Commercial one-origin (2026-08-18): the two independently deployable frontends remain the library
boundary; the shipped commercial app is one origin with grant-based workspaces. Business rules
(KEYS_MISSING, broadcast:false, no embedded signing secret) are unchanged.
