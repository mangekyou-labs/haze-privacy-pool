# Haze: Private Compliant USDC Layer on Avalanche

This packet uses the Stellar Community Fund Build Award field structure as a reusable milestone template. It is not a filing to SCF, Retro9000 (closed 2026-08-20), Team1 Mini ($10K), or Team1 Accelerator ($30K). It is portable for a future Avalanche / Blizzard grant or investor diligence. The Team1 Mini filing is `docs/grants/haze-team1-mini.md`.

- **Title:** Haze: Private Compliant USDC Layer on Avalanche
- **Amount:** $150,000
- **Category:** End-user application plus developer infrastructure
- **Timeline:** 24 weeks, three tranches, 10 / 20 / 30 / 40 payment split
- **Demo:** [Haze commercial host](https://haze-avax.vercel.app)
- **Architecture:** `docs/grants/haze-private-compliant-layer.docx`

The canonical demo host is `haze-avax.vercel.app`. The former `haze-finance.vercel.app` and
`haze-pool.vercel.app` names are retained only as permanent redirect sources because they create
MetaMask impersonation/phishing signals; preview deployment URLs remain non-canonical.

## Products & Services

Haze delivers a compliance-ready privacy layer that enables users and application operators to run confidential USDC operations on Avalanche. More detail on the product is in the architecture document.

The packet covers production deployment of the following components:

1. **Privacy Pool DEX.** A web interface for wallet onboarding, USDC deposits, withdrawals, app-scoped private send, public swap-and-shield, history, and emergency exit. Users prove locally and submit their own transactions. There is no mandatory relayer.

2. **Compliance Portal.** A web interface for application administrators, auditors, and Haze governance. It supports investigation workflows, role-based access, report generation, and controlled selective disclosure. All access is logged and scoped by role, application, and time window.

3. **Compliance services layer.** Off-chain services for authentication, role resolution, encrypted audit event indexing, and controlled data disclosure for authorized auditors. Tranche 1 delivers these as network-accessible services. The current repository implements the same logic as libraries used by the demo host.

4. **Private transaction engine.** A non-custodial execution layer for confidential deposits, app-scoped transfers, withdrawals, and swap-and-shield, with encrypted event logging and selective disclosure. Contracts are versioned and immutable. Upgrades are new deployments, not proxy writes.

5. **Developer SDK and APIs.** Integration tools that let wallets and applications enable confidential, compliant USDC transactions without implementing custom privacy or compliance infrastructure. Proofs are generated in the user’s browser.

6. **Application gatekeeper framework.** A reference service that enforces application-level authorization, policy controls, and transaction validation before the pool will accept a transaction. Integrators may replace it.

All components are delivered as reusable, developer-first infrastructure for payments, payroll, treasury, and settlement on Avalanche. Haze does not operate KYC.

Production proving keys stay behind a public ceremony. Development keys used by the current demo are labeled as such.

## Requested Budget

$150,000

Deliverable budgets below sum to $135,000. The remaining $15,000 is the 10% kickoff payment under a 10 / 20 / 30 / 40 split. Kickoff covers program management across the three tranches, not a fourth engineering workstream.

Completed protocol, circuit, contract, and library work is traction. It is not billed again.

## Traction Evidence

Haze already has a working proof of concept on Avalanche Fuji, including a live demo of the Privacy Pool DEX and Compliance Portal:

https://haze-avax.vercel.app

The PoC demonstrates:

- Private USDC deposits and withdrawals using zero-knowledge proofs
- Encrypted audit events and selective disclosure
- A role-based compliance portal with investigation workflows
- Application-gated entry with wallet-signed authorizations
- Browser-side proving, with the user submitting their own transactions

Pool contracts are deployed on Fuji against Circle USDC. The public demo uses development proving keys. A production ceremony and an independent security review are not claimed; those are Tranche 2.

This packet does not cite third-party volume, transaction counts, or TVL.

## Tranche 1 (Deliverable Roadmap) - MVP

### Milestone 1: Production Compliance Infrastructure (Testnet)

This tranche delivers the compliance and selective-disclosure foundation needed for institutions and regulated applications to use confidential workflows on Avalanche Fuji. It also packages a public testnet demo. Production proving keys are Tranche 2.

**[Deliverable 1] Compliance Authentication and Access-Control Backend**

**Brief description:**

Implement the testnet authentication and access-control layer for auditors, operators, and administrators, and expose the existing compliance and gatekeeper logic as network services.

**How to measure completion:**

- Sign-In with Ethereum works end-to-end for authorized users
- Protected endpoints enforce application and role-based permissions
- Unauthorized callers are rejected
- Testnet deployment is available for demonstration on the public host

**Estimated completion:** Weeks 1-5

**Budget:** $12,000

**Cost breakdown:**

- Authentication, session handling, and permission enforcement: $8,000
- Integration tests against the existing libraries: $2,000
- Deployment onto the public host: $2,000

**[Deliverable 2] Selective Disclosure Services and Testnet Walks**

**Brief description:**

Stand up the services that ingest encrypted audit events, support scoped disclosure, and log reviewer access, then complete public-host operator and auditor walks against Fuji.

**How to measure completion:**

- Encrypted audit events from Fuji activity are indexed
- An operator can deposit and withdraw USDC from the public demo, producing Fuji transaction hashes
- An auditor can open a case and complete a scoped disclosure
- All disclosure actions are logged in an audit trail
- The demonstration states that production proving keys are not yet installed

**Estimated completion:** Weeks 3-7

**Budget:** $8,000

**Cost breakdown:**

- Encrypted event ingestion, scoped disclosure, and access logging: $5,000
- Live-walk validation and issue triage: $3,000

**[Deliverable 3] Compliance Portal UI**

**Brief description:**

Deliver the testnet web interface for investigators and administrators, connected to live Fuji activity.

**How to measure completion:**

- Administrators can delegate auditors, open cases, and export application history
- Auditors can create and manage assigned investigation cases
- Users can search, filter, and export records within their role
- UI components are restricted by role
- Super-auditor access is limited to a named case, expires, and does not include custody of user funds
- Portal is connected end-to-end to authentication and disclosure services

**Estimated completion:** Weeks 4-8

**Budget:** $6,000

**Cost breakdown:**

- Investigator and admin UI integration: $4,000
- Role-restricted views, search, filtering, and export: $2,000

**[Deliverable 4] Testnet QA, Documentation, and Public Demo**

**Brief description:**

Package the tranche for external review through deployment, validation, and technical documentation.

**How to measure completion:**

- Compliance services and portal are available on the public host
- End-to-end demo of authentication, investigation flow, and selective disclosure is available
- Documentation explains authentication, role-based access, disclosure behavior, and the development-key status of the demo
- Architecture document matches this packet

**Estimated completion:** Weeks 7-8

**Budget:** $4,000

**Cost breakdown:**

- Testnet deployment and release packaging: $2,500
- Technical documentation and demo preparation: $1,500

## Tranche 2 (Deliverable Roadmap) - Testnet

### Milestone 2: Production Keys, Independent Review, and Testnet Hardening

This tranche replaces development proving keys with a production ceremony, completes independent security review, and repeats Fuji walks with production artifacts so reviewers can treat the testnet as production-shaped.

**[Deliverable 1] Production Proving Ceremony**

**Brief description:**

Run a production Groth16 ceremony for the spend circuit and install the resulting keys on Fuji.

**How to measure completion:**

- Ceremony transcript and artifact hashes are published
- Production proving keys are installed for the spend circuit
- Development keys are retired from the public demo
- Fuji proving with the new keys succeeds

**Estimated completion:** Weeks 6-12

**Budget:** $18,000

**Cost breakdown:**

- Ceremony operations and transcript packaging: $10,000
- Verifier regeneration, artifact signing, and provenance records: $5,000
- Fuji proving QA with production artifacts: $3,000

**[Deliverable 2] Independent Security Review**

**Brief description:**

Independent review of contracts, circuits, gatekeeper authorizations, and the disclosure path, plus a public remediation log.

**How to measure completion:**

- Signed engagement or published report
- Findings tracker with severity and status
- Remediation merged or explicitly deferred with owner and date

**Estimated completion:** Weeks 8-16

**Budget:** $15,000

**Cost breakdown:**

- External review engagement: $12,000
- Remediation engineering: $3,000

**[Deliverable 3] Threat Model and Monitoring Plan**

**Brief description:**

Publish a threat model and a monitoring plan for the pool, indexer, authentication, and disclosure paths.

**How to measure completion:**

- Threat model covers double-spend, authorization replay, mismatched audit envelopes, and super-auditor grant abuse
- Monitoring plan names metrics and owners for proof failures, indexer lag, disclosure access, and emergency exit
- Both documents are linked from this packet

**Estimated completion:** Weeks 8-12

**Budget:** $8,000

**Cost breakdown:**

- Threat-model writeup and review: $4,000
- Monitoring design and alert stubs: $4,000

**[Deliverable 4] Testnet QA with Production Artifacts**

**Brief description:**

Repeat operator and auditor walks on Fuji using production proving keys.

**How to measure completion:**

- Deposit, app-scoped private send, withdraw, and swap-and-shield complete on Fuji
- Encrypted audit events decrypt under a valid case grant and fail under a revoked grant
- Emergency-exit cooldown is exercised in a test application

**Estimated completion:** Weeks 12-16

**Budget:** $4,000

**Cost breakdown:**

- End-to-end QA and issue triage: $3,000
- Walk documentation updates: $1,000

## Tranche 3 (Deliverable Roadmap) - Mainnet

### Milestone 3: Mainnet Deployment and Production Release

This tranche moves the system from testnet functionality to production-grade Avalanche C-Chain infrastructure that ecosystem participants can rely on for real usage.

**[Deliverable 1] Mainnet Confidential Transaction Engine**

**Brief description:**

Finalize and productionize the confidential transaction layer for live use on Avalanche C-Chain, including mainnet-specific validation and reliability work after testnet delivery.

**How to measure completion:**

- Mainnet confidential execution layer is deployed against Circle USDC
- Mainnet shield, app-scoped private send, unshield, and swap-and-shield flows complete successfully
- Pool contracts remain immutable; upgrades are new versions
- Mainnet audit event emission and transaction observability are functioning in production

**Estimated completion:** Weeks 14-20

**Budget:** $20,000

**Cost breakdown:**

- Mainnet deployment, configuration, and release of shield, transfer, and unshield flows: $8,000
- Mainnet-specific iteration on transaction lifecycle, edge-case fixes, and authorization logic: $8,000
- Production validation, observability, and live transaction verification: $4,000

**[Deliverable 2] Mainnet Compliance Infrastructure**

**Brief description:**

Move the compliance stack from testnet to production and complete the reliability work needed for live selective-disclosure workflows.

**How to measure completion:**

- Authentication, role-based access, and disclosure services are connected to mainnet
- Mainnet audit event indexing is operating
- Authorized reviewers can perform live selective disclosure
- Unauthorized disclosure is rejected and logged
- Monitoring and traceability are enabled for production flows

**Estimated completion:** Weeks 16-22

**Budget:** $15,000

**Cost breakdown:**

- Mainnet rollout of authentication, disclosure, and audit indexing: $7,000
- Mainnet-specific fixes for event indexing, disclosure correctness, and permission enforcement: $5,000
- Production monitoring, QA, and traceability validation: $3,000

**[Deliverable 3] Production SDK, Portal, and Reference Application**

**Brief description:**

Release stable mainnet-ready SDK components and bring the portal and reference app to mainnet for live developer demonstrations.

**How to measure completion:**

- Versioned SDK release is published
- Compliance Portal investigation workflows operate on live mainnet events
- Mainnet version of the Privacy Pool DEX is available on the public host
- Mainnet integration documentation is available for wallets and application operators

**Estimated completion:** Weeks 18-23

**Budget:** $12,000

**Cost breakdown:**

- Mainnet-ready SDK updates and release engineering: $5,000
- Mainnet integration of portal and reference application flows: $4,000
- Mainnet documentation, guides, and integration examples: $3,000

**[Deliverable 4] Production QA, Monitoring, and Release Enablement**

**Brief description:**

Finish the mainnet release with the reliability work needed for production adoption. Proving keys remain ceremony-gated.

**How to measure completion:**

- Final production QA is completed
- Monitoring and alerting are active on proof failures, indexer lag, disclosure access, and emergency-exit state
- Public repositories, release assets, and deployment documentation are available
- Operational runbooks are available for reviewers and integrators

**Estimated completion:** Weeks 20-24

**Budget:** $13,000

**Cost breakdown:**

- Final regression testing, issue triage, and release validation: $5,000
- Monitoring, alerting, and production incident visibility: $4,000
- Release documentation, operational runbooks, and open-source packaging: $4,000

## Team

Bios are labeled placeholders until legal names and links are supplied. Do not treat these as a fabricated roster.

**[Name], protocol and cryptography**

[2 to 3 sentence bio. Zero-knowledge circuits and ceremony operations.]

GitHub: `[github_profile_url]`

**[Name], contracts and EVM**

[2 to 3 sentence bio. Pool contracts, policy registries, swap-and-shield, emergency exit.]

GitHub: `[github_profile_url]`

**[Name], compliance services**

[2 to 3 sentence bio. Gatekeeper, indexer, authentication, disclosure, and datastore.]

GitHub: `[github_profile_url]`

**[Name], client and proving**

[2 to 3 sentence bio. TypeScript SDK, browser prover, encrypted vault.]

GitHub: `[github_profile_url]`

**[Name], product surfaces**

[2 to 3 sentence bio. Privacy Pool DEX and Compliance Portal.]

LinkedIn: `[linkedin_profile_url]`

**Applicant legal name:** `[Applicant legal name]`

## Open-source plan

- Publish pool contracts, circuits, reference gatekeeper / indexer / authentication / disclosure services, and the TypeScript SDK.
- Keep production proving keys behind the ceremony transcript. Development keys stay labeled development.
- Do not ship upgradeable pool proxies. New versions are new deployments.

## Non-goals

- Mandatory relayer or sponsored submission
- Private value moving across applications
- Haze-operated KYC
- Production use before the proving ceremony and independent review
- Unbounded auditor access
- A Stellar / Soroban port
