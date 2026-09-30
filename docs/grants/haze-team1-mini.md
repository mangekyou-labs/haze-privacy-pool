# Haze: Private Compliant USDC Layer on Avalanche

This packet is a Team1 Mini Grant filing. It is original Tranche 1 of `docs/grants/haze-build-award.md`, priced at $10,000 instead of $30,000, and limited to Deliverables 1–3 (the Mini milestones field). It is not a filing to SCF, Retro9000, or Team1 Accelerator. Architecture detail is in the companion document.

- **Title:** Haze: Private Compliant USDC Layer on Avalanche
- **Program:** Team1 Mini Grant (open application)
- **Amount:** $10,000
- **Category:** End-user application plus developer infrastructure
- **Timeline:** 8 weeks, one tranche
- **Demo:** [Haze commercial host](https://haze-avax.vercel.app)
- **Architecture:** `docs/grants/haze-private-compliant-layer.docx`
- **Apply:** [Builder Hub — Team1 Mini Grants](https://build.avax.network/grants/team1-mini-grants)
- **Applicant:** Kyler ([GitHub](https://github.com/MrSufferer))

The canonical demo host is `haze-avax.vercel.app`. Preview deployment URLs remain non-canonical. Production proving keys, independent review, and C-Chain mainnet remain the later tranches in `docs/grants/haze-build-award.md`.

## Products & Services

Haze delivers a compliance-ready privacy layer that enables users and application operators to run confidential USDC operations on Avalanche. More detail on the product is in the architecture document.

1. **Privacy Pool DEX.** Wallet onboarding, USDC deposits, withdrawals, app-scoped private send, public swap-and-shield, history, and emergency exit. Users prove locally and submit their own transactions. There is no mandatory relayer.

2. **Compliance Portal.** Investigation workflows, role-based access, report generation, and controlled selective disclosure. All access is logged and scoped by role, application, and time window.

3. **Compliance services layer.** Authentication, role resolution, encrypted audit event indexing, and controlled disclosure, delivered as network-accessible services.

4. **Private transaction engine.** Non-custodial confidential deposits, app-scoped transfers, withdrawals, and swap-and-shield, with encrypted event logging. Contracts are versioned and immutable.

5. **Developer SDK and APIs.** Browser proving so wallets and applications can enable confidential, compliant USDC without custom privacy infrastructure.

6. **Application gatekeeper framework.** Application-level authorization before the pool accepts a transaction. Integrators may replace it.

Haze does not operate KYC. Production proving keys stay behind a public ceremony. Development keys used by the current demo are labeled as such.

## Requested Budget

$10,000

Original Tranche 1 in `docs/grants/haze-build-award.md` is $30,000 across four deliverables. This Mini files Deliverables 1–3 of that milestone at $10,000. There is no kickoff tax and no 10 / 20 / 30 / 40 split.

Completed protocol, circuit, contract, and library work is traction. It is not billed again.

## Traction Evidence

Working proof of concept on Avalanche Fuji: https://haze-avax.vercel.app

- Private USDC deposits and withdrawals using zero-knowledge proofs
- Encrypted audit events and selective disclosure
- Role-based compliance portal
- Application-gated entry with wallet-signed authorizations
- Browser-side proving; the user submits their own transactions

Live Poseidon pool `HazePoolPoseidon` at `0x00BEB0A5D709d0F093952fD374Dbbf3d0d21d550` against Circle USDC on Fuji. The public demo uses development proving keys. A production ceremony and an independent security review are not claimed.

This packet does not cite third-party volume, transaction counts, or TVL.

What is not yet proved on the public demo, and is billed in Deliverable 2: deposit from wallet A and pay a fresh address B so a Fuji explorer cannot link depositor identity to recipient, in the sense of [Vitalik’s Privacy Pools](https://vitalik.eth.limo/general/2023/09/11/privacypools.html).

## Why you deserve this grant

Applicant: **Kyler** — [github.com/MrSufferer](https://github.com/MrSufferer). Bio: distributed systems and ZK.

**Zero-knowledge.** This is not a first ZK prototype. Public work includes [solana-zk](https://github.com/MrSufferer/solana-zk); [Blink](https://github.com/MrSufferer/blink) (privacy social payments on Solana / Elusiv, OPOS Hackathon 2023 Elusiv 2nd Track, live at [blink-gift.vercel.app](https://blink-gift.vercel.app)); [Paymage](https://github.com/MrSufferer/paymage) (ZK payroll with compliance, [paymage.vercel.app](https://paymage.vercel.app)); [zk blackjack](https://github.com/MrSufferer/sol-blackjack); Hollow mixers on [Solana](https://github.com/MrSufferer/hollow-sol) and [Aleo](https://github.com/MrSufferer/hollow-leo); a [shielded on-ramp SDK](https://github.com/MrSufferer/potara-onramp-sdk); a [private Uniswap v4 hook](https://github.com/MrSufferer/hollow-hook); and encrypted-memory / confidential-oracle / [encrypted-perps](https://github.com/MrSufferer/mgk-solana) experiments.

**Shipped products, live users.** The same profile has kept other products on public hosts that real users can use on mainnet networks (Solana, EVM, NEAR) — including Blink, Paymage, [Lavish Lair](https://lavishlair.vercel.app), [NFT141](https://nft141-exchange.vercel.app), [Vellum](https://vellum-finance.vercel.app), [Jucci Pay](https://juccipay.vercel.app), and [Velopay](https://velopay.vercel.app). This packet does not invent user counts or TVL. Mini funds Haze’s remaining Fuji compliance hosts and the unlinkability walk, not a first app.

## Tranche 1 (Deliverable Roadmap) - MVP

### Milestone 1: Production Compliance Infrastructure (Testnet)

This tranche delivers the compliance and selective-disclosure foundation needed for institutions and regulated applications to use confidential workflows on Avalanche Fuji. It also packages a public testnet demo. Production proving keys are a later tranche.

**[Deliverable 1] Compliance Authentication and Access-Control Backend**

**Brief description:**

Implement the testnet authentication and access-control layer for auditors, operators, and administrators, and expose the existing compliance and gatekeeper logic as network services.

**How to measure completion:**

- Sign-In with Ethereum works end-to-end for authorized auditors, operators, and administrators
- Session issue and verification succeed for those roles
- Protected endpoints enforce application and role-based permissions; unauthorized callers are rejected
- Gatekeeper authorization is available as a network service before the pool will accept a transaction
- Integration tests cover the existing compliance and gatekeeper libraries against this authentication layer
- Testnet deployment is available for demonstration on the public host, and the commercial demo and compliance portal call this backend there

**Estimated completion:** Weeks 1-5

**Budget:** $4,600

**Cost breakdown:**

- Authentication, session handling, and permission enforcement: $3,050
- Integration tests against the existing libraries: $775
- Deployment onto the public host: $775

**[Deliverable 2] Selective Disclosure Services and Testnet Walks**

**Brief description:**

Stand up the services that ingest encrypted audit events, support scoped disclosure, and log reviewer access, then complete public-host operator and auditor walks against Fuji.

**How to measure completion:**

- Encrypted audit events from Fuji activity are indexed
- An operator can deposit and withdraw USDC from the public demo, producing Fuji transaction hashes
- Unlinkability (Vitalik Privacy Pools, testnet): deposit USDC from wallet A, then private send or withdraw to a **fresh** address B. A Fuji explorer cannot link A’s deposit identity to B as the payment recipient. Unshield to the same wallet is not this proof. Users self-submit, so `tx.from` remains the authorized user; the broken link is depositor to recipient
- An auditor can open a case and complete a scoped disclosure
- All disclosure actions are logged in an audit trail
- The demonstration states that production proving keys are not yet installed

**Estimated completion:** Weeks 3-7

**Budget:** $3,100

**Cost breakdown:**

- Encrypted event ingestion, scoped disclosure, and access logging: $1,950
- Live-walk validation and issue triage: $1,150

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

**Budget:** $2,300

**Cost breakdown:**

- Investigator and admin UI integration: $1,550
- Role-restricted views, search, filtering, and export: $750

## Market / competitors

Regulated applications on Avalanche need shielded USDC without going blind to auditors. Mixers hide flow and fail compliance. Railgun and Aztec are the wrong chain. Avalanche Encrypted ERC is a confidential-balance model, not an application-gated pool with selective disclosure.

Haze is a USDC privacy pool on Avalanche C-Chain: application-gated entry, browser proving, user-submitted transactions, and auditor disclosure under a case grant. This Mini delivers testnet compliance infrastructure and the unlinkability walk. It is not a mixer, not an in-pool AMM, and not a mainnet launch.

## Team

Bios are labeled placeholders until legal names and links are supplied. Do not treat these as a fabricated roster.

**Applicant:** Kyler — [github.com/MrSufferer](https://github.com/MrSufferer)

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

## Builder Hub field map

The Mini apply form is login-gated. This appendix maps this packet onto the materials Team1 publishes for Mini (whitepaper / litepaper, prototype, market analysis, team). It does not invent unseen form questions.

| Typical Mini material | This packet |
|---|---|
| Project / idea | Title, Products & Services |
| Whitepaper / litepaper | `docs/grants/haze-private-compliant-layer.docx` plus this file |
| Prototype | https://haze-avax.vercel.app |
| Market analysis | Market / competitors |
| Team | Why you deserve this grant; Team (placeholders until legal names exist) |
| Ask | $10,000 |
| Timeline | 8 weeks |
| Milestones | Milestone 1, Deliverables 1–3 |
| What exists today | Traction Evidence |
| Later work | `docs/grants/haze-build-award.md` Tranches 2 and 3 |
