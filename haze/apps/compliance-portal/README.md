# Haze Compliance Portal

This independently deployable frontend contains the institutional product shell. T5.1 ships
role-scoped `/admin`, `/audit`, and `/governance` guards, shared Haze tokens, and privacy-copy
rules. Ordinary pool users have no portal role. T5.3 ships the library-first application
administration workspace (`createAdminWorkspace`): manifest/KMS registration, gatekeeper
signer health, auditor delegation, cases, application transaction reports, scoped exports,
and revoke. T5.4 ships the library-first auditor investigation workspace
(`createAuditWorkspace`): SIWE binding, assigned cases, field-limited search/export,
expiry/revocation, and personal access history. Static shells live in
`public/admin.html` and `public/audit.html`. T5.5 ships the library-first
governance workspace (`createGovernanceWorkspace`): timelocked schedules with
exact on-chain preview, versions/ceremony provenance, suspensions/emergency
status, and super-auditor grants without custody. Static shells also live in
`public/governance.html`. Hosted Next.js remains T6.2.

