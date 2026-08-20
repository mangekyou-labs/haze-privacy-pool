# Haze security bug policy

This policy applies to the Haze Avalanche compliant pool product program.
It is not a paid-firm engagement letter and does not authorize production activation.

## Severity

- Critical and high findings must be fixed before any release that claims the
  independent-audit task is complete. Regression tests must cover the remediating
  change.
- Medium findings may remain open only with a named owner and an approved
  disposition (`approved-deferral` or `accepted-risk`) bound to a later task.
- Low findings are tracked; they do not block a library-first audit report.

## Reporting

- Report suspected vulnerabilities privately to the Haze security owner. Do not
  open a public issue that includes exploits, witness material, or key material.
- Do not include production proving keys, KMS secrets, or customer PII in a
  report or fixture.

## Disposition tokens

- `fix-before-release` applies to every critical and high finding.
- `owner-and-disposition` applies to every remaining medium finding.

## Release gates

- Open critical or high findings block T7.3 acceptance.
- SC-09 `independent_audit.approved` stays closed until the four production
  approvals exist together. A library-first audit report is not that approval.
- Production spend Groth16 keys remain `KEYS_MISSING` as an operator-owned hard
  stop. T7.5 records operational readiness; it does not authorize mainnet or flip
  SC-09.
