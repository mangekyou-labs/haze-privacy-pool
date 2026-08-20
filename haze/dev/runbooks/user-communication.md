# User communication

Owner: communications
Escalation: incident-commander → communications-lead

## Rules

- Say what users must do (pause, wait, emergency exit) without revealing other users or applications.
- Do not publish witnesses, policy plaintext beyond the public root, or signer material.
- Hosted status pages are out of scope until T7.1. Local rehearsal uses the in-process stack banner copy.

## Procedure

1. Incident commander approves a single status sentence and the affected `applicationId` (or "all applications" if paused).
2. Communications posts that sentence to the application's documented channel.
3. If emergency exit is open, link `emergency-exit.md` and the cooldown duration only.
4. After restore, post a close-out that names the version hashes, not the root cause internals.

## Local tabletop

Verified by assembling this catalog and confirming redaction rules in `disclosure-incident.md`.

Fuji-configured rehearsal: chainId 43113, Circle USDC `0x5425890298aed601595a70AB815c96711a31Bc65`, and `deployments/fuji-v1.json`. Live broadcast remains operator-owned.
