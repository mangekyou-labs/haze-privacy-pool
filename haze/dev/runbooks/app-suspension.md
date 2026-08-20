# Application suspension

Owner: application-ops
Escalation: incident-commander → super-auditor

Hosted HTTP frontends remain operator-owned (T7.2 closed M-04 as library-first). Suspension is a policy and membership action, not a CDN takedown.

## Procedure

1. Super-auditor schedules application suspension through governance.
2. After the delay, mark the application inactive in `ApplicationRegistry`. New deposits and spends for that `applicationId` must fail membership checks.
3. Other applications keep operating. Do not pause the whole pool unless the incident is cross-app.
4. Notify users through `user-communication.md`. Do not disclose other applications' traffic.
5. Re-enable only with a new governance action and a written incident review.

## Local tabletop

Verified against `ApplicationRegistry` pause/membership guards and library-first stack isolation.

Fuji-configured rehearsal: chainId 43113, Circle USDC `0x5425890298aed601595a70AB815c96711a31Bc65`, and `deployments/fuji-v1.json`. Live broadcast remains operator-owned.
