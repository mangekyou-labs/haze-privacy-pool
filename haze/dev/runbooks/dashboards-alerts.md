# Dashboards and alerts

Owner: observability
Escalation: incident-commander → protocol-ops

Hosted metrics backends are out of scope. This runbook names the signals operators must watch on the in-process stack and later Fuji deploy.

## Signals

- Health/ready from `haze_protocol::ops` DurableStore
- Pause state (`HazeAccess.paused`)
- Indexer root mismatch vs on-chain
- Gatekeeper signature failures and rotation_id changes
- Emergency-exit requests and executions
- Disclosure job failures and redaction misses
- Coverage/perf/gas gate verify (`haze/dev/gates.mjs verify`)

## Alerts

Page protocol-ops on ready=false, root mismatch, or unexpected pause.
Page security-oncall on rotation without a scheduled governance action, or on unredacted evidence.
Page incident-commander on emergency-exit volume or disclosure-incident open.

## Local tabletop

Verified by confirming each signal has a named owner in this catalog and T4.5 health/ready exists.

Fuji-configured rehearsal: chainId 43113, Circle USDC `0x5425890298aed601595a70AB815c96711a31Bc65`, and `deployments/fuji-v1.json`. Live broadcast remains operator-owned.
