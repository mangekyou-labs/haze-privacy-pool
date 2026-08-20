# Emergency exit

Owner: protocol-ops
Escalation: incident-commander → super-auditor

## When

Users must exit without application membership and while the pool is paused: unrecoverable lock, failed upgrade-by-version, or prolonged outage.

## Procedure

1. Confirm `EmergencyExit` is the published version in the deployment manifest.
2. Users submit `HazeEmergencyExitRequest` with the seven-day `COOLDOWN`. Operators do not custody notes or submit exits on users' behalf.
3. Pause does not block this path. Do not add an operator kill switch.
4. After cooldown, execute against the pool. Nullifiers still spend; double-exit must revert.
5. Record only redacted evidence (`redactEvidence`). No witnesses.

## Local tabletop

Verified against `contracts/src/EmergencyExit.sol` (`HazeEmergencyExitRequest`, `COOLDOWN`).

Fuji-configured rehearsal: chainId 43113, Circle USDC `0x5425890298aed601595a70AB815c96711a31Bc65`, and `deployments/fuji-v1.json`. Live broadcast remains operator-owned.
