# Pause

Owner: protocol-ops
Escalation: incident-commander → super-auditor

## When

Use pause when deposit, spend, policy, or router traffic must stop immediately: suspected fund-loss bug, proof bypass, or governance compromise.

## Procedure

1. Incident commander authorizes pause.
2. The pause-role signer calls `HazeAccess.pause()`. Pool, policy, version, application, and router entrypoints check `access.paused()`.
3. Confirm `Paused` event and that new user operations revert `PAUSED`.
4. Emergency exit remains available (it ignores pause). Do not disable it.
5. Unpause only after the incident review is written and `HazeAccess.unpause()` is authorized.

## Local tabletop

Verified against `HazeAccess.pause` / `unpause` and `HazePool` `PAUSED` guard.

Fuji-configured rehearsal: chainId 43113, Circle USDC `0x5425890298aed601595a70AB815c96711a31Bc65`, and `deployments/fuji-v1.json`. Live broadcast remains operator-owned.
