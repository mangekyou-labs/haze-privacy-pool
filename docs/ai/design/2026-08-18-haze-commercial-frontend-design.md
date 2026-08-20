# Haze commercial frontend

date: 2026-08-18
status: approved
feature: haze-avalanche-compliant-pool
overrides: 2026-08-10 separate Next.js deployments for this hosted commercial UI
does-not-replace: library T0.1–T7.5, hosted H0–H5 fail-closed gates, protocol design

## Goal

One website, one origin, one Next.js app. Privacy Pool and Compliance Portal are route groups in a single volcanic workstation. Production proving and mainnet stay fail-closed.

## Decisions

| Topic | Choice |
|---|---|
| Product shape | One origin. Pool and Compliance are routes, not separate domains |
| Navigation | Unified chrome. Sidebar groups stay visible. Header role switcher |
| Auth | `authorizeRoute` / `authorizeApi` still enforced. Wrong role is `FORBIDDEN` |
| Depth | Designed routes only |
| Visual | Warm monochrome workstation on alpine-volcanic tokens |
| Chain I/O | Default `fuji-v1.json` fail-closed. Opt-in live profile may development-digest deposit via `fuji-v1.live.json` |
| Stack | Turborepo + one Next.js App Router app + restyled shadcn-style primitives under `haze/web/` |
| Domain | TypeScript SDK, `ux.ts`, `fujiGate`. No viem/ethers. No `PRIVATE_KEY` in the app |

## Out of scope

- Production Groth16 keys
- Flipping SC-09, `mainnetAuthorized`, or committed `fuji-v1.json` `broadcast: false`
- Live spend (swap, send, withdraw, migrate, emergency-exit)
- Two-domain isolation
- Marketing landing, settings, notifications, order book, yield, multi-asset

## Architecture

```text
haze/web/
  apps/haze/         one Next.js app
  packages/ui/       volcanic tokens, shell, role switcher, banners
  packages/config/
  turbo.json
```

Same origin is shared storage. Role switch replaces the session. Vault actions lock when the role is not `pool-user`.

## Routes

Pool (`pool-user`): `/swap` `/shield` `/send` `/withdraw` `/history` `/emergency-exit` `/migrate`  
Compliance: `/admin` `/audit` `/governance`  
`/` redirects by role.

Only `/shield` may broadcast on the live profile.

## Visual

`#16130f` `#221e18` `#f3ece2` `#d4c4ae` `#1f6b62` public `#c47a3a` private `#8ea3c7`.  
IBM Plex Sans + Mono, self-hosted. No Inter, zinc, violet, `#000`. Compact 4/8/12. Tabular numbers.

## Fail-closed

Persistent banners: `broadcast:false`, `KEYS_MISSING`, wrong-chain, `FORBIDDEN`, `APPLICATION_MISMATCH`, sidecar missing, live used on a non-deposit.

## Testing

TDD. playwright-cli on one origin, desktop and mobile. Role switcher: admin can open `/admin`; pool-user cannot. `npm test --prefix haze` stays green. Do not flip `fuji-v1.json`.

## Addendum — 2026-08-20 DEX-first chrome

Pool-user chrome is a centered DEX card (`data-chrome="dex"`), not a two-column workstation.
Home is `/shield`. Tabs: Swap / Shield / Send / Withdraw. Amount + USDC pill. Compliance
is a separate wider card. Fail-closed reasons stay as slim chips, not an inspector.
`KEYS_MISSING` on the committed package is unchanged. See
`docs/ai/design/2026-08-20-haze-dex-first-chrome.md`.
