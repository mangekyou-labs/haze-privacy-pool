# Haze DEX-first chrome addendum

date: 2026-08-20
status: approved
feature: haze-avalanche-compliant-pool
amends: 2026-08-18-haze-commercial-frontend-design.md
does-not-replace: library T0.1–T7.5, hosted H0–H5 fail-closed gates, protocol design

## Goal

Pool-user chrome is a centered privacy-pool DEX card, not a compliance workstation.
Volcanic IBM Plex tokens stay. Fail-closed chips stay. Review-then-sign stays.

## Decisions

| Topic | Choice |
|---|---|
| Layout | Centered card (~440px). No left nav, no fail-closed inspector column |
| Tabs | Shield / Send / Withdraw / Swap on the card. Home is `/shield` |
| Amount | Hero decimal input + USDC pill |
| Compliance | Secondary chrome (`data-chrome="compliance"`) for admin/audit/governance |
| Fail-closed | Slim chips. Spend still shows `KEYS_MISSING` on the committed package |
| Keys / gates | Do not flip SC-09, `fuji-v1.json` `broadcast`, or `mainnet-v1.json` `authorized` |

## Out of scope

- Production Groth16 keys
- Writing committed `fuji-v1.json` (`broadcast: false`, `spend_prove: KEYS_MISSING`)
- Treating operator-owned Fuji sidecar txs as a published proving package
- MetaMask `notification.html` connect/account-switch (unclaimed)

## KEYS_MISSING vs operator-demo Fuji txs

Committed `haze/deployments/fuji-v1.json` is the published package: `broadcast: false`,
`spend_prove: KEYS_MISSING`. Browser `proveSpend` and hosted Fuji without the operator hatch
stay fail-closed on that package.

Live sidecar `haze/deployments/fuji-v1.live.json` records operator-owned Groth16 on the
Poseidon Fuji pool. Deposit `0xf8322001…3036` and withdraw `0x66ff71a2…7760` (1 USDC to
`0xeD37FD0d…cC32`) are real Fuji txs. They are not a ceremony approval and they do not
change `fuji-v1.json`. `spend_prove` on the sidecar remains `KEYS_MISSING` until SC-09.

`liveOperatorWithdrawAllowed` opens `/withdraw` only when `live && operatorProve && zkeyExists`.
Default `npm run commercial` does not open that hatch.

## Testing

TDD chrome test in `haze/tests/commercial-frontend.test.mjs`. playwright-cli desktop and
mobile. `npm test --prefix haze` green. Do not flip `fuji-v1.json`.
