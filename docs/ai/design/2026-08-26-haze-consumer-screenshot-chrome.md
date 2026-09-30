# Haze Consumer Screenshot Chrome Addendum

date: 2026-08-26
status: approved
feature: haze-avalanche-compliant-pool
amends: 2026-08-18-haze-commercial-frontend-design.md, 2026-08-20-haze-dex-first-chrome.md
does-not-replace: library T0.1–T7.5, hosted H0–H5 fail-closed gates, D8 compliance APIs, protocol design

## Goal

Align hosted production dapp on Vercel (`https://haze-avax.vercel.app`) with the screenshot consumer UX design:
- 3 primary tabs: `Shield | Withdraw | Audit` (Swap, Send, History, Emergency exit, Migrate remain as unlisted routes for power users and tests).
- Brand header: HAZE wordmark + inline SVG flame, Avalanche Fuji status, Connect/Disconnect wallet button.
- Centered card (~440px): Asset (USDC locked, Circle Fuji), Hero amount input + USDC pill, Shielded Balance display (reads notes sum from vault), Network display (Avalanche Fuji).
- Modal overlay: EIP-6963 wallet picker with Core, Rabby, MetaMask, discovered wallets, and fail-closed WalletConnect row.
- Connecting overlay: technical spinner and message prompt matching mockup.
- Audit card: disconnected `/audit` renders the same 3-tab consumer card with Case ID and Case File (signed export download, never file upload) + SIWE connect action. Authenticated auditors access the D8 3-column workstation with 5-field disclosure.
- Clean Next.js App Router integration: `renderHazeFragment` without nested HTML/doctype, CSS and font layout imports, proper CSP and web-worker webpack alias.

The host is canonical and intentional: `haze-finance.vercel.app` is rejected because it collides
with the 2021 BSC Haze Finance mixer/token, and `haze-pool.vercel.app` is rejected for mixer-coded
wording on a free Vercel host. Legacy hosts are redirect-only; preview deployments remain untouched.
The final MetaMask headed-connect result is a release gate and is recorded in the feature testing doc.

## Decisions

| Topic | Choice | Why |
|---|---|---|
| Layout | Centered card (~440px) on dark volcanic background (`#16130f`, `#221e18`, `#f3ece2`, `#c47a3a`) | Matches screenshot mockup UX |
| Nav | Primary tabs strictly `Shield \| Withdraw \| Audit` | Unlisted routes `/swap`, `/send`, `/history`, `/emergency-exit`, `/migrate` accessible via direct URLs |
| Header Brand | Text "HAZE" + inline SVG flame | Volcanic design identity without external image dependencies |
| Asset | USDC (Circle Fuji `0x5425…c65`) | Protocol is single-asset USDC. Screenshot "Avax" is filler |
| Connect | EIP-6963 announced provider picker + Core, Rabby, MetaMask, WalletConnect (fail-closed) | Safe multi-wallet support without provider race conditions |
| Continue | Review public facts panel (`data-review="public-facts"`) before spend sign | Transparent user safety & warnings |
| Audit Tab | Disconnected: consumer card with Case ID + Case File (download export) + SIWE. Connected: D8 workstation | Preserves D8 SIWE & disclosure API while matching screenshot consumer card |
| Spend Proving | Fail-closed on committed `fuji-v1.json` (`broadcast: false`, `KEYS_MISSING`) | UI never fakes proof success; operator hatch remains opt-in |

## Out of scope

- Multi-asset or native AVAX
- Case-file file upload (`<input type="file">`)
- WalletConnect without project ID
- Flipping `fuji-v1.json` to `broadcast: true`
- D8.4 live KYC membership operator walk (scheduled for a future session)
