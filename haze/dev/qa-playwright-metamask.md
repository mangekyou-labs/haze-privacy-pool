# Playwright CLI + MetaMask QA (Haze)

dAppwright initializes MetaMask **once**. Do not relaunch it for every snapshot, and do
not increment `TEST_WORKER_INDEX` after a failure.

Fuji Avalanche (chain 43113) is the acceptance target. Avalanche C-Chain mainnet (43114)
is refused. The committed `deployments/fuji-v1.json` stays `broadcast: false`.

## Fuji walk (acceptance)

The connect/sign popups live on MetaMask `notification.html`, which is not a playwright-cli
page. The headed walk that owns those popups is dAppwright:

```bash
cd haze
# Hatch host already running. Do not kill it. Do not use default :3010.
PORT=3014 npm run commercial:operator
HAZE_COMMERCIAL_URL=http://127.0.0.1:3014 npm run dappwright:live-operator
```

`dappwright:live-operator` bootstraps MetaMask with the disposable Anvil seed, imports the
operator `PRIVATE_KEY` from the worktree `.env` **once**, adds Fuji, connects on
`/shield?live=1`, Groth16-shields 1 USDC, then withdraws **that** note on
`/withdraw?live=1`. Popups are confirmed with `confirmAny`. Success is two **mined**
Fuji receipts (`status: 0x1`), not a broadcast hash alone. The hatch must deposit an
unused Poseidon commitment (not the fixture `depositCommitment`). `[data-address]` =
the Fuji operator (`0xeD37…`) on 43113. Committed `fuji-v1.json` stays
`broadcast: false` / `KEYS_MISSING`. playwright-cli does not own `notification.html`.

Digest-only connect (not the hatch MVP):

```bash
HAZE_COMMERCIAL_URL=http://127.0.0.1:3012 npm run dappwright:live
```

Do not import that key into a persist profile as the everyday path. Do not use `?role=`
as acceptance. Do not fall back to Anvil after a Fuji miss.

If the walk fails twice, stop and report. Do not start another worker index.

## Persist-once setup (optional CLI unlock)

Same shape as Blink: setup writes `.playwright/metamask-local/`,
`.playwright/metamask-extension/`, and `.playwright/cli.config.json` (gitignored).
Those paths are for later CLI unlock only. They do not replace `dappwright:live`.

```bash
cd haze
AVALANCHE_CHAIN_ID=43113 DAPP_URL=http://127.0.0.1:3012 npm run qa:wallet:setup
```

If the profile already exists, run `npm run qa:wallet:cleanup` only when you intend to
reinitialize. Setup still does not read `PRIVATE_KEY`.

```bash
npm run qa:cli -- --config .playwright/cli.config.json open "$DAPP_URL" --headed
```

After open: `tab-list`, unlock MetaMask from that snapshot, then select the dApp tab.
Unlock is required after each Chromium restart. playwright-cli cannot click the
permission popup; use `dappwright:live` for connect.

## Cleanup

```bash
npm run qa:cli -- close
npm run qa:wallet:cleanup
```

Cleanup removes only the two disposable directories under `haze/.playwright/`.
