/** One-time MetaMask persist for playwright-cli. Does not launch from npm test. */

import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { LOCAL_TEST_SEED } from "./dappwright-bootstrap.mjs";

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
export const QA_PROFILE_DIR = path.join(rootDir, ".playwright", "metamask-local");
export const QA_EXTENSION_DIR = path.join(rootDir, ".playwright", "metamask-extension");
export const QA_CLI_CONFIG_PATH = path.join(rootDir, ".playwright", "cli.config.json");

const DEFAULT_PASSWORD = "haze-local-qa";

export function validateQaWalletConfig(env = process.env) {
  const seedOverride = env.METAMASK_SEED_PHRASE?.replace(/\s+/gu, " ").trim();
  if (seedOverride && seedOverride !== LOCAL_TEST_SEED) {
    return { ok: false, reason: "PRODUCTION_SEED_REFUSED" };
  }

  const password = (env.METAMASK_PASSWORD ?? DEFAULT_PASSWORD).trim();
  if (password.length < 8) {
    return { ok: false, reason: "PASSWORD_TOO_SHORT" };
  }

  const chainId = Number(env.AVALANCHE_CHAIN_ID ?? 43113);
  if (chainId === 43114) {
    return { ok: false, reason: "MAINNET_REFUSED" };
  }
  if (!Number.isSafeInteger(chainId) || chainId <= 0) {
    return { ok: false, reason: "CHAIN_ID_INVALID" };
  }
  const fuji = chainId === 43113;

  const rpcUrl = (
    env.AVALANCHE_RPC_URL ??
    (fuji ? "https://api.avax-test.network/ext/bc/C/rpc" : "http://127.0.0.1:8545")
  ).trim();
  const dappUrl = (env.DAPP_URL ?? "http://127.0.0.1:3011").trim();
  try {
    if (!["http:", "https:"].includes(new URL(rpcUrl).protocol)) {
      return { ok: false, reason: "RPC_URL_INVALID" };
    }
    if (!["http:", "https:"].includes(new URL(dappUrl).protocol)) {
      return { ok: false, reason: "DAPP_URL_INVALID" };
    }
  } catch {
    return { ok: false, reason: "URL_INVALID" };
  }

  return {
    ok: true,
    seed: LOCAL_TEST_SEED,
    password,
    rpcUrl,
    chainId,
    networkName: (env.AVALANCHE_NETWORK_NAME ?? (fuji ? "Avalanche Fuji C-Chain" : "Anvil")).trim(),
    symbol: (env.AVALANCHE_CURRENCY_SYMBOL ?? (fuji ? "AVAX" : "ETH")).trim(),
    dappUrl,
    usedPrivateKey: false,
    notes: [
      fuji
        ? "Fuji 43113 persist profile. Operator key is imported only by dappwright:live."
        : "Fixed local Anvil seed only.",
      "Does not read PRIVATE_KEY.",
      "Does not write haze/deployments/fuji-v1.json.",
      "Does not launch MetaMask from npm test.",
    ],
  };
}

async function ensureFreshTarget() {
  for (const target of [QA_PROFILE_DIR, QA_EXTENSION_DIR]) {
    try {
      await fs.access(target);
      throw new Error(`${target} already exists. Run npm run qa:wallet:cleanup --prefix haze before reinitializing it.`);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
}

async function removeBrowserLocks(directory) {
  for (const name of ["SingletonCookie", "SingletonLock", "SingletonSocket", "DevToolsActivePort"]) {
    await fs.rm(path.join(directory, name), { force: true });
  }
}

async function persistProfile(dappwrightProfileDir) {
  await fs.mkdir(path.dirname(QA_PROFILE_DIR), { recursive: true });
  await fs.cp(dappwrightProfileDir, QA_PROFILE_DIR, { recursive: true });
  await removeBrowserLocks(QA_PROFILE_DIR);
}

async function writeCliConfig(executablePath) {
  const config = {
    browser: {
      browserName: "chromium",
      userDataDir: ".playwright/metamask-local",
      launchOptions: {
        headless: false,
        executablePath,
        args: [
          "--disable-extensions-except=.playwright/metamask-extension",
          "--load-extension=.playwright/metamask-extension",
        ],
      },
    },
    outputDir: "output/playwright",
    outputMode: "file",
  };
  await fs.mkdir(path.dirname(QA_CLI_CONFIG_PATH), { recursive: true });
  await fs.writeFile(QA_CLI_CONFIG_PATH, `${JSON.stringify(config, null, 2)}\n`);
}

async function persistOnce(config) {
  const { bootstrap, MetaMaskWallet } = await import("@tenkeylabs/dappwright");
  const { chromium } = await import("playwright");
  const workerIndex = process.env.TEST_WORKER_INDEX ?? "0";
  const dappwrightProfileDir = path.join(os.tmpdir(), "dappwright", "session", "metamask", workerIndex);

  await ensureFreshTarget();
  const version = MetaMaskWallet.recommendedVersion;
  const downloadOptions = { wallet: "metamask", version, headless: false };
  let browserContext;

  try {
    const extensionPath = await MetaMaskWallet.download(downloadOptions);
    const [wallet, , context] = await bootstrap("chromium", {
      ...downloadOptions,
      seed: config.seed,
      password: config.password,
      showTestNets: true,
    });
    browserContext = context;

    await wallet.addNetwork({
      networkName: config.networkName,
      rpc: config.rpcUrl,
      chainId: config.chainId,
      symbol: config.symbol,
    });

    const dappPage = await context.newPage();
    await dappPage.goto(config.dappUrl, { waitUntil: "domcontentloaded" });
    await dappPage.waitForFunction(() => typeof window.ethereum !== "undefined", undefined, { timeout: 15000 });
    const provider = await dappPage.evaluate(async () => ({
      hasEthereum: typeof window.ethereum !== "undefined",
      chainId: window.ethereum?.chainId ?? null,
    }));
    const expectedChainId = `0x${config.chainId.toString(16)}`;
    if (!provider.hasEthereum) throw new Error("MetaMask provider was not detected by DAPP_URL.");
    if (provider.chainId?.toLowerCase() !== expectedChainId) {
      throw new Error(`MetaMask provider reported ${provider.chainId ?? "no chain"}, expected ${expectedChainId}.`);
    }

    await browserContext.close();
    browserContext = undefined;
    await fs.cp(extensionPath, QA_EXTENSION_DIR, { recursive: true });
    await persistProfile(dappwrightProfileDir);
    await writeCliConfig(chromium.executablePath());

    console.log(`MetaMask ${version} initialized for ${config.networkName} (${expectedChainId}).`);
    console.log(`Provider detected at ${config.dappUrl}.`);
    console.log(`Persistent profile: ${path.relative(rootDir, QA_PROFILE_DIR)}`);
    console.log("Walk with: npm run qa:cli --prefix haze -- --config .playwright/cli.config.json open \"$DAPP_URL\" --headed");
  } finally {
    if (browserContext) await browserContext.close().catch(() => {});
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const config = validateQaWalletConfig();
  if (!config.ok) {
    console.error(`MetaMask QA config refused: ${config.reason}`);
    process.exitCode = 1;
  } else if (process.argv.includes("--validate-only")) {
    console.log("MetaMask QA configuration is valid.");
    console.log(JSON.stringify({ seed: "LOCAL_TEST_SEED", chainId: config.chainId, dappUrl: config.dappUrl, usedPrivateKey: false }, null, 2));
  } else {
    persistOnce(config).catch((error) => {
      console.error(`MetaMask QA setup failed: ${error instanceof Error ? error.message : error}`);
      process.exitCode = 1;
    });
  }
}
