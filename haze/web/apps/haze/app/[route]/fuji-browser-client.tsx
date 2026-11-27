"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useWalletSession } from "../wallet-session-provider";
import { functionSelector, hexToBuf } from "../../../../../sdk/typescript/src/abi.ts";
import {
  type BrowserShieldedAccount,
} from "../../../../../sdk/typescript/src/browser-crypto.ts";
import {
  encodeBrowserFujiSpend,
  encodeBrowserGroth16Proof,
  encodeBrowserSwapAndShield,
  encodeErc20Approve,
  encodeMembershipRootUpdate,
  planBrowserFujiSpend,
} from "../../../../../sdk/typescript/src/browser-fuji-contracts.ts";
import { ensureFujiMembershipRoot, executeFujiBrowserTransaction, extractFujiRpcError, updateFujiMembershipRoot } from "../../../../../sdk/typescript/src/browser-fuji-flow.ts";
import { createBrowserOperationVault, isConfirmedSpendableInput, type BrowserOperation } from "../../../../../sdk/typescript/src/browser-operation-vault.ts";
import { createBrowserProver, generateBrowserSecrets } from "../../../../../sdk/typescript/src/browser-prover.ts";
import { buildSealedBrowserTransferWitness, buildSealedBrowserWitness } from "../../../../../sdk/typescript/src/browser-witness-flow.ts";
import { emergencyExitRequestId } from "../../../../../sdk/typescript/src/emergency.ts";
import { createFujiMembershipStore, unionMembershipLeaves, type FujiMembershipStore } from "../../../../../sdk/typescript/src/fuji-membership-store.ts";
import { decodePrivateTransaction, reconcileFujiOperation, recoverFujiOperation, recoverSpendableNotesFromLogs, type FujiAction, type FujiLog, type FujiReceipt } from "../../../../../sdk/typescript/src/fuji-reconciliation.ts";
import { classifyBrowserError, type BrowserErrorCategory } from "../../../../../sdk/typescript/src/fuji-browser-error.ts";
import { DEFAULT_HAZE_AUDIT_PUBLIC_KEY } from "../../../../../sdk/typescript/src/render-disclosure.ts";
import { FUJI_V2 } from "../../../../../sdk/typescript/src/fuji-v2-defaults.ts";
import { buildLiveDepositWitness, buildLiveSwapWitness, buildLiveTransferWitness, buildLiveWithdrawWitness } from "../../../../../dev/operator-circuit-witness.mjs";
import { decodeErc20Balance, formatUsdc, recentOperationsFromVault, sumSpendableNotes } from "../../../../packages/ui/src/wallet-session.ts";

const CHAIN_ID = 43113;
const CHAIN_HEX = "0xa869";
const APPLICATION_ID = `0x${"00".repeat(30)}0a11`;
const POOL_VERSION_B002 = `0x${"00".repeat(30)}b001`;
const POOL_VERSION_B003 = `0x${"00".repeat(30)}b001`;
const POOL_B002: string = process.env.NEXT_PUBLIC_HAZE_POOL || FUJI_V2.pool;
const POOL_B003: string = process.env.NEXT_PUBLIC_HAZE_MIGRATION_POOL || FUJI_V2.migrationPool;
const ROUTER: string = process.env.NEXT_PUBLIC_HAZE_ROUTER || FUJI_V2.router;
const EMERGENCY_EXIT_CONTRACT: string = process.env.NEXT_PUBLIC_HAZE_EMERGENCY_EXIT || FUJI_V2.emergencyExit;
const USDC = "0x5425890298aed601595a70AB815c96711a31Bc65";
const PILOT_TOKEN = process.env.NEXT_PUBLIC_HAZE_PILOT_TOKEN || "0x4fAB93a23313CC032D8310Cf0f34A9BDF4E19c72";
const APPLICATION_REGISTRY: string = process.env.NEXT_PUBLIC_HAZE_APPLICATION_REGISTRY || FUJI_V2.applicationRegistry;
const POLICY_REGISTRY: string = process.env.NEXT_PUBLIC_HAZE_POLICY_REGISTRY || FUJI_V2.policyRegistry;
const POLICY_AUTHORITY = "0xeD37FD0d6F0f69236E7472B36796e133D20EcC32";
const AUDIT_KEY = process.env.NEXT_PUBLIC_HAZE_AUDIT_PUBLIC_KEY || DEFAULT_HAZE_AUDIT_PUBLIC_KEY;
const DEFAULT_AMOUNT = 1_000_000;

type Ethereum = { request(input: { method: string; params?: unknown[] }): Promise<unknown> };
type Vault = Awaited<ReturnType<typeof createBrowserOperationVault>>;
const hexBytes = (value: string) => Uint8Array.from(value.replace(/^0x/, "").match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));
const word = (value: string) => `0x${value.replace(/^0x/, "").padStart(64, "0")}`;
function ethereum(): Ethereum { const provider = (globalThis as typeof globalThis & { ethereum?: Ethereum }).ethereum; if (!provider) throw new Error("WALLET_UNAVAILABLE"); return provider; }
function words(value: string) { return value.replace(/^0x/, "").match(/.{64}/g) ?? []; }
function snapshot(app: string, version: string, root: string) { const values = words(app); const start = BigInt(`0x${values[0] ?? "0"}`) === 32n ? 1 : 0; return { membershipRoot: `0x${values[start + 4]}`, membershipVersion: BigInt(`0x${values[start + 5]}`), hazePolicyVersion: BigInt(version), hazeBlocklistRoot: word(root) }; }
// The nullifier a spend publishes on-chain is the spent INPUT note's nullifier. For sends the persisted
// `note` is the change output, so prefer the explicitly recorded input nullifier, then the caller-resolved
// input note (legacy ops), and only then the persisted note (correct for withdrawals, whose note is the input).
function spentNullifier(operation: BrowserOperation, spentInput?: string) {
  const recorded = operation.transaction?.inputNullifier;
  if (typeof recorded === "string" && recorded && !/^0x0*$/.test(recorded)) return recorded;
  if (spentInput) return spentInput;
  return String(operation.note?.nullifier ?? "");
}
function binding(operation: BrowserOperation, wallet: string, poolAddr = POOL_B002, poolVer = POOL_VERSION_B002, spentInput?: string) {
  const explicitAction = typeof operation.transaction?.action === "number" ? (operation.transaction.action as FujiAction) : undefined;
  const inferredAction: FujiAction = operation.kind === "deposit" ? 1 : (operation.kind === "private_send" || operation.kind === "transfer" ? 2 : (operation.kind === "withdrawal" ? 3 : 4));
  const action = explicitAction ?? inferredAction;
  return {
    chainId: CHAIN_ID,
    pool: (operation.transaction?.pool as string) || poolAddr,
    poolVersion: poolVer,
    applicationId: APPLICATION_ID,
    user: wallet,
    action,
    commitment: (action === 1 || action === 4 || operation.kind === "deposit" || operation.kind === "swap") ? String(operation.note?.commitment ?? "") : undefined,
    nullifier: (action === 2 || action === 3 || operation.kind === "withdrawal" || operation.kind === "private_send" || operation.kind === "transfer") ? spentNullifier(operation, spentInput) : undefined,
    kind: operation.kind,
    destination: operation.transaction?.destination as string | undefined,
    transactionHash: typeof operation.transaction?.hash === "string" && operation.transaction.hash !== "pending" ? operation.transaction.hash : (typeof operation.transaction?.transactionHash === "string" && operation.transaction.transactionHash !== "pending" ? (operation.transaction.transactionHash as string) : undefined),
  } as const;
}
export function FujiBrowserClient({ route }: { route: string }) {
  const {
    address: wallet,
    myHazeAddress,
    status,
    vaultReady,
    vaultGeneration,
    connect: sessionConnect,
    disconnect: sessionDisconnect,
    vaultRef,
    accountRef,
  } = useWalletSession();
  const [mount, setMount] = useState<HTMLElement | null>(null);
  const [transactionStatus, setTransactionStatus] = useState("idle");
  const [message, setMessage] = useState("");
  const [errorCategory, setErrorCategory] = useState<BrowserErrorCategory | null>(null);
  const [errorMessage, setErrorMessage] = useState<string>("");
  const [userAmount, setUserAmount] = useState("1.0");
  const [publicRecipient, setPublicRecipient] = useState("");
  const [recipientHazeAddress, setRecipientHazeAddress] = useState("");
  const [previewed, setPreviewed] = useState(false);
  const [provingElapsed, setProvingElapsed] = useState(0);
  const [vaultNotes, setVaultNotes] = useState<BrowserOperation[]>([]);
  const [recovering, setRecovering] = useState(false);
  const recoverEpoch = useRef(0);
  const [lastReceipt, setLastReceipt] = useState<{
    amount: string;
    hash: string;
    action: FujiAction | number;
    actionName: string;
    pool: string;
    stage: "preparing" | "broadcast" | "mined" | "finalized" | "failed";
    blockNumber?: number;
    confirmations?: number;
    failureStage?: string;
    failureReason?: string;
  } | null>(null);
  const [swapQuote, setSwapQuote] = useState<{
    amountIn?: string;
    amountOut?: string;
    usdcOut?: string;
    minUsdcOut?: string;
    routeHash?: string;
    deadline?: number;
    adapter?: string;
    data?: string;
    expectedRouteHash?: string;
  } | null>(null);
  const [proposals, setProposals] = useState<any[]>([]);
  const [apps, setApps] = useState<any[]>([]);
  const [newMemberWallet, setNewMemberWallet] = useState("");
  const [emergencyRequestId, setEmergencyRequestId] = useState("");
  const [migrationStatus, setMigrationStatus] = useState<string | null>(null);
  const vault = useRef<Vault | undefined>(undefined);
  const shieldedAccount = useRef<BrowserShieldedAccount | undefined>(undefined);
  const membershipStore = useRef<FujiMembershipStore | undefined>(undefined);
  const worker = useRef<Worker | undefined>(undefined);
  const lastWithdrawal = useRef<BrowserOperation | undefined>(undefined);

  useEffect(() => {
    setMount(document.getElementById("fuji-browser-transaction-root"));
    return () => worker.current?.terminate();
  }, []);

  useEffect(() => {
    if (transactionStatus !== "proving" && transactionStatus !== "building_witness") {
      setProvingElapsed(0);
      return;
    }
    const start = Date.now();
    const interval = setInterval(() => {
      setProvingElapsed(Math.floor((Date.now() - start) / 1000));
    }, 1000);
    return () => clearInterval(interval);
  }, [transactionStatus]);
  useEffect(() => {
    if (route !== "swap") return;
    const numeric = Number.parseFloat(userAmount);
    if (!numeric || numeric <= 0) {
      setSwapQuote(null);
      return;
    }
    const spendUnits = Math.round(numeric * 1e6);
    let cancelled = false;
    fetch("/api/v1/pool/quote", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tokenIn: PILOT_TOKEN, amountIn: String(spendUnits), slippageBps: 50 }),
    })
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (!cancelled && data) setSwapQuote(data);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [route, userAmount]);

  const rpc = useCallback((method: string, params: unknown[] = []) => ethereum().request({ method, params }), []);
  // Pool history comes from the server: wallet RPCs cap eth_getLogs at 100 blocks.
  const poolLogs = useCallback(async (poolAddress = POOL_B002) => {
    const res = await fetch(`/api/v1/pool/logs?address=${encodeURIComponent(poolAddress)}`, { cache: "no-store" });
    if (!res.ok) throw new Error(`POOL_LOGS_UNAVAILABLE: HTTP ${res.status}`);
    return ((await res.json()) as { logs: FujiLog[] }).logs;
  }, []);
  const chainRpc = useCallback((method: string, params: unknown[] = []) => (
    method === "eth_getLogs" ? poolLogs((params[0] as { address?: string } | undefined)?.address) : rpc(method, params)
  ), [poolLogs, rpc]);
  // Registry state and receipts come from the server's public RPC: the wallet's
  // own Fuji RPC can lag behind a confirmed membership update.
  const readRpc = useCallback(async (method: string, params: unknown[]) => {
    try {
      const res = await fetch("/api/v1/pool/read", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ method, params }),
        cache: "no-store",
      });
      if (res.ok) return ((await res.json()) as { result: unknown }).result;
    } catch {}
    return rpc(method, params);
  }, [rpc]);
  const receipt = useCallback(async (hash: string) => {
    for (let attempt = 0; attempt < 120; attempt += 1) {
      const found = await readRpc("eth_getTransactionReceipt", [hash]) as FujiReceipt | null;
      if (found) return found;
      await new Promise((resolve) => setTimeout(resolve, 2_000));
    }
    return undefined;
  }, [readRpc]);

  const readSnapshot = useCallback(async () => snapshot(
    await readRpc("eth_call", [{ to: APPLICATION_REGISTRY, data: `${functionSelector("getApplication(bytes32)")}${APPLICATION_ID.slice(2)}` }, "latest"]) as string,
    await readRpc("eth_call", [{ to: POLICY_REGISTRY, data: functionSelector("activeVersion()") }, "latest"]) as string,
    await readRpc("eth_call", [{ to: POLICY_REGISTRY, data: functionSelector("activeRoot()") }, "latest"]) as string,
  ), [readRpc]);

  // The spend is estimated and sent through the wallet's RPC. Wait (bounded,
  // non-fatal) until that RPC also reports the new root, so gas estimation
  // does not run against a node that has not seen the membership update.
  const walletSeesRoot = useCallback(async (root: string) => {
    for (let attempt = 0; attempt < 30; attempt += 1) {
      try {
        const state = snapshot(
          await rpc("eth_call", [{ to: APPLICATION_REGISTRY, data: `${functionSelector("getApplication(bytes32)")}${APPLICATION_ID.slice(2)}` }, "latest"]) as string,
          await rpc("eth_call", [{ to: POLICY_REGISTRY, data: functionSelector("activeVersion()") }, "latest"]) as string,
          await rpc("eth_call", [{ to: POLICY_REGISTRY, data: functionSelector("activeRoot()") }, "latest"]) as string,
        );
        if (state.membershipRoot.toLowerCase() === root.toLowerCase()) return;
      } catch {}
      await new Promise((resolve) => setTimeout(resolve, 2_000));
    }
  }, [rpc]);

  const treeLeaves = useCallback(async (poolAddress = POOL_B002) => {
    const logs = await poolLogs(poolAddress);
    const leaves: { leafIndex: number; commitment: string }[] = [];
    for (const log of logs) {
      const event = decodePrivateTransaction(log);
      for (const commitment of [event?.outputCommitment0, event?.outputCommitment1]) {
        if (commitment && BigInt(commitment) !== 0n) leaves.push({ leafIndex: leaves.length, commitment });
      }
    }
    return leaves;
  }, [poolLogs]);

  const loadVaultNotes = useCallback(async (active: Vault) => {
    const list = await active.list();
    setVaultNotes(list);
    lastWithdrawal.current = list.findLast((item) => item.kind === "withdrawal" && item.state === "confirmed");
  }, []);

  const recover = useCallback(async (active: Vault, address: string, account?: BrowserShieldedAccount) => {
    const epoch = ++recoverEpoch.current;
    setRecovering(true);
    try {
    await loadVaultNotes(active);
    const operations = await active.list();
    for (const operation of operations.filter((item) => item.state === "submitted" || item.state === "pending_finality")) {
      const spentFrom = typeof operation.note?.depositOperationId === "string"
        ? operations.find((item) => item.id === operation.note?.depositOperationId)
        : undefined;
      const spentInput = typeof spentFrom?.note?.nullifier === "string" ? spentFrom.note.nullifier : undefined;
      const result = await recoverFujiOperation({ ...binding(operation, address, POOL_B002, POOL_VERSION_B002, spentInput), rpc: chainRpc });
      if (result.confirmed) {
        const confirmed = await active.transition(operation.id, "confirmed", {
          recovered: true,
          hash: operation.transaction?.hash,
          finalityProvenance: "finalityProvenance" in result ? result.finalityProvenance : undefined,
        });
        if (operation.kind === "withdrawal" || operation.transaction?.action === 3 || operation.kind === "transfer" || operation.transaction?.action === 2) {
          if (typeof confirmed.note?.depositOperationId === "string") {
            await active.consumeConfirmedNote(confirmed.note.depositOperationId);
          }
          if (operation.kind === "withdrawal" || operation.transaction?.action === 3) {
            lastWithdrawal.current = confirmed;
          }
        }
      } else if (result.status === "pending_finality") {
        await active.transition(operation.id, "pending_finality", {
          confirmations: result.confirmations,
        });
      }
    }
    if (account) {
      try {
        const logs = await poolLogs(POOL_B002);
        const recovered = recoverSpendableNotesFromLogs({
          chainId: CHAIN_ID,
          pool: POOL_B002,
          poolVersion: POOL_VERSION_B002,
          applicationId: APPLICATION_ID,
          recipientIkm: hexToBuf(account.x25519Secret),
          logs,
        });
        await active.persistRecoveredSpendableNotes(
          recovered.map((note) => ({ ...note, x25519: account.x25519PublicKey })),
        );
        for (const note of recovered) {
          if (note.npk && note.enc) {
            await membershipStore.current?.add({ npk: note.npk, enc: note.enc });
          }
        }
      } catch (err: unknown) {
        const classified = classifyBrowserError(err);
        setErrorCategory(classified.category);
        setErrorMessage(classified.message);
        setMessage(classified.message);
      }
    }

    await loadVaultNotes(active);
    } finally {
      if (epoch === recoverEpoch.current) {
        setRecovering(false);
        setTransactionStatus("ready");
      }
    }
  }, [loadVaultNotes, rpc, chainRpc, poolLogs]);

  // Sync vault/account refs from the session provider (silent resume path).
  // Depends on vaultGeneration so a connected first-paint still reloads after openVault.
  useEffect(() => {
    const active = vaultRef.current ?? vault.current;
    if (!(wallet && vaultReady && active && accountRef.current)) return;
    vault.current = active;
    shieldedAccount.current = accountRef.current;
    membershipStore.current = createFujiMembershipStore();
    let cancelled = false;
    (async () => {
      await recover(active, wallet, shieldedAccount.current);
      if (cancelled) return;
    })();
    return () => {
      cancelled = true;
    };
  }, [wallet, status, vaultReady, vaultGeneration, vaultRef, accountRef, recover]);

  useEffect(() => {
    const active = vaultRef.current ?? vault.current;
    if (route === "history" && vaultReady && active) {
      void loadVaultNotes(active);
    }
  }, [route, status, wallet, vaultReady, vaultGeneration, loadVaultNotes, vaultRef]);
  // Hydrate overview figures and recent operations when on /overview or session/notes update
  useEffect(() => {
    const pubEl = document.querySelector('[data-card="overview"] [data-balance="public"] .haze-figure');
    const privEl = document.querySelector('[data-card="overview"] [data-balance="private"] .haze-figure');
    const recentSection = document.querySelector<HTMLElement>("[data-recent-ops]");
    const tbody = document.getElementById("haze-recent-ops-body");

    if (recentSection) recentSection.setAttribute("data-recovering", recovering ? "true" : "false");

    const paintPlaceholder = (copy: string, busy = false) => {
      if (!tbody) return;
      tbody.replaceChildren();
      if (busy) tbody.setAttribute("aria-busy", "true");
      else tbody.removeAttribute("aria-busy");
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 5;
      td.className = "haze-muted";
      td.textContent = copy;
      tr.append(td);
      tbody.append(tr);
    };

    if (!wallet || status !== "connected") {
      if (pubEl) pubEl.textContent = "—";
      if (privEl) privEl.textContent = "—";
      paintPlaceholder("Connect to see your local vault activity.");
      return;
    }

    let cancelled = false;
    (async () => {
      try {
        const res = await rpc("eth_call", [
          {
            to: USDC,
            data: `${functionSelector("balanceOf(address)")}${wallet.toLowerCase().replace(/^0x/, "").padStart(64, "0")}`,
          },
          "latest",
        ]);
        if (!cancelled && pubEl && typeof res === "string") {
          const val = decodeErc20Balance(res);
          pubEl.textContent = `${formatUsdc(val)} USDC`;
        }
      } catch {
        if (!cancelled && pubEl) pubEl.textContent = "0.00 USDC";
      }
    })();

    const spendableSum = sumSpendableNotes(vaultNotes);
    if (privEl) {
      privEl.textContent = `${formatUsdc(spendableSum)} USDC`;
    }

    if (recovering && vaultNotes.length === 0) {
      paintPlaceholder("Recovering operations from Fuji…", true);
    } else {
      const rows = recentOperationsFromVault(vaultNotes);
      if (!tbody) {
        // mount missing
      } else if (rows.length === 0) {
        paintPlaceholder("No recent operations in local vault.");
      } else {
        tbody.replaceChildren();
        tbody.removeAttribute("aria-busy");
        for (const row of rows) {
          const tr = document.createElement("tr");
          const cells: Array<[string, string, HTMLElement?]> = [
            ["date", row.date],
            ["type", row.type],
            ["amount", `${row.amount} USDC`],
            ["status", row.status],
          ];
          for (const [col, text] of cells) {
            const td = document.createElement("td");
            td.dataset.col = col;
            td.textContent = text;
            tr.append(td);
          }
          const receiptTd = document.createElement("td");
          receiptTd.dataset.col = "receipt";
          if (row.receiptHref) {
            const link = document.createElement("a");
            link.href = row.receiptHref;
            link.target = "_blank";
            link.rel = "noreferrer";
            link.textContent = row.receipt;
            receiptTd.append(link);
          } else {
            receiptTd.textContent = row.receipt;
          }
          tr.append(receiptTd);
          tbody.append(tr);
        }
      }
    }

    return () => {
      cancelled = true;
    };
  }, [wallet, status, vaultNotes, recovering, rpc]);


  const connect = useCallback(async () => {
    if (wallet) return;
    try {
      membershipStore.current = createFujiMembershipStore();
      await sessionConnect();
      const active = vaultRef.current;
      if (!active || !accountRef.current) throw new Error("VAULT_OPEN_FAILED");
      vault.current = active;
      shieldedAccount.current = accountRef.current;
      await recover(active, wallet, shieldedAccount.current);

      // Load admin / governance if on those routes
      if (route === "governance") {
        const res = await fetch("/api/v1/governance/proposals");
        if (res.ok) {
          const data = await res.json();
          setProposals(data.proposals || []);
        }
      } else if (route === "admin") {
        const res = await fetch("/api/v1/admin/applications");
        if (res.ok) {
          const data = await res.json();
          setApps(data.applications || []);
        }
      }
    } catch (error) {
      setTransactionStatus("error");
      setMessage(error instanceof Error ? error.message : "WALLET_ERROR");
    }
  }, [recover, route, wallet, sessionConnect, vaultRef, accountRef]);

  const prover = useCallback(() => {
    worker.current ??= new Worker(new URL("../../../../../sdk/typescript/src/prover-worker.ts", import.meta.url), { type: "module" });
    return createBrowserProver({
      worker: worker.current,
      profile: "fuji-development",
      expectedArtifactHash: "0x374bb2394da985ab824ce61a95b3b3409b71355139f0a6b16fb8e0bff8e508d5",
    });
  }, []);

  // Standard Shield / Withdraw / Swap / Send workflow
  const executeSpendWorkflow = useCallback(async () => {
    let activeVault = vaultRef.current ?? vault.current;
    if (!activeVault || !wallet) {
      if (!wallet) await sessionConnect();
      activeVault = vaultRef.current ?? vault.current;
      if (!activeVault || !wallet) {
        throw new Error("VAULT_NOT_INITIALIZED");
      }
    }
    console.log(`[HAZE CLIENT] executeSpendWorkflow started for ${route}, wallet: ${wallet}`);
    let currentPhase = "building_witness";
    try {
      setErrorCategory(null);
      setErrorMessage("");
      if (!/^(?:0x)?[0-9a-f]{64}$/i.test(AUDIT_KEY)) throw new Error("AUDIT_PUBLIC_KEY_MISSING");
      const account = shieldedAccount.current ?? accountRef.current;
      if (!account?.x25519PublicKey) throw new Error("VAULT_NOT_INITIALIZED");
      const recipientPublicKey = hexBytes(account.x25519PublicKey);
      setTransactionStatus("building_witness");
      console.log("[HAZE CLIENT] Phase: building_witness");
      const leaves = await treeLeaves();
      const current = await readSnapshot();
      const secrets = generateBrowserSecrets();
      const storedMembers = (await membershipStore.current?.list()) ?? [];
      const isWithdrawal = route === "withdraw";
      const isSend = route === "send";
      const isSwap = route === "swap";
      const isDeposit = route === "shield" || isSwap;

      if (isSend && !recipientHazeAddress) {
        throw new Error("RECIPIENT_ADDRESS_REQUIRED");
      }

      const spendAmount = Math.round(Number.parseFloat(userAmount || "1.0") * 1e6) || DEFAULT_AMOUNT;

      let quote: { tokenIn: string; amountIn: string; usdcOut: string; minUsdcOut: string; routeHash: string; deadline: number; adapter: string; data: string; expectedRouteHash: string } | undefined;
      if (isSwap) {
        const pilotBalHex = (await rpc("eth_call", [
          {
            to: PILOT_TOKEN,
            data: `${functionSelector("balanceOf(address)")}${wallet.toLowerCase().replace(/^0x/, "").padStart(64, "0")}`,
          },
          "latest",
        ])) as string;
        const pilotBal = decodeErc20Balance(pilotBalHex);
        if (pilotBal < BigInt(spendAmount)) {
          throw new Error("INSUFFICIENT_PILOT");
        }

        const quoteRes = await fetch("/api/v1/pool/quote", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ tokenIn: PILOT_TOKEN, amountIn: String(spendAmount) }),
        });
        if (!quoteRes.ok) {
          const err = await quoteRes.json().catch(() => ({}));
          throw new Error(err.code || "SWAP_VENUE_UNAVAILABLE");
        }
        quote = await quoteRes.json();
      }

      const deposit = (await activeVault.list()).findLast(isConfirmedSpendableInput);
      if ((isWithdrawal || isSend) && !deposit) throw new Error("DEPOSIT_NOTE_REQUIRED");

      const common = {
        pool: POOL_B002,
        user: wallet,
        applicationId: APPLICATION_ID,
        poolVersion: POOL_VERSION_B002,
        publicAmount: isSend ? 0 : spendAmount,
        applicationPolicyVersion: Number(current.membershipVersion),
        hazePolicyVersion: Number(current.hazePolicyVersion),
      };

      let sealed: ReturnType<typeof buildSealedBrowserWitness>;

      if (isSend) {
        const sendWitnessInput = {
          user: wallet,
          applicationPolicyVersion: Number(current.membershipVersion),
          hazePolicyVersion: Number(current.hazePolicyVersion),
        };
        sealed = buildSealedBrowserTransferWitness({
          buildWitness: buildLiveTransferWitness,
          witnessInput: sendWitnessInput,
          note: deposit!.note,
          sendAmount: spendAmount,
          recipientAddress: recipientHazeAddress,
          chainId: CHAIN_ID,
          pool: POOL_B002,
          poolVersion: POOL_VERSION_B002,
          applicationId: APPLICATION_ID,
          auditPublicKey: hexBytes(AUDIT_KEY),
          auditKeyVersion: 1n,
          caseTag: new TextEncoder().encode("SEND"),
          secrets,
          treeLeaves: leaves,
          membershipLeaves: storedMembers,
          ownerPublicKey: recipientPublicKey,
        }) as unknown as ReturnType<typeof buildSealedBrowserWitness>;

        const membershipLeavesForRelay = unionMembershipLeaves(
          storedMembers,
          [deposit!.note],
          [sealed.witness.recipientNote, sealed.witness.note],
        );

        const updateMembership = async (root: string) => {
          return ensureFujiMembershipRoot({
            membershipRoot: root,
            applicationId: APPLICATION_ID,
            policyAuthority: POLICY_AUTHORITY,
            wallet,
            readApplication: async () => {
              const state = await readSnapshot();
              return { membershipVersion: state.membershipVersion, membershipRoot: state.membershipRoot };
            },
            sendUpdate: async (appId, r) => rpc("eth_sendTransaction", [{ from: wallet, to: APPLICATION_REGISTRY, data: encodeMembershipRootUpdate(appId, r) }]) as Promise<string>,
            waitReceipt: receipt,
            relayUpdate: async (payload) => {
              const res = await fetch("/api/v1/pool/membership-root", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ ...payload, membershipLeaves: membershipLeavesForRelay }),
              });
              if (!res.ok) {
                if (res.status === 503) throw new Error("MEMBERSHIP_RELAYER_UNAVAILABLE");
                const data = await res.json().catch(() => ({}));
                throw new Error(data.error || "MEMBERSHIP_UPDATE_FAILED");
              }
              const data = await res.json();
              return {
                membershipVersion: BigInt(data.membershipVersion),
                membershipRoot: data.membershipRoot,
              };
            },
          });
        };

        const after = await updateMembership(sealed.witness.membershipRoot);
        await walletSeesRoot(after.membershipRoot);
        sealed = buildSealedBrowserTransferWitness({
          buildWitness: buildLiveTransferWitness,
          witnessInput: { ...sendWitnessInput, applicationPolicyVersion: Number(after.membershipVersion) },
          note: deposit!.note,
          sendAmount: spendAmount,
          recipientAddress: recipientHazeAddress,
          chainId: CHAIN_ID,
          pool: POOL_B002,
          poolVersion: POOL_VERSION_B002,
          applicationId: APPLICATION_ID,
          auditPublicKey: hexBytes(AUDIT_KEY),
          auditKeyVersion: 1n,
          caseTag: new TextEncoder().encode("SEND"),
          secrets,
          treeLeaves: leaves,
          membershipLeaves: storedMembers,
          ownerPublicKey: recipientPublicKey,
        }) as unknown as ReturnType<typeof buildSealedBrowserWitness>;
      } else if (isSwap && quote) {
        const swapWitnessInput = {
          ...common,
          tokenIn: quote.tokenIn,
          amountIn: quote.amountIn,
          value: quote.usdcOut,
          minUsdcOut: Number(quote.minUsdcOut),
          routeHash: quote.routeHash,
          deadline: Number(quote.deadline),
          leafIndex: leaves.length,
          membershipLeaves: storedMembers,
        };
        sealed = buildSealedBrowserWitness({
          buildWitness: buildLiveSwapWitness,
          witnessInput: swapWitnessInput,
          chainId: CHAIN_ID,
          pool: POOL_B002,
          poolVersion: POOL_VERSION_B002,
          applicationId: APPLICATION_ID,
          auditPublicKey: hexBytes(AUDIT_KEY),
          auditKeyVersion: 1n,
          caseTag: new TextEncoder().encode("SWAP"),
          secrets,
          recipientPublicKey,
        });

        const membershipLeavesForRelay = unionMembershipLeaves(
          storedMembers,
          [],
          [sealed.witness.recipientNote, sealed.witness.note],
        );

        const updateMembership = async (root: string) => {
          return ensureFujiMembershipRoot({
            membershipRoot: root,
            applicationId: APPLICATION_ID,
            policyAuthority: POLICY_AUTHORITY,
            wallet,
            readApplication: async () => {
              const state = await readSnapshot();
              return { membershipVersion: state.membershipVersion, membershipRoot: state.membershipRoot };
            },
            sendUpdate: async (appId, r) => rpc("eth_sendTransaction", [{ from: wallet, to: APPLICATION_REGISTRY, data: encodeMembershipRootUpdate(appId, r) }]) as Promise<string>,
            waitReceipt: receipt,
            relayUpdate: async (payload) => {
              const res = await fetch("/api/v1/pool/membership-root", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ ...payload, membershipLeaves: membershipLeavesForRelay }),
              });
              if (!res.ok) {
                if (res.status === 503) throw new Error("MEMBERSHIP_RELAYER_UNAVAILABLE");
                const data = await res.json().catch(() => ({}));
                throw new Error(data.error || "MEMBERSHIP_UPDATE_FAILED");
              }
              const data = await res.json();
              return {
                membershipVersion: BigInt(data.membershipVersion),
                membershipRoot: data.membershipRoot,
              };
            },
          });
        };

        const after = await updateMembership(sealed.witness.membershipRoot);
        await walletSeesRoot(after.membershipRoot);
        sealed = buildSealedBrowserWitness({
          buildWitness: buildLiveSwapWitness,
          witnessInput: { ...swapWitnessInput, applicationPolicyVersion: Number(after.membershipVersion) },
          chainId: CHAIN_ID,
          pool: POOL_B002,
          poolVersion: POOL_VERSION_B002,
          applicationId: APPLICATION_ID,
          auditPublicKey: hexBytes(AUDIT_KEY),
          auditKeyVersion: 1n,
          caseTag: new TextEncoder().encode("SWAP"),
          secrets,
          recipientPublicKey,
        });
      } else {
        const targetRecipient = publicRecipient.trim() || wallet;
        const witnessInput = isWithdrawal
          ? { ...common, note: deposit!.note, publicRecipient: targetRecipient, treeLeaves: leaves, membershipLeaves: storedMembers }
          : { ...common, value: spendAmount, leafIndex: leaves.length, membershipLeaves: storedMembers };

        const factory = isWithdrawal ? buildLiveWithdrawWitness : buildLiveDepositWitness;
        sealed = buildSealedBrowserWitness({
          buildWitness: factory,
          witnessInput,
          chainId: CHAIN_ID,
          pool: POOL_B002,
          poolVersion: POOL_VERSION_B002,
          applicationId: APPLICATION_ID,
          auditPublicKey: hexBytes(AUDIT_KEY),
          auditKeyVersion: 1n,
          caseTag: new TextEncoder().encode(isWithdrawal ? "WITHDRAWAL" : "DEPOSIT"),
          secrets,
          recipientPublicKey,
        });

        const membershipLeavesForRelay = unionMembershipLeaves(
          storedMembers,
          isWithdrawal ? [deposit!.note] : [],
          [sealed.witness.recipientNote, sealed.witness.note],
        );

        const updateMembership = async (root: string) => {
          return ensureFujiMembershipRoot({
            membershipRoot: root,
            applicationId: APPLICATION_ID,
            policyAuthority: POLICY_AUTHORITY,
            wallet,
            readApplication: async () => {
              const state = await readSnapshot();
              return { membershipVersion: state.membershipVersion, membershipRoot: state.membershipRoot };
            },
            sendUpdate: async (appId, r) => rpc("eth_sendTransaction", [{ from: wallet, to: APPLICATION_REGISTRY, data: encodeMembershipRootUpdate(appId, r) }]) as Promise<string>,
            waitReceipt: receipt,
            relayUpdate: async (payload) => {
              const res = await fetch("/api/v1/pool/membership-root", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ ...payload, membershipLeaves: membershipLeavesForRelay }),
              });
              if (!res.ok) {
                if (res.status === 503) throw new Error("MEMBERSHIP_RELAYER_UNAVAILABLE");
                const data = await res.json().catch(() => ({}));
                throw new Error(data.error || "MEMBERSHIP_UPDATE_FAILED");
              }
              const data = await res.json();
              return {
                membershipVersion: BigInt(data.membershipVersion),
                membershipRoot: data.membershipRoot,
              };
            },
          });
        };

        const after = await updateMembership(sealed.witness.membershipRoot);
        await walletSeesRoot(after.membershipRoot);
        sealed = buildSealedBrowserWitness({
          buildWitness: factory,
          witnessInput: { ...witnessInput, applicationPolicyVersion: Number(after.membershipVersion) },
          chainId: CHAIN_ID,
          pool: POOL_B002,
          poolVersion: POOL_VERSION_B002,
          applicationId: APPLICATION_ID,
          auditPublicKey: hexBytes(AUDIT_KEY),
          auditKeyVersion: 1n,
          caseTag: new TextEncoder().encode(isWithdrawal ? "WITHDRAWAL" : "DEPOSIT"),
          secrets,
          recipientPublicKey,
        });
      }

      const operationId = sealed.witness.actionReference;
      const actionId: 1 | 2 | 3 | 4 = isWithdrawal ? 3 : isSend ? 2 : isSwap ? 4 : 1;
      const destination = isWithdrawal ? (publicRecipient.trim() || wallet) : (isSend ? recipientHazeAddress.trim() : undefined);
      const noteToPersist = isSend
        ? (sealed.witness.note ? { ...sealed.witness.note, spendable: true, depositOperationId: deposit?.id } : { spendable: false, depositOperationId: deposit?.id })
        : isWithdrawal
          ? { ...sealed.witness.note, spendable: false, depositOperationId: deposit?.id }
          : { ...sealed.witness.note, spendable: true };

      const operation = await activeVault.create({
        id: operationId,
        kind: isWithdrawal ? "withdrawal" : isSend ? "transfer" : isSwap ? "swap" : "deposit",
        note: noteToPersist,
        transaction: {
          to: isSwap ? ROUTER : POOL_B002,
          pool: POOL_B002,
          action: actionId,
          destination,
          actionReference: sealed.witness.actionReference,
          commitment: sealed.witness.note?.commitment ?? `0x${"00".repeat(32)}`,
          nullifier: sealed.witness.note?.nullifier ?? `0x${"00".repeat(32)}`,
          inputNullifier: isWithdrawal || isSend
            ? String((sealed.witness.circom as { inputNullifier0?: unknown } | undefined)?.inputNullifier0 ?? "")
            : undefined,
        },
      });
      currentPhase = "proving";
      setTransactionStatus("proving");
      console.log("[HAZE CLIENT] Phase: proving...");
      // The v2 pool verifies Groth16 only, so a proving failure must stop the spend.
      const browserProver = prover();
      const manifestRes = await fetch("/proving/fuji-development/haze-spend-v1/manifest.json", { cache: "no-store" });
      if (!manifestRes.ok) throw new Error("PROVING_MANIFEST_NOT_FOUND");
      await browserProver.loadFujiArtifacts(await manifestRes.json());
      const proof: string = encodeBrowserGroth16Proof(await browserProver.proveSpend(sealed.witness.circom) as never);
      console.log("[HAZE CLIENT] Groth16 proof generated");
      await activeVault.transition(operationId, "ready_to_submit", { proofReady: true });

      const plan = planBrowserFujiSpend({
        witness: sealed.witness,
        user: wallet,
        pool: POOL_B002,
        poolVersion: POOL_VERSION_B002,
        applicationId: APPLICATION_ID,
        action: actionId,
        now: Math.floor(Date.now() / 1000),
        proof,
        publicRecipient: isWithdrawal ? (publicRecipient.trim() || wallet) : "0x0000000000000000000000000000000000000000",
        tokenIn: isSwap ? quote?.tokenIn : undefined,
        amountIn: isSwap ? quote?.amountIn : undefined,
        minUsdcOut: isSwap && quote ? Number(quote.minUsdcOut) : undefined,
        routeHash: isSwap ? quote?.routeHash : undefined,
        deadline: isSwap && quote ? Number(quote.deadline) : undefined,
      });

      currentPhase = "authorizing";
      setTransactionStatus("authorizing");
      let signature: string;
      const GATEKEEPER_AUTHORITY = "0xeD37FD0d6F0f69236E7472B36796e133D20EcC32";
      if (wallet.toLowerCase() === GATEKEEPER_AUTHORITY.toLowerCase()) {
        signature = (await rpc("eth_signTypedData_v4", [wallet, JSON.stringify(plan.typedData)])) as string;
      } else {
        const authRes = await fetch("/api/v1/pool/authorize", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            applicationId: APPLICATION_ID,
            intent: plan.intent,
            authorization: plan.authorization,
            actionReference: sealed.witness.actionReference,
          }),
        });
        if (!authRes.ok) {
          const errData = await authRes.json().catch(() => ({}));
          throw new Error(errData.message || errData.code || "GATEKEEPER_AUTHORIZATION_FAILED");
        }
        const authData = await authRes.json();
        signature = authData.signature;
        if (authData.authorization) {
          plan.authorization = {
            ...plan.authorization,
            ...authData.authorization,
          };
        }
      }
      const ready = (await activeVault.get(operationId))!;

      let approvalTransaction: { from: string; to: string; data: string } | undefined;
      let poolTransaction: { from: string; to: string; data: string };

      if (isSwap && quote) {
        const allowRes = (await rpc("eth_call", [
          {
            to: PILOT_TOKEN,
            data: `${functionSelector("allowance(address,address)")}${wallet.toLowerCase().replace(/^0x/, "").padStart(64, "0")}${ROUTER.toLowerCase().replace(/^0x/, "").padStart(64, "0")}`,
          },
          "latest",
        ])) as string;
        const currentAllow = decodeErc20Balance(allowRes);
        if (currentAllow < BigInt(spendAmount)) {
          approvalTransaction = { from: wallet, to: PILOT_TOKEN, data: encodeErc20Approve(ROUTER, spendAmount) };
        }
        const swapPayload = encodeBrowserSwapAndShield({
          router: ROUTER,
          plan,
          signature,
          route: {
            adapter: quote.adapter,
            data: quote.data,
            expectedRouteHash: quote.expectedRouteHash,
          },
        });
        poolTransaction = { from: wallet, ...swapPayload };
      } else if (route === "shield") {
        const allowRes = (await rpc("eth_call", [
          {
            to: USDC,
            data: `${functionSelector("allowance(address,address)")}${wallet.toLowerCase().replace(/^0x/, "").padStart(64, "0")}${POOL_B002.toLowerCase().replace(/^0x/, "").padStart(64, "0")}`,
          },
          "latest",
        ])) as string;
        const currentAllow = decodeErc20Balance(allowRes);
        if (currentAllow < BigInt(spendAmount)) {
          approvalTransaction = { from: wallet, to: USDC, data: encodeErc20Approve(POOL_B002, spendAmount) };
        }
        poolTransaction = { from: wallet, ...encodeBrowserFujiSpend({ plan, signature }) };
      } else {
        approvalTransaction = undefined;
        poolTransaction = { from: wallet, ...encodeBrowserFujiSpend({ plan, signature }) };
      }

      console.log("[POOL TX]", JSON.stringify(poolTransaction));
      currentPhase = approvalTransaction ? "approving" : "submitting";
      setTransactionStatus(currentPhase);
      const result = await executeFujiBrowserTransaction({
        operation: ready,
        approvalTransaction,
        poolTransaction,
        send: (tx) => {
          currentPhase = tx === approvalTransaction ? "approving" : "submitting";
          setTransactionStatus(currentPhase);
          return rpc("eth_sendTransaction", [tx]) as Promise<string>;
        },
        waitReceipt: (h) => {
          currentPhase = "confirming";
          setTransactionStatus("confirming");
          return receipt(h);
        },
        preflight: async (tx) => {
          try {
            await rpc("eth_call", [tx, "latest"]);
          } catch (err: unknown) {
            const raw = extractFujiRpcError(err);
            console.error("[PREFLIGHT ERROR RAW]", err, "Extracted:", raw);
            throw new Error(raw);
          }
        },
        markSubmittedBeforeBroadcast: activeVault.markSubmittedBeforeBroadcast,
        recordSubmittedHash: activeVault.recordSubmittedHash,
        reconcile: (value) => reconcileFujiOperation({ ...binding(ready, wallet), receipt: value as FujiReceipt }),
      });
      if (!result.confirmed) throw new Error("FUJI_EVENT_NOT_CONFIRMED");
      await activeVault.transition(operationId, "confirmed", { hash: result.transactionHash });
      if (isWithdrawal || isSend) {
        await activeVault.consumeConfirmedNote(deposit!.id);
      }

      // Add output member leaves to membership store
      if (sealed.witness.note?.npk && sealed.witness.note?.enc) {
        await membershipStore.current?.add({ npk: String(sealed.witness.note.npk), enc: String(sealed.witness.note.enc) });
      }
      if ("recipientNote" in sealed.witness && sealed.witness.recipientNote) {
        const rec = sealed.witness.recipientNote as { npk?: string; enc?: string };
        if (rec?.npk && rec?.enc) {
          await membershipStore.current?.add({ npk: String(rec.npk), enc: String(rec.enc) });
        }
      }

      await loadVaultNotes(activeVault);
      setTransactionStatus("confirmed");
      setMessage("");
      setLastReceipt({
        amount: formatAmount(userAmount || "1"),
        hash: result.transactionHash,
        action: actionId,
        actionName: actionId === 1 ? "Shield" : actionId === 2 ? "Send" : actionId === 3 ? "Withdraw" : "Swap",
        pool: POOL_B002,
        stage: "finalized",
        blockNumber: result.receipt?.blockNumber ? Number(result.receipt.blockNumber) : undefined,
        confirmations: 12,
      });
    } catch (error) {
      console.error("Fuji workflow error:", error);
      setTransactionStatus("error");
      const classified = classifyBrowserError(error, currentPhase);
      setErrorCategory(classified.category);
      setErrorMessage(classified.message);
      setMessage(classified.message);
    }
  }, [connect, loadVaultNotes, prover, readSnapshot, receipt, recipientHazeAddress, route, rpc, treeLeaves, userAmount, wallet, walletSeesRoot]);
  const wipeVault = useCallback(async () => {
    if (!vault.current) return;
    const confirmation = window.prompt('Type "WIPE" to permanently erase your local vault data:');
    if (confirmation !== "WIPE") {
      setMessage('Wipe cancelled. Confirmation must be "WIPE".');
      return;
    }
    try {
      await vault.current.wipe("WIPE");
      setVaultNotes([]);
      setMessage("Local vault wiped successfully.");
    } catch {
      setMessage("Failed to wipe local vault.");
    }
  }, []);

  // Emergency exit: request with CSPRNG salt
  const requestEmergency = useCallback(async () => {
    if (!EMERGENCY_EXIT_CONTRACT) { setTransactionStatus("error"); setMessage("EMERGENCY_EXIT_NOT_CONFIGURED"); return; }
    if (!wallet) return connect();
    try {
      setTransactionStatus("requesting_emergency");
      const saltBytes = crypto.getRandomValues(new Uint8Array(32));
      const salt = `0x${Array.from(saltBytes, (b) => b.toString(16).padStart(2, "0")).join("")}`;
      const nullifierBytes = crypto.getRandomValues(new Uint8Array(32));
      const nullifier = `0x${Array.from(nullifierBytes, (b) => b.toString(16).padStart(2, "0")).join("")}`;
      const id = emergencyExitRequestId({
        chainId: CHAIN_ID,
        pool: POOL_B002,
        poolVersion: POOL_VERSION_B002,
        applicationId: APPLICATION_ID,
        nullifier,
        recipient: wallet,
        requestSalt: salt,
      });
      setEmergencyRequestId(id);

      const data = `${functionSelector("requestEmergencyExit(bytes32,bytes32,address,bytes32)")}${nullifier.slice(2)}${word(APPLICATION_ID).slice(2)}${addressWordHex(wallet).slice(2)}${salt.slice(2)}`;
      const hash = await rpc("eth_sendTransaction", [{ from: wallet, to: EMERGENCY_EXIT_CONTRACT, data }]) as string;
      await receipt(hash);
      setTransactionStatus("emergency_requested");
      setMessage(`Emergency exit requested with ID: ${id}`);
    } catch (error) {
      setTransactionStatus("error");
      setMessage(error instanceof Error ? error.message : "EMERGENCY_REQUEST_FAILED");
    }
  }, [connect, receipt, rpc, wallet]);

  // Emergency exit: execute after 7 days
  const executeEmergency = useCallback(async () => {
    if (!EMERGENCY_EXIT_CONTRACT) { setTransactionStatus("error"); setMessage("EMERGENCY_EXIT_NOT_CONFIGURED"); return; }
    if (!wallet) return connect();
    try {
      setTransactionStatus("executing_emergency");
      const data = `${functionSelector("executeEmergencyExit(bytes32,address)")}${emergencyRequestId.slice(2)}${addressWordHex(wallet).slice(2)}`;
      const hash = await rpc("eth_sendTransaction", [{ from: wallet, to: EMERGENCY_EXIT_CONTRACT, data }]) as string;
      await receipt(hash);
      setTransactionStatus("emergency_executed");
      setMessage(`Emergency exit executed successfully.`);
    } catch (error) {
      setTransactionStatus("error");
      setMessage(error instanceof Error ? error.message : "EMERGENCY_EXECUTE_FAILED");
    }
  }, [connect, emergencyRequestId, receipt, rpc, wallet]);

  // Migration from B002 to B003
  const migratePool = useCallback(async () => {
    if (!POOL_B003) { setTransactionStatus("error"); setMessage("MIGRATION_POOL_NOT_CONFIGURED"); return; }
    if (!wallet || !vault.current) return connect();
    try {
      setMigrationStatus("1/2 Public withdrawal from B002...");
      setTransactionStatus("migrating_withdrawing");

      const activeVault = vault.current;
      const deposit = (await activeVault.list()).findLast((item) => item.kind === "deposit" && item.state === "confirmed" && item.note.spendable !== false);
      if (!deposit) throw new Error("NO_NOTE_TO_MIGRATE");

      const leaves = await treeLeaves(POOL_B002);
      const current = await readSnapshot();
      const secrets = generateBrowserSecrets();

      const withdrawWitness = buildSealedBrowserWitness({
        buildWitness: buildLiveWithdrawWitness,
        witnessInput: {
          pool: POOL_B002,
          user: wallet,
          applicationId: APPLICATION_ID,
          poolVersion: POOL_VERSION_B002,
          publicAmount: DEFAULT_AMOUNT,
          applicationPolicyVersion: Number(current.membershipVersion),
          hazePolicyVersion: Number(current.hazePolicyVersion),
          publicRecipient: wallet,
          note: deposit.note,
          treeLeaves: leaves,
        },
        chainId: CHAIN_ID,
        pool: POOL_B002,
        poolVersion: POOL_VERSION_B002,
        applicationId: APPLICATION_ID,
        auditPublicKey: hexBytes(AUDIT_KEY),
        auditKeyVersion: 1n,
        caseTag: new TextEncoder().encode("MIGRATE_WITHDRAW"),
        secrets,
      });

      const browserProver = prover();
      const manifest = await (await fetch("/proving/fuji-development/haze-spend-v1/manifest.json", { cache: "no-store" })).json();
      await browserProver.loadFujiArtifacts(manifest);
      const withdrawProof = encodeBrowserGroth16Proof(await browserProver.proveSpend(withdrawWitness.witness.circom) as never);

      const withdrawPlan = planBrowserFujiSpend({
        witness: withdrawWitness.witness,
        user: wallet,
        pool: POOL_B002,
        poolVersion: POOL_VERSION_B002,
        applicationId: APPLICATION_ID,
        action: 3,
        now: Math.floor(Date.now() / 1000),
        proof: withdrawProof,
        publicRecipient: wallet,
      });

      const withdrawSig = await rpc("eth_signTypedData_v4", [wallet, JSON.stringify(withdrawPlan.typedData)]) as string;
      const withdrawTx = encodeBrowserFujiSpend({ plan: withdrawPlan, signature: withdrawSig });

      const wHash = await rpc("eth_sendTransaction", [{ from: wallet, ...withdrawTx }]) as string;
      await receipt(wHash);
      await activeVault.consumeConfirmedNote(deposit.id);

      setMigrationStatus("2/2 Public shield into B003...");
      setTransactionStatus("migrating_shielding");

      const depositWitness = buildSealedBrowserWitness({
        buildWitness: buildLiveDepositWitness,
        witnessInput: {
          pool: POOL_B003,
          user: wallet,
          applicationId: APPLICATION_ID,
          poolVersion: POOL_VERSION_B003,
          publicAmount: DEFAULT_AMOUNT,
          applicationPolicyVersion: Number(current.membershipVersion),
          hazePolicyVersion: Number(current.hazePolicyVersion),
          leafIndex: 0,
        },
        chainId: CHAIN_ID,
        pool: POOL_B003,
        poolVersion: POOL_VERSION_B003,
        applicationId: APPLICATION_ID,
        auditPublicKey: hexBytes(AUDIT_KEY),
        auditKeyVersion: 1n,
        caseTag: new TextEncoder().encode("MIGRATE_DEPOSIT"),
        secrets: generateBrowserSecrets(),
        recipientPublicKey: hexBytes((shieldedAccount.current ?? accountRef.current)?.x25519PublicKey ?? ""),
      });

      const depositProof = encodeBrowserGroth16Proof(await browserProver.proveSpend(depositWitness.witness.circom) as never);
      const depositPlan = planBrowserFujiSpend({
        witness: depositWitness.witness,
        user: wallet,
        pool: POOL_B003,
        poolVersion: POOL_VERSION_B003,
        applicationId: APPLICATION_ID,
        action: 1,
        now: Math.floor(Date.now() / 1000),
        proof: depositProof,
      });

      const depositSig = await rpc("eth_signTypedData_v4", [wallet, JSON.stringify(depositPlan.typedData)]) as string;
      const depositTx = encodeBrowserFujiSpend({ plan: depositPlan, signature: depositSig });

      const appHash = await rpc("eth_sendTransaction", [{ from: wallet, to: USDC, data: encodeErc20Approve(POOL_B003, DEFAULT_AMOUNT) }]) as string;
      await receipt(appHash);

      const dHash = await rpc("eth_sendTransaction", [{ from: wallet, ...depositTx }]) as string;
      await receipt(dHash);

      setMigrationStatus("Migration complete. 1 USDC transferred from B002 to B003.");
      setTransactionStatus("migration_completed");
    } catch (error) {
      console.error("Migration error:", error);
      setTransactionStatus("error");
      const classified = classifyBrowserError(error, transactionStatus);
      setErrorCategory(classified.category);
      setErrorMessage(classified.message);
      setMessage(classified.message);
    }
  }, [connect, prover, readSnapshot, receipt, rpc, treeLeaves, wallet]);

  const spendableNotes = vaultNotes.filter(isConfirmedSpendableInput);
  const spendableShieldNotes = spendableNotes.filter((item) => item.transaction?.action === 1);
  const latestSpendableShield = spendableShieldNotes.findLast((item) =>
    typeof item.transaction?.hash === "string" || typeof item.transaction?.transactionHash === "string"
  );
  const latestSpendableShieldTxHash = typeof latestSpendableShield?.transaction?.hash === "string"
    ? latestSpendableShield.transaction.hash
    : typeof latestSpendableShield?.transaction?.transactionHash === "string"
      ? latestSpendableShield.transaction.transactionHash
      : "";
  const spendableNote = spendableNotes[0];
  const totalShieldedUnits = spendableNotes.reduce(
    (sum, n) => sum + (typeof n.note?.value === "number" ? n.note.value : typeof n.note?.value === "string" ? Number(n.note.value) : 1_000_000),
    0,
  );
  const shieldedBalanceDisplay = `${(totalShieldedUnits / 1e6).toFixed(2)} USDC`;
  const isConnected = status === "connected" || Boolean(wallet);
  const canSend = isConnected && Boolean(spendableNote) && recipientHazeAddress.trim().length > 0;
  const amount = userAmount.trim() === "" ? "—" : userAmount;
  const assetLabel =
    route === "swap"
      ? "Fuji Pilot (PILOT) → USDC"
      : route === "shield" || route === "withdraw"
        ? "USDC · Circle Fuji"
        : "USDC";
  const actionLabel =
    route === "swap"
      ? `Swap ${amount} PILOT`
      : `${route.charAt(0).toUpperCase()}${route.slice(1)} ${amount} USDC`;
  const quoteDisplay = swapQuote ? `${(Number(swapQuote.usdcOut) / 1e6).toFixed(2)} USDC` : `${formatAmount(userAmount || "1")} USDC`;
  const proving = transactionStatus === "proving";

  useEffect(() => {
    if (!proving) return;
    const started = Date.now();
    const timer = setInterval(() => setProvingElapsed(Math.floor((Date.now() - started) / 1000)), 1000);
    return () => clearInterval(timer);
  }, [proving]);

  if (!mount) return null;

  return createPortal(
    <section
      className="haze-form"
      aria-label="Fuji browser transaction"
      data-spendable-note-count={spendableNotes.length}
      data-spendable-shield-note-count={spendableShieldNotes.length}
      data-spendable-shield-tx-hash={latestSpendableShieldTxHash}
    >
      <p className="haze-mono haze-hidden-status" data-transaction-status={transactionStatus} />
      <p className="haze-muted">{message}</p>


      {route === "shield" || route === "withdraw" || route === "swap" || route === "send" ? (
        <div className="haze-action">
          <div className="haze-action-rows">
            <div className="haze-row" data-row="asset">
              <span className="haze-row-label">Asset</span>
              <span className="haze-row-value haze-mono">{assetLabel}</span>
            </div>

            <div className="haze-amount-row">
              <label className="haze-field haze-amount-field">
                {route === "swap" ? "Source amount" : "Amount"}
                <input
                  className="haze-amount haze-figure"
                  type="text"
                  value={userAmount}
                  onChange={(e) => setUserAmount(e.target.value)}
                  inputMode="decimal"
                  autoComplete="off"
                  disabled={!isConnected}
                />
              </label>
              <span className="haze-token">{route === "swap" ? "PILOT" : "USDC"}</span>
            </div>

            <div className="haze-row" data-row="shielded-balance">
              <span className="haze-row-label">Shielded Balance</span>
              <span className="haze-row-value haze-figure" data-balance="shielded">
                {shieldedBalanceDisplay}
              </span>
            </div>

            <div className="haze-row" data-row="network">
              <span className="haze-row-label">Network</span>
              <span className="haze-row-value">
                Avalanche <span className="haze-badge" data-network-badge="testnet">Testnet</span>
              </span>
            </div>

            {route === "swap" ? (
              <>
                <p className="haze-muted" style={{ margin: "4px 0 8px", fontSize: "12px" }}>
                  Fuji Pilot is a test swap asset, swapped 1:1 into USDC before shielding.
                </p>
                <div className="haze-row" data-row="quote">
                  <span className="haze-row-label">Quote</span>
                  <span className="haze-row-value haze-figure" data-quote>
                    {quoteDisplay}
                  </span>
                </div>
                <div className="haze-row" data-row="slippage">
                  <span className="haze-row-label">Slippage</span>
                  <span className="haze-row-value haze-figure">0.5% (50 bps)</span>
                </div>
              </>
            ) : null}

            {route === "withdraw" ? (
              <label className="haze-field">
                Public recipient
                <input
                  className="haze-figure"
                  type="text"
                  placeholder={wallet || "0x…"}
                  value={publicRecipient}
                  onChange={(e) => setPublicRecipient(e.target.value)}
                  autoComplete="off"
                  disabled={!isConnected}
                />
              </label>
            ) : null}

            {route === "send" ? (
              <div className="haze-send-fields">
                {myHazeAddress ? (
                  <div className="haze-address-copy" data-haze-address={myHazeAddress}>
                    <span className="haze-row-label">Your haze1</span>
                    <button
                      className="haze-button haze-button-secondary haze-copy"
                      type="button"
                      onClick={() => void navigator.clipboard?.writeText(myHazeAddress)}
                    >
                      Copy
                    </button>
                    <span className="haze-figure">{myHazeAddress.slice(0, 18)}…</span>
                  </div>
                ) : null}
                {!spendableNote ? (
                  <p className="haze-muted haze-empty-note">
                    Shield USDC to create a private balance. <a href="/shield">Shield USDC</a>
                  </p>
                ) : null}
                <label className="haze-field">
                  Recipient haze1
                  <input
                    className="haze-figure"
                    type="text"
                    placeholder="haze1…"
                    value={recipientHazeAddress}
                    onChange={(e) => setRecipientHazeAddress(e.target.value)}
                    autoComplete="off"
                    disabled={!isConnected}
                  />
                </label>
              </div>
            ) : null}
          </div>

          <button
            className="haze-button haze-preview-toggle"
            type="button"
            onClick={() => setPreviewed(!previewed)}
            data-action="preview"
          >
            {previewed ? "Hide preview" : "Preview"}
          </button>

          {previewed ? (
            <div className="haze-preview" data-review="balanced">
              {route === "withdraw" ? (
                <>
                  <p className="haze-muted">Debit private</p>
                  <p className="haze-figure" data-balance="private">{amount} USDC</p>
                  <p className="haze-muted">Credit public</p>
                  <p className="haze-figure" data-balance="public">{amount} USDC</p>
                </>
              ) : route === "swap" ? (
                <>
                  <p className="haze-muted">Debit public</p>
                  <p className="haze-figure" data-balance="public">{amount} PILOT</p>
                  <p className="haze-muted">Credit private</p>
                  <p className="haze-figure" data-balance="private">{quoteDisplay}</p>
                </>
              ) : route === "send" ? (
                <>
                  <p className="haze-muted">Debit private</p>
                  <p className="haze-figure" data-balance="private">{amount} USDC</p>
                  <p className="haze-muted">Credit recipient</p>
                  <p className="haze-figure" data-balance="recipient">{amount} USDC</p>
                </>
              ) : (
                <>
                  <p className="haze-muted">Debit public</p>
                  <p className="haze-figure" data-balance="public">{amount} USDC</p>
                  <p className="haze-muted">Credit private</p>
                  <p className="haze-figure" data-balance="private">{amount} USDC</p>
                </>
              )}
            </div>
          ) : null}

          {transactionStatus === "building_witness" ? (
            <p className="haze-mono haze-proving" data-phase="building_witness">Preparing cryptographic witness…</p>
          ) : transactionStatus === "proving" ? (
            <p className="haze-mono haze-proving" data-phase="proving">Generating proof… {provingElapsed}s</p>
          ) : transactionStatus === "authorizing" ? (
            <p className="haze-mono haze-authorizing" data-phase="authorizing">Requesting gatekeeper authorization…</p>
          ) : transactionStatus === "approving" ? (
            <p className="haze-mono haze-approving" data-phase="approving">Confirming USDC allowance in wallet…</p>
          ) : transactionStatus === "submitting" ? (
            <p className="haze-mono haze-submitting" data-phase="submitting">Confirming transaction in wallet…</p>
          ) : transactionStatus === "confirming" ? (
            <p className="haze-mono haze-confirming" data-phase="confirming">Waiting for on-chain finality…</p>
          ) : null}
          {transactionStatus === "error" && errorCategory ? (
            <p className="haze-mono haze-error" data-error={errorCategory}>{errorMessage}</p>
          ) : null}
          {lastReceipt ? (
            <div className="haze-receipt" data-receipt="confirmed" data-stage={lastReceipt.stage}>
              <div className="haze-lifecycle-stepper" data-lifecycle={lastReceipt.stage}>
                <span className={`haze-step ${["preparing", "broadcast", "mined", "finalized"].includes(lastReceipt.stage) ? "haze-step-done" : ""}`}>1. Preparing</span>
                <span className="haze-step-arrow">→</span>
                <span className={`haze-step ${["broadcast", "mined", "finalized"].includes(lastReceipt.stage) ? "haze-step-done" : ""}`}>2. Broadcast</span>
                <span className="haze-step-arrow">→</span>
                <span className={`haze-step ${["mined", "finalized"].includes(lastReceipt.stage) ? "haze-step-done" : ""}`}>3. Mined</span>
                <span className="haze-step-arrow">→</span>
                <span className={`haze-step ${lastReceipt.stage === "finalized" ? "haze-step-done" : ""}`}>4. Finalized (12 Conf)</span>
              </div>
              <p className="haze-figure" data-balance="private">{lastReceipt.amount} USDC</p>
              <div className="haze-mono haze-receipt-details">
                <p><strong>Action:</strong> {lastReceipt.actionName} (Action {lastReceipt.action})</p>
                <p><strong>Pool:</strong> {lastReceipt.pool}</p>
                {lastReceipt.blockNumber ? <p><strong>Block:</strong> {lastReceipt.blockNumber}</p> : null}
                {lastReceipt.confirmations ? <p><strong>Confirmations:</strong> {lastReceipt.confirmations} / 12</p> : null}
                <p className="haze-receipt-hash">
                  <strong>Tx Hash: </strong>
                  <a href={`https://testnet.snowtrace.io/tx/${lastReceipt.hash}`} target="_blank" rel="noreferrer">
                    {lastReceipt.hash.slice(0, 18)}… ↗
                  </a>
                </p>
                {lastReceipt.stage === "failed" ? (
                  <p className="haze-error-details" data-failure-stage={lastReceipt.failureStage}>
                    Failed at stage: {lastReceipt.failureStage} — {lastReceipt.failureReason}
                  </p>
                ) : null}
              </div>
              {route === "shield" || route === "swap" ? (
                <a className="haze-button haze-button-secondary" href="/send">Next: Send</a>
              ) : (
                <a className="haze-button haze-button-secondary" href="/overview">Next: Overview</a>
              )}
            </div>
          ) : null}
          <div className="haze-actions">
            <button
              className="haze-button haze-confirm"
              type="button"
              onClick={() => void executeSpendWorkflow()}
              disabled={
                !isConnected ||
                (route === "send" && !canSend) ||
                (route !== "send" && !previewed) ||
                ["building_witness", "proving", "authorizing", "approving", "submitting", "confirming"].includes(transactionStatus)
              }
            >
              {transactionStatus === "building_witness"
                ? "Preparing witness…"
                : transactionStatus === "proving"
                  ? `Generating proof… ${provingElapsed}s`
                  : transactionStatus === "authorizing"
                    ? "Authorizing…"
                    : transactionStatus === "approving"
                      ? "Approving in wallet…"
                      : transactionStatus === "submitting"
                        ? "Confirming in wallet…"
                        : transactionStatus === "confirming"
                          ? "Confirming on-chain…"
                          : actionLabel}
            </button>
          </div>
        </div>
      ) : null}

      {route === "history" ? (
        <div className="haze-history">
          <h3 className="haze-subtitle">Operation History & Local Vault Notes</h3>
          {!vaultReady || recovering ? (
            <p className="haze-empty">Recovering operations from Fuji…</p>
          ) : vaultNotes.length === 0 ? (
            <p className="haze-empty">No operations recorded in the local vault.</p>
          ) : (
            <div className="haze-history-list">
              {vaultNotes.map((n) => {
                const actionNum = n.transaction?.action ?? (n.kind === "deposit" ? 1 : n.kind === "private_send" || n.kind === "transfer" ? 2 : n.kind === "withdrawal" ? 3 : 4);
                const actionLabel = actionNum === 1 ? "SHIELD" : actionNum === 2 ? "SEND" : actionNum === 3 ? "WITHDRAW" : "SWAP";
                const isFinalized = n.state === "confirmed";
                const isPendingFinality = n.state === "pending_finality";
                const isSubmitted = n.state === "submitted";
                const isFailed = n.state === "failed";
                const txHash = typeof n.transaction?.hash === "string" && n.transaction.hash !== "pending" ? n.transaction.hash : (typeof n.transaction?.transactionHash === "string" && n.transaction.transactionHash !== "pending" ? (n.transaction.transactionHash as string) : undefined);
                const confs = n.transaction?.finalityProvenance?.confirmationCount ?? (n.transaction?.confirmations as number | undefined);
                const blockNum = n.transaction?.finalityProvenance?.inclusionBlock;

                return (
                  <div key={n.id} className="haze-history-card" data-state={n.state} data-action={actionNum}>
                    <div className="haze-history-header">
                      <span className={`haze-badge haze-badge-action haze-badge-${actionLabel.toLowerCase()}`}>{actionLabel}</span>
                      <span className={`haze-badge haze-badge-state haze-badge-${n.state}`}>
                        {isFinalized ? "FINALIZED (12+ CONF)" : isPendingFinality ? `PENDING FINALITY (${confs ?? 0}/12)` : isSubmitted ? "SUBMITTED" : isFailed ? "FAILED" : "LOCAL"}
                      </span>
                    </div>
                    <div className="haze-mono haze-history-body">
                      {txHash ? (
                        <p className="haze-history-row">
                          <strong>Hash: </strong>
                          <a href={`https://testnet.snowtrace.io/tx/${txHash}`} target="_blank" rel="noreferrer">
                            {txHash.slice(0, 18)}… ↗
                          </a>
                        </p>
                      ) : null}
                      <p className="haze-history-row"><strong>Pool:</strong> {String(n.transaction?.pool || POOL_B002)}</p>
                      {n.transaction?.destination ? <p className="haze-history-row"><strong>Destination:</strong> {String(n.transaction.destination).slice(0, 16)}…</p> : null}
                      {blockNum ? <p className="haze-history-row"><strong>Inclusion Block:</strong> {blockNum}</p> : null}
                      {confs ? <p className="haze-history-row"><strong>Confirmations:</strong> {confs} / 12</p> : null}
                      {n.note?.amount ? <p className="haze-history-row"><strong>Amount:</strong> {formatUsdc(BigInt(String(n.note.amount)))} USDC</p> : null}
                      {n.transaction?.failureDetails ? (
                        <p className="haze-error haze-history-row">
                          Failed at {n.transaction.failureDetails.stage}: {n.transaction.failureDetails.reason}
                        </p>
                      ) : null}
                      {isConfirmedSpendableInput(n) ? (
                        <p className="haze-history-row haze-history-actions">
                          <a className="haze-button haze-button-secondary" href="/send">Send</a>
                          <a className="haze-button haze-button-secondary" href="/withdraw">Withdraw</a>
                        </p>
                      ) : null}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
          <div className="haze-actions">
            <button className="haze-button haze-button-secondary" type="button" onClick={wipeVault}>Wipe local vault</button>
            <button className="haze-button" type="button" onClick={() => wallet && vault.current && recover(vault.current, wallet, shieldedAccount.current)}>Recover from wallet message</button>
          </div>
        </div>
      ) : null}

      {route === "emergency-exit" ? (
        <div className="haze-emergency">
          <div className="haze-banner">
            <strong>Simulation Only (Non-Broadcast Demo):</strong> Emergency exit allows an unconditional 7-day delayed exit from B002. Live execution is disabled for MVP.
          </div>
          <p className="haze-muted">Emergency exit is not a live MVP capability.</p>
          <div className="haze-actions">
            <button className="haze-button" type="button" disabled title="Disabled in MVP">1. Request Emergency Exit (Disabled)</button>
            <button className="haze-button haze-button-secondary" type="button" disabled title="Disabled in MVP">2. Execute After 7 Days (Disabled)</button>
          </div>
        </div>
      ) : null}

      {route === "migrate" ? (
        <div className="haze-migrate">
          <div className="haze-banner">
            <strong>Simulation Only (Non-Broadcast Demo):</strong> Migration performs a public withdrawal from B002 followed by a public shield into B003. Live execution is disabled for MVP.
          </div>
          <p className="haze-muted">Migration is not a live MVP capability.</p>
          <div className="haze-actions">
            <button className="haze-button" type="button" disabled title="Disabled in MVP">Execute B002 → B003 Migration (Disabled)</button>
          </div>
        </div>
      ) : null}

      {route === "admin" ? (
        <div className="haze-admin">
          <h3 className="haze-subtitle">Application Administration</h3>
          {apps.map((a) => (
            <div key={a.applicationId} className="haze-mono haze-row-card">
              <div>App: {a.name} ({a.applicationId.slice(0, 10)}…)</div>
              <div>Admin: {a.adminWallet}</div>
              <div>Membership Root: {a.membershipRoot.slice(0, 12)}… (v{a.membershipVersion})</div>
            </div>
          ))}
          <div className="haze-field-grid">
            <label className="haze-field">
              Enroll Member Wallet
              <input type="text" placeholder="0x…" value={newMemberWallet} onChange={(e) => setNewMemberWallet(e.target.value)} autoComplete="off" />
            </label>
            <button className="haze-button" type="button" onClick={async () => {
              const res = await fetch("/api/v1/admin/members", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ memberWallet: newMemberWallet }),
              });
              if (res.ok) setMessage(`Member ${newMemberWallet} enrolled successfully.`);
            }}>
              Enroll Member
            </button>
          </div>
        </div>
      ) : null}

      {route === "governance" ? (
        <div className="haze-governance">
          <h3 className="haze-subtitle">2-of-3 Multisig Governance Proposals</h3>
          {proposals.map((p) => (
            <div key={p.proposalId} className="haze-mono haze-row-card">
              <div>Proposal #{p.proposalId}: {p.description}</div>
              <div>Target: {p.target} | Approvals: {p.approvalsCount}/2</div>
              <div className="haze-actions">
                <button className="haze-button haze-button-secondary haze-compact" type="button" onClick={async () => {
                  const res = await fetch("/api/v1/governance/approve", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ proposalId: p.proposalId }) });
                  if (res.ok) setMessage(`Proposal #${p.proposalId} approved.`);
                }}>Approve (2-of-3)</button>
                <button className="haze-button haze-compact" type="button" onClick={async () => {
                  const res = await fetch("/api/v1/governance/execute", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ proposalId: p.proposalId }) });
                  if (res.ok) setMessage(`Proposal #${p.proposalId} executed on-chain.`);
                }}>Execute</button>
              </div>
            </div>
          ))}
        </div>
      ) : null}
    </section>,
    mount,
  );
}

function humanError(code: string): string {
  switch (code) {
    case "RECIPIENT_ADDRESS_REQUIRED":
      return "Enter a haze1 recipient";
    case "DEPOSIT_NOTE_REQUIRED":
      return "Shield USDC first";
    case "FUJI_REQUIRED":
    case "WALLET_ON_WRONG_CHAIN":
      return "Switch to Avalanche Fuji in your wallet";
    case "SWAP_VENUE_UNAVAILABLE":
      return "Swap venue unavailable — try again later";
    case "AUDIT_PUBLIC_KEY_MISSING":
    default:
      return "Proof failed — retry";
  }
}

function formatAmount(value: string): string {
  const parsed = Number.parseFloat(value);
  if (Number.isNaN(parsed)) return "—";
  return parsed.toFixed(2);
}

function addressWordHex(address: string) {
  return `0x${address.replace(/^0x/, "").padStart(64, "0")}`;
}
