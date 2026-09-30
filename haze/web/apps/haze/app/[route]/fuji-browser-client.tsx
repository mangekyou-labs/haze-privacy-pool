"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useWalletSession } from "../wallet-session-provider";
import { concatBytes, functionSelector, hexToBuf } from "../../../../../sdk/typescript/src/abi.ts";
import { u64be } from "../../../../../sdk/typescript/src/field.ts";
import {
  decodeBrowserEnvelope,
  openBrowserHpke,
  parseBrowserRecipientPlaintext,
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
import { executeFujiBrowserTransaction, updateFujiMembershipRoot } from "../../../../../sdk/typescript/src/browser-fuji-flow.ts";
import {
  createBrowserOperationVault,
  type BrowserOperation,
  type BrowserOperationVault,
} from "../../../../../sdk/typescript/src/browser-operation-vault.ts";
import { createBrowserProver, generateBrowserSecrets } from "../../../../../sdk/typescript/src/browser-prover.ts";
import { buildSealedBrowserTransferWitness, buildSealedBrowserWitness } from "../../../../../sdk/typescript/src/browser-witness-flow.ts";
import { emergencyExitRequestId } from "../../../../../sdk/typescript/src/emergency.ts";
import { createFujiMembershipStore, type FujiMembershipStore } from "../../../../../sdk/typescript/src/fuji-membership-store.ts";
import { PRIVATE_TRANSACTION_TOPIC, decodePrivateTransaction, reconcileFujiOperation, recoverFujiOperation, type FujiLog, type FujiReceipt } from "../../../../../sdk/typescript/src/fuji-reconciliation.ts";
import { classifyBrowserError, type BrowserErrorCategory } from "../../../../../sdk/typescript/src/fuji-browser-error.ts";
import { noteCommitment, nullifier } from "../../../../../sdk/typescript/src/note.ts";
import { DEFAULT_HAZE_AUDIT_PUBLIC_KEY } from "../../../../../sdk/typescript/src/render-disclosure.ts";
import { buildLiveDepositWitness, buildLiveSwapWitness, buildLiveTransferWitness, buildLiveWithdrawWitness } from "../../../../../dev/operator-circuit-witness.mjs";

const CHAIN_ID = 43113;
const CHAIN_HEX = "0xa869";
const APPLICATION_ID = `0x${"00".repeat(30)}0a11`;
const POOL_VERSION_B002 = `0x${"00".repeat(30)}b001`;
const POOL_VERSION_B003 = `0x${"00".repeat(30)}b003`;
const POOL_B002 = "0x00BEB0A5D709d0F093952fD374Dbbf3d0d21d550";
const POOL_B003 = "0x919b338f189B1e564Af34A26fC002138f308f7dE";
const ROUTER = "0xdb386aeAd1C0b859903702454a7ECDfC306800F6";
const EMERGENCY_EXIT_CONTRACT = "0x3c40abEEAF252f3F37F59C8D72E7624D466f8ec9";
const USDC = "0x5425890298aed601595a70AB815c96711a31Bc65";
const PILOT_TOKEN = process.env.NEXT_PUBLIC_HAZE_PILOT_TOKEN || "0x15cF58144EF33af1e14b5208015d11F9143E27b9";
const APPLICATION_REGISTRY = "0xcCB53D8430E5c5555c66d56D2747660f97826f9E";
const POLICY_REGISTRY = "0x7147832d44094DD2a8A28470b9CD8C02e402162b";
const POLICY_AUTHORITY = "0xeD37FD0d6F0f69236E7472B36796e133D20EcC32";
const AUDIT_KEY = process.env.NEXT_PUBLIC_HAZE_AUDIT_PUBLIC_KEY || DEFAULT_HAZE_AUDIT_PUBLIC_KEY;
const DEFAULT_AMOUNT = 1_000_000;

type Ethereum = { request(input: { method: string; params?: unknown[] }): Promise<unknown> };
const hexBytes = (value: string) => Uint8Array.from(value.replace(/^0x/, "").match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));
const word = (value: string) => `0x${value.replace(/^0x/, "").padStart(64, "0")}`;
function ethereum(): Ethereum { const provider = (globalThis as typeof globalThis & { ethereum?: Ethereum }).ethereum; if (!provider) throw new Error("WALLET_UNAVAILABLE"); return provider; }
function words(value: string) { return value.replace(/^0x/, "").match(/.{64}/g) ?? []; }
function snapshot(app: string, version: string, root: string) { const values = words(app); const start = BigInt(`0x${values[0] ?? "0"}`) === 32n ? 1 : 0; return { membershipRoot: `0x${values[start + 4]}`, membershipVersion: BigInt(`0x${values[start + 5]}`), hazePolicyVersion: BigInt(version), hazeBlocklistRoot: word(root) }; }
function binding(operation: BrowserOperation, wallet: string, poolAddr = POOL_B002, poolVer = POOL_VERSION_B002) { return { chainId: CHAIN_ID, pool: poolAddr, poolVersion: poolVer, applicationId: APPLICATION_ID, user: wallet, action: operation.kind === "deposit" ? 1 : 3, commitment: operation.kind === "deposit" ? String(operation.note.commitment ?? "") : undefined, nullifier: operation.kind === "withdrawal" ? String(operation.note.nullifier ?? "") : undefined, kind: operation.kind, transactionHash: typeof operation.transaction.hash === "string" && operation.transaction.hash !== "pending" ? operation.transaction.hash : undefined } as const; }

export function FujiBrowserClient({ route }: { route: string }) {
  const {
    address: wallet,
    myHazeAddress,
    status,
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
  const [recipientHazeAddress, setRecipientHazeAddress] = useState("");
  const [previewed, setPreviewed] = useState(false);
  const [provingElapsed, setProvingElapsed] = useState(0);
  const [lastReceipt, setLastReceipt] = useState<{ amount: string; hash: string } | null>(null);
  const [vaultNotes, setVaultNotes] = useState<BrowserOperation[]>([]);
  const [proposals, setProposals] = useState<Array<{ proposalId: string; description: string; target: string; approvalsCount: number }>>([]);
  const [apps, setApps] = useState<Array<{ applicationId: string; name: string; adminWallet: string; membershipRoot: string; membershipVersion: number }>>([]);
  const [newMemberWallet, setNewMemberWallet] = useState("");
  const [emergencyRequestId, setEmergencyRequestId] = useState("");
  const [migrationStatus, setMigrationStatus] = useState<string | null>(null);

  const vault = useRef<BrowserOperationVault | undefined>(undefined);
  const shieldedAccount = useRef<BrowserShieldedAccount | undefined>(undefined);
  const membershipStore = useRef<FujiMembershipStore | undefined>(undefined);
  const worker = useRef<Worker | undefined>(undefined);
  const lastWithdrawal = useRef<BrowserOperation | undefined>(undefined);

  useEffect(() => {
    setMount(document.getElementById("fuji-browser-transaction-root"));
    return () => worker.current?.terminate();
  }, []);

  const rpc = useCallback((method: string, params: unknown[] = []) => ethereum().request({ method, params }), []);
  const receipt = useCallback(async (hash: string) => {
    for (let attempt = 0; attempt < 120; attempt += 1) {
      const found = await rpc("eth_getTransactionReceipt", [hash]) as FujiReceipt | null;
      if (found) return found;
      await new Promise((resolve) => setTimeout(resolve, 2_000));
    }
    return undefined;
  }, [rpc]);

  const readSnapshot = useCallback(async () => snapshot(
    await rpc("eth_call", [{ to: APPLICATION_REGISTRY, data: `${functionSelector("getApplication(bytes32)")}${APPLICATION_ID.slice(2)}` }, "latest"]) as string,
    await rpc("eth_call", [{ to: POLICY_REGISTRY, data: functionSelector("activeVersion()") }, "latest"]) as string,
    await rpc("eth_call", [{ to: POLICY_REGISTRY, data: functionSelector("activeRoot()") }, "latest"]) as string,
  ), [rpc]);

  const treeLeaves = useCallback(async (poolAddress = POOL_B002) => {
    const logs = await rpc("eth_getLogs", [{ address: poolAddress, fromBlock: "0x0", toBlock: "latest", topics: [PRIVATE_TRANSACTION_TOPIC, APPLICATION_ID] }]) as FujiLog[];
    const leaves: { leafIndex: number; commitment: string }[] = [];
    for (const log of logs) {
      const event = decodePrivateTransaction(log);
      for (const commitment of [event?.outputCommitment0, event?.outputCommitment1]) {
        if (commitment && BigInt(commitment) !== 0n) leaves.push({ leafIndex: leaves.length, commitment });
      }
    }
    return leaves;
  }, [rpc]);

  const loadVaultNotes = useCallback(async (active: BrowserOperationVault) => {
    const list = await active.list();
    setVaultNotes(list);
    lastWithdrawal.current = list.findLast((item) => item.kind === "withdrawal" && item.state === "confirmed");
  }, []);

  const recover = useCallback(async (active: BrowserOperationVault, address: string, account?: BrowserShieldedAccount) => {
    setTransactionStatus("recovering");
    const operations = await active.list();
    for (const operation of operations.filter((item) => item.state === "submitted")) {
      const result = await recoverFujiOperation({ ...binding(operation, address), rpc });
      if (result.confirmed) {
        const confirmed = await active.transition(operation.id, "confirmed", { recovered: true });
        if (operation.kind === "withdrawal") {
          if (typeof confirmed.note.depositOperationId === "string") await active.consumeConfirmedNote(confirmed.note.depositOperationId);
          lastWithdrawal.current = confirmed;
        }
      }
    }

    // Inbound note discovery: scan PrivateTransaction events for notes encrypted to our x25519 key
    if (account) {
      try {
        const logs = (await rpc("eth_getLogs", [
          { address: POOL_B002, fromBlock: "0x0", toBlock: "latest", topics: [PRIVATE_TRANSACTION_TOPIC, APPLICATION_ID] },
        ])) as FujiLog[];
        let leafIdx = 0;
        for (const log of logs) {
          const event = decodePrivateTransaction(log);
          if (!event) continue;
          const outs = [
            { commitment: event.outputCommitment0, envelope: extractLogEnvelope(log.data, 13), index: 0 },
            { commitment: event.outputCommitment1, envelope: extractLogEnvelope(log.data, 14), index: 1 },
          ];
          for (const out of outs) {
            if (!out.commitment || BigInt(out.commitment) === 0n || !out.envelope || out.envelope.ciphertext.length === 0) {
              continue;
            }
            const curLeafIndex = leafIdx;
            leafIdx += 1;
            try {
              const aad = concatBytes(
                u64be(CHAIN_ID),
                hexToBuf(POOL_B002),
                hexToBuf(APPLICATION_ID),
                hexToBuf(POOL_VERSION_B002),
                hexToBuf(out.commitment),
              );
              const plaintext = await openBrowserHpke({
                recipientPrivateKey: account.x25519PrivateKey,
                senderPublicKey: out.envelope.encapsulatedKey,
                ciphertext: out.envelope.ciphertext,
                aad,
              });
              const noteData = parseBrowserRecipientPlaintext(plaintext);
              const localCommitment = noteCommitment({
                spendingPublicKey: notePublicKey(noteData.spendingSecret),
                x25519PublicKey: noteData.x25519PublicKey,
                value: noteData.value,
                nullifierSecret: noteData.nullifierSecret,
              });
              if (localCommitment.toLowerCase() === out.commitment.toLowerCase()) {
                const localNullifier = nullifier({
                  nullifierSecret: noteData.nullifierSecret,
                  leafIndex: curLeafIndex,
                });
                const noteId = `recovered_${localCommitment.slice(0, 10)}`;
                const existing = await active.get(noteId);
                if (!existing) {
                  await active.create({
                    id: noteId,
                    kind: "deposit",
                    note: {
                      spendingSecret: noteData.spendingSecret,
                      nullifierSecret: noteData.nullifierSecret,
                      x25519PublicKey: noteData.x25519PublicKey,
                      value: noteData.value,
                      commitment: localCommitment,
                      nullifier: localNullifier,
                      spendable: true,
                    },
                    transaction: {
                      actionReference: noteId,
                      commitment: localCommitment,
                      nullifier: localNullifier,
                    },
                  });
                  await active.transition(noteId, "confirmed", { recoveredInbound: true });
                }
              }
            } catch {
              // Not encrypted to us, safely ignore
            }
          }
        }
      } catch {
        // Log scan failure handled gracefully
      }
    }

    await loadVaultNotes(active);
    setTransactionStatus("ready");
    setMessage("Vault recovered.");
  }, [loadVaultNotes, rpc]);

  // Synchronize vault and shielded account from WalletSessionProvider
  useEffect(() => {
    if (vaultRef?.current) {
      vault.current = vaultRef.current;
      loadVaultNotes(vaultRef.current);
    }
    if (accountRef?.current) {
      shieldedAccount.current = accountRef.current;
    }
    if (status === "connected" && wallet) {
      setTransactionStatus((prev) => (prev === "idle" || prev === "connecting" ? "ready" : prev));
    } else if (status === "disconnected") {
      setTransactionStatus("idle");
    }
  }, [vaultRef, accountRef, loadVaultNotes, status, wallet]);

  // Lazy membership store initialization
  useEffect(() => {
    membershipStore.current ??= createFujiMembershipStore();
  }, []);

  const connect = useCallback(async () => {
    setErrorCategory(null);
    setErrorMessage("");
    setTransactionStatus("connecting");
    try {
      await sessionConnect();
      if (vaultRef?.current && wallet) {
        await loadVaultNotes(vaultRef.current);
        await recover(vaultRef.current, wallet, accountRef?.current);
      }
      setTransactionStatus("ready");

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
    } catch (error: unknown) {
      setTransactionStatus("error");
      const classified = classifyBrowserError(error, "connecting");
      setErrorCategory(classified.category);
      setErrorMessage(classified.message);
      setMessage(classified.message);
    }
  }, [recover, route, wallet, sessionConnect, vaultRef, accountRef, loadVaultNotes]);

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
    if (!vault.current || !wallet) return connect();
    try {
      setErrorCategory(null);
      setErrorMessage("");
      if (!/^(?:0x)?[0-9a-f]{64}$/i.test(AUDIT_KEY)) throw new Error("AUDIT_PUBLIC_KEY_MISSING");
      setTransactionStatus("building_witness");
      const activeVault = vault.current;
      const leaves = await treeLeaves();
      const current = await readSnapshot();
      const secrets = generateBrowserSecrets();
      const storedMembers = (await membershipStore.current?.list()) ?? [];

      const isWithdrawal = route === "withdraw";
      const isSend = route === "send";
      const isSwap = route === "swap";

      if (isSend && !recipientHazeAddress) {
        throw new Error("RECIPIENT_ADDRESS_REQUIRED");
      }

      const spendAmount = Math.round(Number.parseFloat(userAmount || "1.0") * 1e6) || DEFAULT_AMOUNT;

      let quote: { tokenIn: string; amountIn: string; minUsdcOut: string; routeHash: string; deadline: number; adapter: string; data: string; expectedRouteHash: string } | undefined;
      if (isSwap) {
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

      const deposit = (await activeVault.list()).findLast((item) => item.kind === "deposit" && item.state === "confirmed" && item.note.spendable !== false);
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
        }) as unknown as ReturnType<typeof buildSealedBrowserWitness>;

        if (wallet.toLowerCase() === POLICY_AUTHORITY.toLowerCase()) {
          const after = await updateFujiMembershipRoot({
            membershipRoot: sealed.witness.membershipRoot,
            applicationId: APPLICATION_ID,
            policyAuthority: POLICY_AUTHORITY,
            wallet,
            readApplication: async () => {
              const state = await readSnapshot();
              return { membershipVersion: state.membershipVersion, membershipRoot: state.membershipRoot };
            },
            sendUpdate: async (appId, root) => rpc("eth_sendTransaction", [{ from: wallet, to: APPLICATION_REGISTRY, data: encodeMembershipRootUpdate(appId, root) }]) as Promise<string>,
            waitReceipt: receipt,
          });
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
          }) as unknown as ReturnType<typeof buildSealedBrowserWitness>;
        }
      } else if (isSwap && quote) {
        const swapWitnessInput = {
          ...common,
          tokenIn: quote.tokenIn,
          amountIn: quote.amountIn,
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
        });
        if (wallet.toLowerCase() === POLICY_AUTHORITY.toLowerCase()) {
          const after = await updateFujiMembershipRoot({
            membershipRoot: sealed.witness.membershipRoot,
            applicationId: APPLICATION_ID,
            policyAuthority: POLICY_AUTHORITY,
            wallet,
            readApplication: async () => {
              const state = await readSnapshot();
              return { membershipVersion: state.membershipVersion, membershipRoot: state.membershipRoot };
            },
            sendUpdate: async (appId, root) => rpc("eth_sendTransaction", [{ from: wallet, to: APPLICATION_REGISTRY, data: encodeMembershipRootUpdate(appId, root) }]) as Promise<string>,
            waitReceipt: receipt,
          });
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
          });
        }
      } else {
        const witnessInput = isWithdrawal
          ? { ...common, note: deposit!.note, publicRecipient: wallet, treeLeaves: leaves, membershipLeaves: storedMembers }
          : { ...common, leafIndex: leaves.length, membershipLeaves: storedMembers };

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
        });

        if (wallet.toLowerCase() === POLICY_AUTHORITY.toLowerCase()) {
          const after = await updateFujiMembershipRoot({
            membershipRoot: sealed.witness.membershipRoot,
            applicationId: APPLICATION_ID,
            policyAuthority: POLICY_AUTHORITY,
            wallet,
            readApplication: async () => {
              const state = await readSnapshot();
              return { membershipVersion: state.membershipVersion, membershipRoot: state.membershipRoot };
            },
            sendUpdate: async (appId, root) => rpc("eth_sendTransaction", [{ from: wallet, to: APPLICATION_REGISTRY, data: encodeMembershipRootUpdate(appId, root) }]) as Promise<string>,
            waitReceipt: receipt,
          });
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
          });
        }
      }

      const operationId = sealed.witness.actionReference;
      const noteToPersist = isSend
        ? (sealed.witness.note ? { ...sealed.witness.note, spendable: true, depositOperationId: deposit?.id } : { spendable: false, depositOperationId: deposit?.id })
        : isWithdrawal
          ? { ...sealed.witness.note, spendable: false, depositOperationId: deposit?.id }
          : { ...sealed.witness.note, spendable: true };

      const operation = await activeVault.create({
        id: operationId,
        kind: isWithdrawal ? "withdrawal" : isSend ? "transfer" : "deposit",
        note: noteToPersist,
        transaction: {
          actionReference: sealed.witness.actionReference,
          commitment: sealed.witness.note?.commitment ?? `0x${"00".repeat(32)}`,
          nullifier: sealed.witness.note?.nullifier ?? `0x${"00".repeat(32)}`,
        },
      });

      setTransactionStatus("proving");
      const browserProver = prover();
      const manifest = await (await fetch("/proving/fuji-development/haze-spend-v1/manifest.json", { cache: "no-store" })).json();
      await browserProver.loadFujiArtifacts(manifest);
      const proof = encodeBrowserGroth16Proof(await browserProver.proveSpend(sealed.witness.circom) as never);
      await activeVault.transition(operationId, "ready_to_submit", { proofReady: true });

      const actionId: 1 | 2 | 3 | 4 = isWithdrawal ? 3 : isSend ? 2 : isSwap ? 4 : 1;
      const plan = planBrowserFujiSpend({
        witness: sealed.witness,
        user: wallet,
        pool: POOL_B002,
        poolVersion: POOL_VERSION_B002,
        applicationId: APPLICATION_ID,
        action: actionId,
        now: Math.floor(Date.now() / 1000),
        proof,
        publicRecipient: isWithdrawal ? wallet : "0x0000000000000000000000000000000000000000",
        tokenIn: isSwap ? quote?.tokenIn : undefined,
        amountIn: isSwap ? quote?.amountIn : undefined,
        minUsdcOut: isSwap && quote ? Number(quote.minUsdcOut) : undefined,
        routeHash: isSwap ? quote?.routeHash : undefined,
        deadline: isSwap && quote ? Number(quote.deadline) : undefined,
      });

      const signature = await rpc("eth_signTypedData_v4", [wallet, JSON.stringify(plan.typedData)]) as string;
      const ready = (await activeVault.get(operationId))!;

      let approvalTransaction: { from: string; to: string; data: string } | undefined;
      let poolTransaction: { from: string; to: string; data: string };

      if (isSwap && quote) {
        approvalTransaction = { from: wallet, to: PILOT_TOKEN, data: encodeErc20Approve(ROUTER, spendAmount) };
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
        approvalTransaction = { from: wallet, to: USDC, data: encodeErc20Approve(POOL_B002, spendAmount) };
        poolTransaction = { from: wallet, ...encodeBrowserFujiSpend({ plan, signature }) };
      } else {
        approvalTransaction = undefined;
        poolTransaction = { from: wallet, ...encodeBrowserFujiSpend({ plan, signature }) };
      }

      setTransactionStatus("submitting");
      const result = await executeFujiBrowserTransaction({
        operation: ready,
        approvalTransaction,
        poolTransaction,
        send: (tx) => rpc("eth_sendTransaction", [tx]) as Promise<string>,
        waitReceipt: receipt,
        preflight: async (tx) => { await rpc("eth_call", [tx, "latest"]); },
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
      setLastReceipt({ amount: formatAmount(userAmount || "1"), hash: result.transactionHash });
    } catch (error: unknown) {
      console.error("Fuji workflow error:", error);
      setTransactionStatus("error");
      const classified = classifyBrowserError(error, transactionStatus);
      setErrorCategory(classified.category);
      setErrorMessage(classified.message);
      setMessage(classified.message);
    }
  }, [connect, loadVaultNotes, prover, readSnapshot, receipt, recipientHazeAddress, route, rpc, treeLeaves, userAmount, wallet, transactionStatus]);

  // Wipe IndexedDB vault with strict typed confirmation
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
    if (!wallet) return connect();
    try {
      setErrorCategory(null);
      setErrorMessage("");
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
    } catch (error: unknown) {
      setTransactionStatus("error");
      const classified = classifyBrowserError(error, "submitting");
      setErrorCategory(classified.category);
      setErrorMessage(classified.message);
      setMessage(classified.message);
    }
  }, [connect, receipt, rpc, wallet]);

  // Emergency exit: execute after 7 days
  const executeEmergency = useCallback(async () => {
    if (!wallet) return connect();
    try {
      setErrorCategory(null);
      setErrorMessage("");
      setTransactionStatus("executing_emergency");
      const data = `${functionSelector("executeEmergencyExit(bytes32,address)")}${emergencyRequestId.slice(2)}${addressWordHex(wallet).slice(2)}`;
      const hash = await rpc("eth_sendTransaction", [{ from: wallet, to: EMERGENCY_EXIT_CONTRACT, data }]) as string;
      await receipt(hash);
      setTransactionStatus("emergency_executed");
      setMessage(`Emergency exit executed successfully.`);
    } catch (error: unknown) {
      setTransactionStatus("error");
      const classified = classifyBrowserError(error, "submitting");
      setErrorCategory(classified.category);
      setErrorMessage(classified.message);
      setMessage(classified.message);
    }
  }, [connect, emergencyRequestId, receipt, rpc, wallet]);

  // Migration from B002 to B003
  const migratePool = useCallback(async () => {
    if (!wallet || !vault.current) return connect();
    try {
      setErrorCategory(null);
      setErrorMessage("");
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
    } catch (error: unknown) {
      setTransactionStatus("error");
      const classified = classifyBrowserError(error, "submitting");
      setErrorCategory(classified.category);
      setErrorMessage(classified.message);
      setMessage(classified.message);
      setMigrationStatus(classified.message);
    }
  }, [connect, prover, readSnapshot, receipt, rpc, treeLeaves, wallet]);

  const spendableNote = vaultNotes.find(
    (item) => item.kind === "deposit" && item.state === "confirmed" && item.note.spendable !== false,
  );
  const canSend = Boolean(wallet) && Boolean(spendableNote) && recipientHazeAddress.trim().length > 0;
  const amount = userAmount.trim() === "" ? "—" : userAmount;
  const actionLabel = `${route.charAt(0).toUpperCase()}${route.slice(1)} ${amount} USDC`;
  const proving = transactionStatus === "proving";

  useEffect(() => {
    if (!proving) return;
    const started = Date.now();
    const timer = setInterval(() => setProvingElapsed(Math.floor((Date.now() - started) / 1000)), 1000);
    return () => clearInterval(timer);
  }, [proving]);

  if (!mount) return null;

  return createPortal(
    <div className="haze-browser-live-status" data-transaction-status={transactionStatus}>
      {message ? <p className="haze-muted">{message}</p> : null}

      {route === "shield" || route === "withdraw" || route === "swap" || route === "send" ? (
        <div className="haze-action">
          <div className="haze-amount-row">
            <label className="haze-field haze-amount-field">Amount
              <input
                className="haze-amount haze-figure"
                type="text"
                value={userAmount}
                onChange={(e) => setUserAmount(e.target.value)}
                inputMode="decimal"
                autoComplete="off"
                disabled={!wallet}
              />
            </label>
            <span className="haze-token">{route === "swap" ? "PILOT" : "USDC"}</span>
          </div>

          {route === "send" ? (
            <div className="haze-send-fields">
              {myHazeAddress ? (
                <div className="haze-address-copy" data-haze-address={myHazeAddress}>
                  <span className="haze-muted">Your haze1</span>
                  <button className="haze-button haze-button-secondary haze-copy" type="button" onClick={() => void navigator.clipboard?.writeText(myHazeAddress)}>
                    Copy
                  </button>
                  <span className="haze-figure">{myHazeAddress.slice(0, 18)}…</span>
                </div>
              ) : null}
              {!spendableNote ? (
                <p className="haze-muted haze-empty-note">Shield USDC to create a private balance. <a href="/shield">Shield USDC</a></p>
              ) : null}
              <label className="haze-field">Recipient haze1
                <input
                  className="haze-figure"
                  type="text"
                  placeholder="haze1…"
                  value={recipientHazeAddress}
                  onChange={(e) => setRecipientHazeAddress(e.target.value)}
                  autoComplete="off"
                  disabled={!wallet}
                />
              </label>
            </div>
          ) : null}

          <button className="haze-button haze-preview-toggle" type="button" onClick={() => setPreviewed(!previewed)} data-action="preview">
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

          {transactionStatus === "proving" ? (
            <p className="haze-mono haze-proving" data-phase="proving">Generating proof… {provingElapsed}s</p>
          ) : null}
          {transactionStatus === "error" && errorCategory ? (
            <p className="haze-mono haze-error" data-error={errorCategory}>{errorMessage}</p>
          ) : null}
          {lastReceipt ? (
            <div className="haze-receipt" data-receipt="confirmed">
              <p className="haze-figure" data-balance="private">{lastReceipt.amount} USDC</p>
              <p className="haze-mono haze-receipt-hash">
                <a href={`https://testnet.snowtrace.io/tx/${lastReceipt.hash}`} target="_blank" rel="noreferrer">
                  {lastReceipt.hash.slice(0, 18)}… ↗
                </a>
              </p>
              {route === "shield" || route === "swap" ? (
                <a className="haze-button haze-button-secondary" href="/send">Next: Send</a>
              ) : (
                <a className="haze-button haze-button-secondary" href="/overview">Next: Overview</a>
              )}
            </div>
          ) : null}
          <div className="haze-actions">
            <button className="haze-button haze-confirm" type="button" onClick={() => void executeSpendWorkflow()} disabled={!wallet || (route === "send" && !canSend) || (route !== "send" && !previewed)}>
              {proving ? "Generating proof…" : actionLabel}
            </button>
          </div>
        </div>
      ) : null}

      {route === "overview" ? (
        <div className="haze-overview-client" data-card="overview-client">
          <div className="haze-actions">
            <a className="haze-button" href="/shield">Shield USDC</a>
            <a className="haze-button haze-button-secondary" href="/send">Send</a>
          </div>
        </div>
      ) : null}

      {route === "history" ? (
        <div className="haze-history">
          <h3 className="haze-subtitle">Local Vault Notes</h3>
          {vaultNotes.length === 0 ? (
            <p className="haze-empty">No notes in the local vault.</p>
          ) : (
            <ul className="haze-note-list">
              {vaultNotes.map((n) => (
                <li key={n.id} className="haze-note-item">
                  <strong>{n.kind.toUpperCase()}</strong> — {n.state} · {n.id.slice(0, 12)}…
                </li>
              ))}
            </ul>
          )}
          <div className="haze-actions">
            <button className="haze-button haze-button-secondary" type="button" onClick={wipeVault}>Wipe local vault</button>
            <button className="haze-button" type="button" onClick={() => wallet && vault.current && recover(vault.current, wallet, shieldedAccount.current)}>Recover from wallet message</button>
          </div>
        </div>
      ) : null}

      {route === "emergency-exit" ? (
        <div className="haze-emergency">
          <p className="haze-muted">Emergency exit allows an unconditional 7-day delayed exit from B002.</p>
          <div className="haze-actions">
            <button className="haze-button" type="button" onClick={requestEmergency}>1. Request Emergency Exit</button>
            <button className="haze-button haze-button-secondary" type="button" onClick={executeEmergency}>2. Execute After 7 Days</button>
          </div>
        </div>
      ) : null}

      {route === "migrate" ? (
        <div className="haze-migrate">
          <div className="haze-banner">
            <strong>Linkage Warning:</strong> Migration performs a public withdrawal from B002 followed by a public shield into B003.
          </div>
          {migrationStatus ? <p className="haze-mono">{migrationStatus}</p> : null}
          <div className="haze-actions">
            <button className="haze-button" type="button" onClick={migratePool}>Execute B002 → B003 Migration</button>
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
    </div>,
    mount,
  );
}

function formatAmount(value: string): string {
  const parsed = Number.parseFloat(value);
  if (Number.isNaN(parsed)) return "—";
  return parsed.toFixed(2);
}

function addressWordHex(address: string) {
  return `0x${address.replace(/^0x/, "").padStart(64, "0")}`;
}

function extractLogEnvelope(dataHex: string, wordIndex: number) {
  try {
    const raw = dataHex.replace(/^0x/, "");
    if (raw.length < 16 * 64) return undefined;
    const offsetHex = raw.slice(wordIndex * 64, (wordIndex + 1) * 64);
    const byteOffset = Number(BigInt(`0x${offsetHex}`));
    const charOffset = byteOffset * 2;
    if (raw.length < charOffset + 64) return undefined;
    const lenHex = raw.slice(charOffset, charOffset + 64);
    const byteLength = Number(BigInt(`0x${lenHex}`));
    const dataSlice = raw.slice(charOffset + 64, charOffset + 64 + byteLength * 2);
    if (dataSlice.length < byteLength * 2) return undefined;
    return decodeBrowserEnvelope(hexToBuf(`0x${dataSlice}`));
  } catch {
    return undefined;
  }
}
