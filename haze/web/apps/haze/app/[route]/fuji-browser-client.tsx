"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { functionSelector } from "../../../../../sdk/typescript/src/abi.ts";
import { encodeBrowserFujiSpend, encodeBrowserGroth16Proof, encodeErc20Approve, encodeMembershipRootUpdate, planBrowserFujiSpend } from "../../../../../sdk/typescript/src/browser-fuji-contracts.ts";
import { executeFujiBrowserTransaction, updateFujiMembershipRoot } from "../../../../../sdk/typescript/src/browser-fuji-flow.ts";
import { createBrowserOperationVault, createIndexedDbOperationStore, type BrowserOperation } from "../../../../../sdk/typescript/src/browser-operation-vault.ts";
import { createBrowserProver, generateBrowserSecrets } from "../../../../../sdk/typescript/src/browser-prover.ts";
import { buildSealedBrowserWitness } from "../../../../../sdk/typescript/src/browser-witness-flow.ts";
import { PRIVATE_TRANSACTION_TOPIC, decodePrivateTransaction, reconcileFujiOperation, recoverFujiOperation, type FujiLog, type FujiReceipt } from "../../../../../sdk/typescript/src/fuji-reconciliation.ts";
import { DEFAULT_HAZE_AUDIT_PUBLIC_KEY, DEFAULT_HAZE_DISCLOSURE_ORIGIN, planFujiWithdrawalDisclosure, requestFujiDisclosure } from "../../../../../sdk/typescript/src/render-disclosure.ts";
import { buildLiveDepositWitness, buildLiveWithdrawWitness } from "../../../../../dev/operator-circuit-witness.mjs";

const CHAIN_ID = 43113; const CHAIN_HEX = "0xa869";
const APPLICATION_ID = `0x${"00".repeat(30)}0a11`; const POOL_VERSION = `0x${"00".repeat(30)}b001`;
const POOL = "0x00BEB0A5D709d0F093952fD374Dbbf3d0d21d550";
const USDC = "0x5425890298aed601595a70AB815c96711a31Bc65";
const APPLICATION_REGISTRY = "0xcCB53D8430E5c5555c66d56D2747660f97826f9E";
const POLICY_REGISTRY = "0x7147832d44094DD2a8A28470b9CD8C02e402162b";
const POLICY_AUTHORITY = "0xeD37FD0d6F0f69236E7472B36796e133D20EcC32";
const AUDIT_KEY = process.env.NEXT_PUBLIC_HAZE_AUDIT_PUBLIC_KEY || DEFAULT_HAZE_AUDIT_PUBLIC_KEY;
const AMOUNT = 1_000_000;
type Ethereum = { request(input: { method: string; params?: unknown[] }): Promise<unknown> };
type Vault = Awaited<ReturnType<typeof createBrowserOperationVault>>;
const hexBytes = (value: string) => Uint8Array.from(value.replace(/^0x/, "").match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));
const word = (value: string) => `0x${value.replace(/^0x/, "").padStart(64, "0")}`;
function ethereum(): Ethereum { const provider = (globalThis as typeof globalThis & { ethereum?: Ethereum }).ethereum; if (!provider) throw new Error("WALLET_UNAVAILABLE"); return provider; }
function words(value: string) { return value.replace(/^0x/, "").match(/.{64}/g) ?? []; }
function snapshot(app: string, version: string, root: string) { const values = words(app); const start = BigInt(`0x${values[0] ?? "0"}`) === 32n ? 1 : 0; return { membershipRoot: `0x${values[start + 4]}`, membershipVersion: BigInt(`0x${values[start + 5]}`), hazePolicyVersion: BigInt(version), hazeBlocklistRoot: word(root) }; }
function binding(operation: BrowserOperation, wallet: string) { return { chainId: CHAIN_ID, pool: POOL, poolVersion: POOL_VERSION, applicationId: APPLICATION_ID, user: wallet, action: operation.kind === "deposit" ? 1 : 3, commitment: operation.kind === "deposit" ? String(operation.note.commitment ?? "") : undefined, nullifier: operation.kind === "withdrawal" ? String(operation.note.nullifier ?? "") : undefined, kind: operation.kind, transactionHash: typeof operation.transaction.hash === "string" && operation.transaction.hash !== "pending" ? operation.transaction.hash : undefined } as const; }

export function FujiBrowserClient({ route }: { route: string }) {
  const [mount, setMount] = useState<HTMLElement | null>(null);
  const [wallet, setWallet] = useState(""); const [transactionStatus, setTransactionStatus] = useState("wallet_disconnected"); const [disclosureStatus, setDisclosureStatus] = useState("not_requested"); const [message, setMessage] = useState("Connect the Fuji policy-authority wallet.");
  const vault = useRef<Vault | undefined>(undefined); const worker = useRef<Worker | undefined>(undefined); const lastWithdrawal = useRef<BrowserOperation | undefined>(undefined);
  useEffect(() => {
    setMount(document.getElementById("fuji-browser-transaction-root"));
    return () => worker.current?.terminate();
  }, []);
  const rpc = useCallback((method: string, params: unknown[] = []) => ethereum().request({ method, params }), []);
  const receipt = useCallback(async (hash: string) => { for (let attempt = 0; attempt < 120; attempt += 1) { const found = await rpc("eth_getTransactionReceipt", [hash]) as FujiReceipt | null; if (found) return found; await new Promise((resolve) => setTimeout(resolve, 2_000)); } return undefined; }, [rpc]);
  const readSnapshot = useCallback(async () => snapshot(
    await rpc("eth_call", [{ to: APPLICATION_REGISTRY, data: `${functionSelector("getApplication(bytes32)")}${APPLICATION_ID.slice(2)}` }, "latest"]) as string,
    await rpc("eth_call", [{ to: POLICY_REGISTRY, data: functionSelector("activeVersion()") }, "latest"]) as string,
    await rpc("eth_call", [{ to: POLICY_REGISTRY, data: functionSelector("activeRoot()") }, "latest"]) as string,
  ), [rpc]);
  const treeLeaves = useCallback(async () => { const logs = await rpc("eth_getLogs", [{ address: POOL, fromBlock: "0x0", toBlock: "latest", topics: [PRIVATE_TRANSACTION_TOPIC, APPLICATION_ID] }]) as FujiLog[]; const leaves: { leafIndex: number; commitment: string }[] = []; for (const log of logs) { const event = decodePrivateTransaction(log); for (const commitment of [event?.outputCommitment0, event?.outputCommitment1]) if (commitment && BigInt(commitment) !== 0n) leaves.push({ leafIndex: leaves.length, commitment }); } return leaves; }, [rpc]);
  const recover = useCallback(async (active: Vault, address: string) => { setTransactionStatus("recovering"); const operations = await active.list(); lastWithdrawal.current = operations.findLast((item) => item.kind === "withdrawal" && item.state === "confirmed"); for (const operation of operations.filter((item) => item.state === "submitted")) { const result = await recoverFujiOperation({ ...binding(operation, address), rpc }); if (result.confirmed) { const confirmed = await active.transition(operation.id, "confirmed", { recovered: true }); if (operation.kind === "withdrawal") { if (typeof confirmed.note.depositOperationId === "string") await active.consumeConfirmedNote(confirmed.note.depositOperationId); lastWithdrawal.current = confirmed; } } } setTransactionStatus("ready"); }, [rpc]);
  const connect = useCallback(async () => { try { const accounts = await rpc("eth_requestAccounts") as string[]; const address = accounts[0]; if (!address || (await rpc("eth_chainId")) !== CHAIN_HEX) throw new Error("FUJI_REQUIRED"); if (address.toLowerCase() !== POLICY_AUTHORITY.toLowerCase()) throw new Error("POLICY_AUTHORITY_REQUIRED"); const signature = await rpc("personal_sign", [`Unlock Haze Fuji recovery vault\n${APPLICATION_ID}\n${POOL}`, address]) as string; const active = await createBrowserOperationVault({ database: createIndexedDbOperationStore(), signature, binding: { chainId: CHAIN_ID, applicationId: APPLICATION_ID, pool: POOL, wallet: address } }); vault.current = active; setWallet(address); await recover(active, address); } catch (error) { setTransactionStatus("error"); setMessage(error instanceof Error ? error.message : "WALLET_ERROR"); } }, [recover, rpc]);
  const prover = useCallback(() => { worker.current ??= new Worker(new URL("../../../../../sdk/typescript/src/prover-worker.ts", import.meta.url), { type: "module" }); return createBrowserProver({ worker: worker.current, profile: "fuji-development", expectedArtifactHash: "0x374bb2394da985ab824ce61a95b3b3409b71355139f0a6b16fb8e0bff8e508d5" }); }, []);

  const begin = useCallback(async () => { if (!vault.current || !wallet) return connect(); try {
    if (!/^(?:0x)?[0-9a-f]{64}$/i.test(AUDIT_KEY)) throw new Error("AUDIT_PUBLIC_KEY_MISSING");
    setTransactionStatus("building_witness"); const activeVault = vault.current; const leaves = await treeLeaves(); const current = await readSnapshot(); const secrets = generateBrowserSecrets();
    const isWithdrawal = route === "withdraw"; const deposit = (await activeVault.list()).find((item) => item.kind === "deposit" && item.state === "confirmed" && item.note.spendable !== false);
    if (isWithdrawal && !deposit) throw new Error("DEPOSIT_NOTE_REQUIRED");
    const common = { pool: POOL, user: wallet, applicationId: APPLICATION_ID, poolVersion: POOL_VERSION, publicAmount: AMOUNT, applicationPolicyVersion: Number(current.membershipVersion), hazePolicyVersion: Number(current.hazePolicyVersion) };
    const witnessInput = isWithdrawal ? { ...common, note: deposit!.note, publicRecipient: wallet, treeLeaves: leaves } : { ...common, leafIndex: leaves.length };
    const factory = isWithdrawal ? buildLiveWithdrawWitness : buildLiveDepositWitness;
    let sealed = buildSealedBrowserWitness({ buildWitness: factory, witnessInput, chainId: CHAIN_ID, pool: POOL, poolVersion: POOL_VERSION, applicationId: APPLICATION_ID, auditPublicKey: hexBytes(AUDIT_KEY), auditKeyVersion: 1n, caseTag: new TextEncoder().encode(isWithdrawal ? "WITHDRAWAL" : "DEPOSIT"), secrets });
    const after = await updateFujiMembershipRoot({ membershipRoot: sealed.witness.membershipRoot, applicationId: APPLICATION_ID, policyAuthority: POLICY_AUTHORITY, wallet, readApplication: async () => { const state = await readSnapshot(); return { membershipVersion: state.membershipVersion, membershipRoot: state.membershipRoot }; }, sendUpdate: async (applicationId, root) => rpc("eth_sendTransaction", [{ from: wallet, to: APPLICATION_REGISTRY, data: encodeMembershipRootUpdate(applicationId, root) }]) as Promise<string>, waitReceipt: receipt });
    sealed = buildSealedBrowserWitness({ buildWitness: factory, witnessInput: { ...witnessInput, applicationPolicyVersion: Number(after.membershipVersion) }, chainId: CHAIN_ID, pool: POOL, poolVersion: POOL_VERSION, applicationId: APPLICATION_ID, auditPublicKey: hexBytes(AUDIT_KEY), auditKeyVersion: 1n, caseTag: new TextEncoder().encode(isWithdrawal ? "WITHDRAWAL" : "DEPOSIT"), secrets });
    const operationId = sealed.witness.actionReference; const operation = await activeVault.create({ id: operationId, kind: isWithdrawal ? "withdrawal" : "deposit", note: { ...sealed.witness.note, spendable: true, depositOperationId: deposit?.id }, transaction: { actionReference: sealed.witness.actionReference, commitment: sealed.witness.note.commitment, nullifier: sealed.witness.note.nullifier } });
    setTransactionStatus("proving"); const browserProver = prover(); const manifest = await (await fetch("/proving/fuji-development/haze-spend-v1/manifest.json", { cache: "no-store" })).json(); await browserProver.loadFujiArtifacts(manifest); const proof = encodeBrowserGroth16Proof(await browserProver.proveSpend(sealed.witness.circom) as never); await activeVault.transition(operationId, "ready_to_submit", { proofReady: true });
    const plan = planBrowserFujiSpend({ witness: sealed.witness, user: wallet, pool: POOL, poolVersion: POOL_VERSION, applicationId: APPLICATION_ID, action: isWithdrawal ? 3 : 1, now: Math.floor(Date.now() / 1000), proof, publicRecipient: isWithdrawal ? wallet : undefined }); const signature = await rpc("eth_signTypedData_v4", [wallet, JSON.stringify(plan.typedData)]) as string; const transaction = encodeBrowserFujiSpend({ plan, signature }); const ready = (await activeVault.get(operationId))!;
    setTransactionStatus("submitting"); const result = await executeFujiBrowserTransaction({ operation: ready, approvalTransaction: isWithdrawal ? undefined : { from: wallet, to: USDC, data: encodeErc20Approve(POOL, AMOUNT) }, poolTransaction: { from: wallet, ...transaction }, send: (tx) => rpc("eth_sendTransaction", [tx]) as Promise<string>, waitReceipt: receipt, preflight: async (tx) => { await rpc("eth_call", [tx, "latest"]); }, markSubmittedBeforeBroadcast: activeVault.markSubmittedBeforeBroadcast, recordSubmittedHash: activeVault.recordSubmittedHash, reconcile: (value) => reconcileFujiOperation({ ...binding(ready, wallet), receipt: value as FujiReceipt }) });
    if (!result.confirmed) throw new Error("FUJI_EVENT_NOT_CONFIRMED"); await activeVault.transition(operationId, "confirmed", { hash: result.transactionHash }); if (isWithdrawal) { await activeVault.consumeConfirmedNote(deposit!.id); lastWithdrawal.current = await activeVault.get(operationId); } setTransactionStatus("confirmed"); setMessage(`Fuji ${isWithdrawal ? "withdrawal" : "deposit"} confirmed with a matching PrivateTransaction event.`);
  } catch (error) { console.error("Fuji transaction error:", error); setTransactionStatus("error"); setMessage(error instanceof Error ? error.message : "TRANSACTION_FAILED"); } }, [connect, prover, readSnapshot, receipt, route, rpc, treeLeaves, wallet]);

  const disclose = useCallback(async () => { const operation = lastWithdrawal.current; const hash = operation?.transaction.hash; if (typeof hash !== "string") return; setDisclosureStatus("requesting"); try { const expiresAt = Math.floor(Date.now() / 1000) + 600; const plan = planFujiWithdrawalDisclosure({ transactionHash: hash, applicationId: APPLICATION_ID, pool: POOL, chainId: CHAIN_ID, expiresAt }); const signature = await rpc("eth_signTypedData_v4", [wallet, JSON.stringify(plan.typedData)]) as string; await requestFujiDisclosure({ origin: process.env.NEXT_PUBLIC_HAZE_DISCLOSURE_ORIGIN || DEFAULT_HAZE_DISCLOSURE_ORIGIN, body: { transactionHash: hash, applicationId: APPLICATION_ID, requestedFields: plan.requestedFields, expiresAt, signature } }); setDisclosureStatus("success"); } catch (error) { setDisclosureStatus("failed"); setMessage(error instanceof Error ? error.message : "DISCLOSURE_FAILED"); } }, [rpc, wallet]);
  if (!mount) return null;
  return createPortal(
    <section className="haze-form" aria-label="Fuji browser transaction">
      <p className="haze-mono" data-transaction-status={transactionStatus}>Transaction: {transactionStatus}</p>
      <p className="haze-mono" data-disclosure-status={disclosureStatus}>Disclosure: {disclosureStatus}</p>
      <p className="haze-muted">{message}</p>
      <div className="haze-actions">
        <button className="haze-button" type="button" onClick={begin}>{wallet ? `${route === "withdraw" ? "Withdraw" : "Deposit"} 1 USDC` : "Connect wallet"}</button>
        {route === "withdraw" && lastWithdrawal.current ? <button className="haze-button haze-button-secondary" type="button" onClick={disclose}>Request wallet-scoped disclosure</button> : null}
      </div>
    </section>,
    mount,
  );
}
