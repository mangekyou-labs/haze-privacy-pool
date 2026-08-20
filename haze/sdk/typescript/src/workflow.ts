import { requireAddressBinding, type HazeAddress } from "./address.ts";
import { EMERGENCY_SELECTORS, POOL_SELECTORS, ROUTER_SELECTORS } from "./bindings.ts";
import type { ApplicationAuthorizationFields, HazeIntentFields } from "./eip712.ts";
import { EMERGENCY_EXIT_COOLDOWN, emergencyExitRequestId } from "./emergency.ts";
import { SdkError } from "./errors.ts";
import { createProverSession, ProverError } from "./prover.ts";
import type { HazeSwapQuote, QuoteAdapter } from "./quote.ts";

const ZERO32 = `0x${"00".repeat(32)}`;
const ZERO20 = "0x0000000000000000000000000000000000000000";

export type WorkflowKind =
  | "direct-shield"
  | "swap-and-shield"
  | "private-send"
  | "withdraw"
  | "emergency-exit"
  | "exit-and-reshield";

export type WorkflowPhase =
  | "idle"
  | "quoting"
  | "authorizing"
  | "proving"
  | "submitting"
  | "finalizing"
  | "finalized"
  | "cancelled"
  | "failed"
  | "resyncing";

export type WorkflowResult = {
  kind: WorkflowKind;
  phase: WorkflowPhase;
  action: number;
  nonceConsumed: boolean;
  publicWarnings: readonly string[];
  txHash?: string;
  requestId?: string;
  resynced?: boolean;
  retried?: boolean;
  linkage?: boolean;
};

export type WorkflowInput = {
  value?: bigint | number | string;
  outputCommitment0?: string;
  outputCommitment1?: string;
  recipientCiphertextHash0?: string;
  recipientCiphertextHash1?: string;
  inputNullifier0?: string;
  inputNullifier1?: string;
  publicRecipient?: string;
  recipientAddress?: HazeAddress;
  tokenIn?: string;
  amountIn?: string;
  minUsdcOut?: string | number;
  deadline?: number;
  nullifier?: string;
  requestSalt?: string;
  step?: "request" | "execute";
  replacementPool?: string;
  replacementPoolVersion?: string;
};

export type PolicySnapshot = {
  noteTreeRoot: string;
  applicationPolicyVersion: number;
  hazePolicyVersion: number;
  applicationMembershipRoot: string;
  hazeBlocklistRoot: string;
};

export type WorkflowWallet = {
  send(request: { to: string; data: string }): Promise<{ hash: string }>;
};

type Gatekeeper = {
  requestAuthorization(request: {
    applicationId: string;
    session: string;
    intent: HazeIntentFields;
  }): Promise<{ intent: HazeIntentFields; authorization: ApplicationAuthorizationFields }>;
};

type Prover = {
  cancel(): void;
  proveDevelopment(value: number): Promise<unknown>;
};

type WorkflowConfig = {
  chainId: number;
  pool: string;
  router: string;
  exit: string;
  poolVersion: string;
  applicationId: string;
  user: string;
  session: string;
  gatekeeper: Gatekeeper;
  quotes?: QuoteAdapter;
  wallet: WorkflowWallet;
  policy: { snapshot(): Promise<PolicySnapshot> };
  finality: {
    wait(txHash: string): Promise<{ status: string; blockNumber: number; events: unknown[] }>;
  };
  clock: () => number;
  prover?: Prover;
  vault?: unknown;
};

const PUBLIC_WARNINGS: Record<WorkflowKind, readonly string[]> = {
  "direct-shield": ["deposit-amount", "wallet-address", "gas"],
  "swap-and-shield": ["source-token-swap", "deposit-amount", "wallet-address", "gas"],
  "private-send": ["wallet-address", "gas"],
  withdraw: ["withdrawal-amount", "wallet-address", "gas"],
  "emergency-exit": ["withdrawal-amount", "wallet-address", "gas"],
  "exit-and-reshield": ["withdrawal-amount", "deposit-amount", "wallet-address", "gas"],
};

function asNumber(value: bigint | number | string | undefined): number {
  if (value === undefined) {
    return 0;
  }
  if (typeof value === "bigint") {
    return Number(value);
  }
  return Number(value);
}

function hexOrZero32(value: string | undefined): string {
  return value ?? ZERO32;
}

function hexOrZero20(value: string | undefined): string {
  return value ?? ZERO20;
}

function actionFor(kind: WorkflowKind): number {
  switch (kind) {
    case "direct-shield":
      return 1;
    case "private-send":
      return 2;
    case "withdraw":
      return 3;
    case "swap-and-shield":
      return 4;
    case "emergency-exit":
      return 5;
    case "exit-and-reshield":
      return 3;
  }
}

function selectorFor(kind: WorkflowKind, step?: "request" | "execute"): string {
  switch (kind) {
    case "direct-shield":
      return POOL_SELECTORS.deposit;
    case "private-send":
    case "withdraw":
      return POOL_SELECTORS.transact;
    case "swap-and-shield":
      return ROUTER_SELECTORS.swapAndShield;
    case "emergency-exit":
      return step === "execute"
        ? EMERGENCY_SELECTORS.executeEmergencyExit
        : EMERGENCY_SELECTORS.requestEmergencyExit;
    case "exit-and-reshield":
      return POOL_SELECTORS.transact;
  }
}

function targetFor(kind: WorkflowKind, config: WorkflowConfig): string {
  if (kind === "swap-and-shield") {
    return config.router;
  }
  if (kind === "emergency-exit") {
    return config.exit;
  }
  return config.pool;
}

export function createWorkflowClient(config: WorkflowConfig) {
  let phase: WorkflowPhase = "idle";
  let consumed = false;
  let authorizations = 0;
  let lastAuthorization: ApplicationAuthorizationFields | undefined;
  let lastIntent: HazeIntentFields | undefined;
  let lastQuote: HazeSwapQuote | undefined;
  let emergencyRequestedAt: number | undefined;
  const prover = config.prover ?? createProverSession();

  function fail(error: unknown): never {
    if (error instanceof ProverError && error.code === "CANCELLED") {
      phase = "cancelled";
    } else {
      phase = "failed";
    }
    throw error;
  }

  function draftIntent(
    kind: Exclude<WorkflowKind, "emergency-exit" | "exit-and-reshield"> | "withdraw" | "direct-shield",
    input: WorkflowInput,
    snapshot: PolicySnapshot,
    quote: HazeSwapQuote | undefined,
    binding: { pool: string; poolVersion: string },
  ): HazeIntentFields {
    const action = actionFor(kind);
    const deposit = action === 1;
    const transfer = action === 2;
    const swap = action === 4;
    return {
      applicationId: config.applicationId,
      user: config.user,
      pool: binding.pool,
      poolVersion: binding.poolVersion,
      action,
      noteTreeRoot: deposit ? ZERO32 : snapshot.noteTreeRoot,
      applicationPolicyVersion: snapshot.applicationPolicyVersion,
      hazePolicyVersion: snapshot.hazePolicyVersion,
      applicationMembershipRoot: snapshot.applicationMembershipRoot,
      hazeBlocklistRoot: snapshot.hazeBlocklistRoot,
      inputNullifier0: deposit ? ZERO32 : hexOrZero32(input.inputNullifier0),
      inputNullifier1: deposit ? ZERO32 : hexOrZero32(input.inputNullifier1),
      outputCommitment0: hexOrZero32(input.outputCommitment0),
      outputCommitment1: hexOrZero32(input.outputCommitment1),
      publicAmount: transfer ? 0 : asNumber(input.value),
      publicRecipient: transfer || deposit ? ZERO20 : hexOrZero20(input.publicRecipient),
      recipientCiphertextHash0: hexOrZero32(input.recipientCiphertextHash0),
      recipientCiphertextHash1: hexOrZero32(input.recipientCiphertextHash1),
      auditDataCommitment: ZERO32,
      auditCiphertextHash: ZERO32,
      tokenIn: swap ? (input.tokenIn ?? ZERO20) : ZERO20,
      amountIn: swap ? (input.amountIn ?? ZERO32) : ZERO32,
      minUsdcOut: swap ? asNumber(quote?.minUsdcOut ?? input.minUsdcOut) : 0,
      routeHash: swap ? (quote?.routeHash ?? ZERO32) : ZERO32,
      deadline: swap ? (input.deadline ?? 0) : 0,
    };
  }

  async function quoteSwap(input: WorkflowInput): Promise<HazeSwapQuote> {
    phase = "quoting";
    if (!config.quotes) {
      throw new SdkError("UNAVAILABLE");
    }
    const quote = await config.quotes.quote({
      tokenIn: input.tokenIn ?? ZERO20,
      amountIn: input.amountIn ?? ZERO32,
      minUsdcOut: String(input.minUsdcOut ?? "0"),
      deadline: input.deadline ?? 0,
    });
    if (config.clock() > quote.expiry) {
      throw new SdkError("QUOTE_STALE");
    }
    lastQuote = quote;
    return quote;
  }

  async function authorizeIntent(intent: HazeIntentFields): Promise<{
    intent: HazeIntentFields;
    authorization: ApplicationAuthorizationFields;
  }> {
    phase = "authorizing";
    const granted = await config.gatekeeper.requestAuthorization({
      applicationId: config.applicationId,
      session: config.session,
      intent,
    });
    lastIntent = granted.intent;
    lastAuthorization = granted.authorization;
    authorizations += 1;
    return granted;
  }

  async function prove(value: number): Promise<void> {
    phase = "proving";
    await prover.proveDevelopment(value);
  }

  function assertAuthorizationLive(authorization: ApplicationAuthorizationFields): void {
    const now = config.clock();
    if (now > authorization.validUntil || now < authorization.validAfter) {
      throw new SdkError("AUTHORIZATION_EXPIRED");
    }
  }

  async function submitAuthorized(
    to: string,
    selector: string,
    authorization: ApplicationAuthorizationFields,
  ): Promise<{ hash: string; data: string }> {
    assertAuthorizationLive(authorization);
    phase = "submitting";
    const data = `${selector}${authorization.nonce.slice(2)}`;
    const sent = await config.wallet.send({ to, data });
    return { hash: sent.hash, data };
  }

  async function waitFinal(txHash: string): Promise<{ status: string }> {
    phase = "finalizing";
    return config.finality.wait(txHash);
  }

  async function submitAndFinalize(
    kind: WorkflowKind,
    input: WorkflowInput,
    granted: { intent: HazeIntentFields; authorization: ApplicationAuthorizationFields },
    flags: { resynced: boolean; retried: boolean },
    to = targetFor(kind, config),
  ): Promise<WorkflowResult> {
    const selector = selectorFor(kind, input.step);
    let submitted: { hash: string; data: string };
    try {
      submitted = await submitAuthorized(to, selector, granted.authorization);
    } catch (error) {
      if (error instanceof SdkError && error.code === "POLICY_STALE") {
        phase = "resyncing";
        flags.resynced = true;
        const again = await authorizeAndProve(kind, input, { pool: to, poolVersion: granted.intent.poolVersion });
        return submitAndFinalize(kind, input, again, flags, to);
      }
      throw error;
    }

    let receipt = await waitFinal(submitted.hash);
    if (receipt.status === "reorged") {
      flags.retried = true;
      phase = "submitting";
      const retry = await config.wallet.send({ to, data: submitted.data });
      receipt = await waitFinal(retry.hash);
      submitted = { hash: retry.hash, data: submitted.data };
    }

    consumed = true;
    phase = "finalized";
    return {
      kind,
      phase,
      action: granted.intent.action,
      nonceConsumed: consumed,
      publicWarnings: PUBLIC_WARNINGS[kind],
      txHash: submitted.hash,
      resynced: flags.resynced || undefined,
      retried: flags.retried || undefined,
    };
  }

  async function authorizeAndProve(
    kind: WorkflowKind,
    input: WorkflowInput,
    binding: { pool: string; poolVersion: string } = {
      pool: config.pool,
      poolVersion: config.poolVersion,
    },
  ): Promise<{ intent: HazeIntentFields; authorization: ApplicationAuthorizationFields }> {
    const snapshot = await config.policy.snapshot();
    const quote = kind === "swap-and-shield" ? lastQuote : undefined;
    const mapped =
      kind === "exit-and-reshield"
        ? ("withdraw" as const)
        : kind === "emergency-exit"
          ? ("withdraw" as const)
          : kind;
    const draft = draftIntent(mapped, input, snapshot, quote, binding);
    const granted = await authorizeIntent(draft);
    await prove(granted.intent.publicAmount);
    return granted;
  }

  async function runAuthorized(kind: WorkflowKind, input: WorkflowInput): Promise<WorkflowResult> {
    if (kind === "private-send") {
      if (!input.recipientAddress) {
        throw new SdkError("ENCODING_INVALID");
      }
      requireAddressBinding(input.recipientAddress, {
        chainId: config.chainId,
        applicationId: config.applicationId,
        poolVersion: config.poolVersion,
      });
    }
    if (kind === "swap-and-shield") {
      await quoteSwap(input);
    }
    const granted = await authorizeAndProve(kind, input);
    return submitAndFinalize(kind, input, granted, { resynced: false, retried: false });
  }

  async function runEmergency(input: WorkflowInput): Promise<WorkflowResult> {
    const requestId = emergencyExitRequestId({
      chainId: config.chainId,
      pool: config.pool,
      poolVersion: config.poolVersion,
      applicationId: config.applicationId,
      nullifier: input.nullifier ?? ZERO32,
      recipient: input.publicRecipient ?? ZERO20,
      requestSalt: input.requestSalt ?? ZERO32,
    });
    if (input.step === "execute") {
      if (
        emergencyRequestedAt === undefined ||
        config.clock() < emergencyRequestedAt + EMERGENCY_EXIT_COOLDOWN
      ) {
        throw new SdkError("TIMELOCK");
      }
    }

    await prove(asNumber(input.value));
    phase = "submitting";
    const selector = selectorFor("emergency-exit", input.step);
    const sent = await config.wallet.send({
      to: config.exit,
      data: `${selector}${requestId.slice(2)}`,
    });
    await waitFinal(sent.hash);
    if (input.step !== "execute") {
      emergencyRequestedAt = config.clock();
    }
    phase = "finalized";
    return {
      kind: "emergency-exit",
      phase,
      action: 5,
      nonceConsumed: false,
      publicWarnings: PUBLIC_WARNINGS["emergency-exit"],
      txHash: sent.hash,
      requestId,
    };
  }

  async function runExitAndReshield(input: WorkflowInput): Promise<WorkflowResult> {
    const withdraw = await runAuthorized("withdraw", input);
    if (!input.replacementPool || !input.replacementPoolVersion) {
      throw new SdkError("ENCODING_INVALID");
    }
    const snapshot = await config.policy.snapshot();
    const draft = draftIntent(
      "direct-shield",
      {
        ...input,
        inputNullifier0: ZERO32,
        inputNullifier1: ZERO32,
      },
      snapshot,
      undefined,
      { pool: input.replacementPool, poolVersion: input.replacementPoolVersion },
    );
    const granted = await authorizeIntent(draft);
    await prove(granted.intent.publicAmount);
    const flags = { resynced: withdraw.resynced === true, retried: withdraw.retried === true };
    const shielded = await submitAndFinalize(
      "direct-shield",
      input,
      granted,
      flags,
      input.replacementPool,
    );
    phase = "finalized";
    return {
      kind: "exit-and-reshield",
      phase,
      action: 1,
      nonceConsumed: consumed,
      publicWarnings: PUBLIC_WARNINGS["exit-and-reshield"],
      txHash: shielded.txHash,
      linkage: true,
      resynced: flags.resynced || undefined,
      retried: flags.retried || undefined,
    };
  }

  return {
    phase(): WorkflowPhase {
      return phase;
    },
    publicWarnings(kind: WorkflowKind): readonly string[] {
      return PUBLIC_WARNINGS[kind];
    },
    cancel() {
      prover.cancel();
    },
    nonceConsumed() {
      return consumed;
    },
    authorizationCount() {
      return authorizations;
    },
    lastAuthorization(): ApplicationAuthorizationFields | undefined {
      return lastAuthorization;
    },
    lastIntent(): HazeIntentFields | undefined {
      return lastIntent;
    },
    lastQuote(): HazeSwapQuote | undefined {
      return lastQuote;
    },
    async run(kind: WorkflowKind, input: WorkflowInput): Promise<WorkflowResult> {
      consumed = false;
      try {
        if (kind === "emergency-exit") {
          return await runEmergency(input);
        }
        if (kind === "exit-and-reshield") {
          return await runExitAndReshield(input);
        }
        return await runAuthorized(kind, input);
      } catch (error) {
        fail(error);
      }
    },
  };
}
