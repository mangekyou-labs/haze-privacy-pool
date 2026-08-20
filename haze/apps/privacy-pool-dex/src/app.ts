/** Library-first Privacy Pool DEX controller. Hosted Next.js remains T6.2. */

import {
  authorizeRoute,
  copyFor,
  designSystem,
  layoutFor,
  navFor,
  primitive,
} from "../../_shared/ux.ts";
import type { Session } from "../../_shared/ux.ts";
import { encodeHazeAddress } from "../../../sdk/typescript/src/address.ts";
import { SdkError } from "../../../sdk/typescript/src/errors.ts";
import type { HazeSwapQuote, QuoteAdapter } from "../../../sdk/typescript/src/quote.ts";
import {
  createLocalVault,
  createMemoryStore,
  deriveVaultAccount,
} from "../../../sdk/typescript/src/vault.ts";
import type { NoteEvent, VaultAccount, VaultNote } from "../../../sdk/typescript/src/vault.ts";
import { createWorkflowClient } from "../../../sdk/typescript/src/workflow.ts";
import type {
  WorkflowInput,
  WorkflowKind,
  WorkflowPhase,
  WorkflowResult,
  WorkflowWallet,
} from "../../../sdk/typescript/src/workflow.ts";

const APP = "privacy-pool-dex" as const;

export type WalletStatus = "disconnected" | "connecting" | "connected" | "rejected" | "wrong-chain";

export type DexConnector = {
  connect(): Promise<{ address: string; chainId: number; signingKey?: string }>;
  disconnect(): Promise<void> | void;
};

export type DexNote = {
  value: bigint;
  visibility: "private";
  commitment?: string;
  txHash?: string;
  finalized?: boolean;
};

export type DexHistoryItem = {
  kind: string;
  txHash?: string;
  phase?: WorkflowPhase;
};

export type DexWarning = {
  fact: string;
  visibility: "public" | "private";
  label: string;
  warning: string;
  acknowledged: boolean;
};

export type DexScreen = {
  path: string;
  title: string;
  walletStatus: WalletStatus;
  canSign: boolean;
  warnings: DexWarning[];
  nav: { path: string; visible: boolean }[];
  phase: WorkflowPhase;
  quote?: HazeSwapQuote;
  notes: DexNote[];
  layout: ReturnType<typeof layoutFor>;
};

export type DexAppConfig = {
  chainId: number;
  expectedChainId: number;
  pool: string;
  router: string;
  exit: string;
  poolVersion: string;
  applicationId: string;
  connector: DexConnector;
  wallet: WorkflowWallet;
  gatekeeper: {
    requestAuthorization(request: {
      applicationId: string;
      session: string;
      intent: unknown;
    }): Promise<{ intent: unknown; authorization: unknown }>;
  };
  quotes?: QuoteAdapter;
  policy: {
    snapshot(): Promise<{
      noteTreeRoot: string;
      applicationPolicyVersion: number;
      hazePolicyVersion: number;
      applicationMembershipRoot: string;
      hazeBlocklistRoot: string;
    }>;
  };
  finality: {
    wait(txHash: string): Promise<{ status: string; blockNumber: number; events: unknown[] }>;
  };
  clock: () => number;
  prover?: { cancel(): void; proveDevelopment(value: number): Promise<unknown> };
  noteEvents?: NoteEvent[];
};

const TITLES: Record<string, string> = {
  "/swap": "Public swap and shield",
  "/shield": "Direct shield",
  "/send": "Private send",
  "/withdraw": "Withdraw",
  "/history": "History",
  "/emergency-exit": "Emergency exit",
  "/migrate": "Version migration",
};

const PATH_KIND: Record<string, WorkflowKind> = {
  "/swap": "swap-and-shield",
  "/shield": "direct-shield",
  "/send": "private-send",
  "/withdraw": "withdraw",
  "/emergency-exit": "emergency-exit",
  "/migrate": "exit-and-reshield",
};

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => {
    switch (char) {
      case "&":
        return "&amp;";
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case '"':
        return "&quot;";
      default:
        return "&#39;";
    }
  });
}

function asError(error: unknown): { code?: string } {
  if (error instanceof SdkError) {
    return error;
  }
  if (error && typeof error === "object" && "code" in error) {
    return error as { code?: string };
  }
  return {};
}

function warningsFor(kind: WorkflowKind, acknowledged: boolean): DexWarning[] {
  const clientFacts =
    kind === "direct-shield"
      ? ["deposit-amount", "wallet-address", "gas"]
      : kind === "swap-and-shield"
        ? ["source-token-swap", "deposit-amount", "wallet-address", "gas"]
        : kind === "private-send"
          ? ["wallet-address", "gas"]
          : kind === "withdraw" || kind === "emergency-exit"
            ? ["withdrawal-amount", "wallet-address", "gas"]
            : ["withdrawal-amount", "deposit-amount", "wallet-address", "gas", "version-migration"];
  return clientFacts.map((fact) => {
    const copy = copyFor(fact);
    return { fact, ...copy, acknowledged };
  });
}

function noteFromVault(note: VaultNote): DexNote {
  return {
    value: note.value,
    visibility: "private",
    commitment: note.commitment,
    txHash: note.txHash,
    finalized: note.finalized,
  };
}

export function renderDexHtml(screen: DexScreen): string {
  const tokens = designSystem.tokens;
  const button = primitive("button");
  const status = primitive("status");
  const alert = primitive("alert");
  const warningMarkup = screen.warnings
    .map(
      (item) =>
        `<li data-visibility="${item.visibility}"><strong>${escapeHtml(item.label)}</strong> ${escapeHtml(item.warning)}</li>`,
    )
    .join("");
  const navMarkup = screen.nav
    .map((item) => `<a href="${escapeHtml(item.path)}">${escapeHtml(item.path.slice(1))}</a>`)
    .join("");
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Haze Privacy Pool DEX — ${escapeHtml(screen.title)}</title>
  <style>
    :root {
      --haze-bg: ${tokens.background};
      --haze-surface: ${tokens.surface};
      --haze-text: ${tokens.text};
      --haze-muted: ${tokens.muted};
      --haze-primary: ${tokens.primary};
    }
    body {
      margin: 0;
      font-family: "${designSystem.fontSans}", sans-serif;
      background: var(--haze-bg);
      color: var(--haze-text);
    }
    .skip { position: absolute; left: -999px; }
    .skip:focus { left: 8px; top: 8px; }
    button { font-family: inherit; }
  </style>
</head>
<body data-layout="${screen.layout.mode}">
  <a class="skip" href="#haze-main">Skip to content</a>
  <nav aria-label="Haze Privacy Pool DEX">${navMarkup}</nav>
  <main id="haze-main">
    <h1 id="haze-action-label">${escapeHtml(screen.title)}</h1>
    <p role="${status.role}" aria-live="${status.ariaLive}" id="${status.labelledBy}">
      ${escapeHtml(screen.walletStatus)} · ${escapeHtml(screen.phase)}
    </p>
    <ul role="${alert.role}" aria-live="${alert.ariaLive}" id="${alert.labelledBy}">${warningMarkup}</ul>
    <button type="button" role="${button.role}" tabindex="${button.tabIndex}" aria-labelledby="${button.labelledBy}" ${screen.canSign ? "" : "disabled"}>
      Sign and submit
    </button>
  </main>
</body>
</html>`;
}

export function createDexApp(config: DexAppConfig) {
  const store = createMemoryStore();
  let walletStatus: WalletStatus = "disconnected";
  let session: Session = { role: null };
  let path = "/shield";
  let account: VaultAccount | undefined;
  let vault: ReturnType<typeof createLocalVault> | undefined;
  let workflow: ReturnType<typeof createWorkflowClient> | undefined;
  let acknowledged: WorkflowKind | undefined;
  let localPhase: WorkflowPhase | undefined;
  let lastError: { code?: string } | undefined;
  let lastQuote: HazeSwapQuote | undefined;
  const localNotes: DexNote[] = [];
  const localHistory: DexHistoryItem[] = [];

  function currentKind(): WorkflowKind | undefined {
    return PATH_KIND[path];
  }

  function phase(): WorkflowPhase {
    return localPhase ?? workflow?.phase() ?? "idle";
  }

  function notes(): DexNote[] {
    const recovered = vault?.listNotes().map(noteFromVault) ?? [];
    return [...recovered, ...localNotes];
  }

  function history(): DexHistoryItem[] {
    const recovered =
      vault?.listNotes().map((note) => ({
        kind: "note",
        txHash: note.txHash,
        phase: "finalized" as const,
      })) ?? [];
    return [...recovered, ...localHistory];
  }

  function screen(): DexScreen {
    const kind = currentKind();
    const warnings = kind ? warningsFor(kind, acknowledged === kind) : [];
    return {
      path,
      title: TITLES[path] ?? "Haze",
      walletStatus,
      canSign: Boolean(kind && acknowledged === kind && walletStatus === "connected"),
      warnings,
      nav: navFor(APP, session),
      phase: phase(),
      quote: lastQuote,
      notes: notes(),
      layout: layoutFor(720),
    };
  }

  function bindWorkflow(user: string) {
    workflow = createWorkflowClient({
      chainId: config.chainId,
      pool: config.pool,
      router: config.router,
      exit: config.exit,
      poolVersion: config.poolVersion,
      applicationId: config.applicationId,
      user,
      session: "app-session",
      gatekeeper: config.gatekeeper as never,
      quotes: config.quotes,
      wallet: config.wallet,
      policy: config.policy,
      finality: config.finality,
      clock: config.clock,
      prover: config.prover,
      vault,
    });
  }

  return {
    walletStatus() {
      return walletStatus;
    },
    session() {
      return session;
    },
    phase,
    lastError() {
      return lastError;
    },
    notes,
    history,
    hazeAddress() {
      if (!account) {
        throw new SdkError("ENCODING_INVALID");
      }
      return encodeHazeAddress({
        chainId: config.chainId,
        applicationId: config.applicationId,
        poolVersion: config.poolVersion,
        notePublicKey: account.notePublicKey,
        x25519PublicKey: account.x25519PublicKey,
      });
    },
    navigate(next: string) {
      const decision = authorizeRoute(APP, session, next);
      if (decision.ok) {
        path = next;
      }
      return decision;
    },
    screen() {
      return {
        ...screen(),
        layout: layoutFor(1080),
      };
    },
    preview(kind: WorkflowKind) {
      if (walletStatus !== "connected") {
        throw new SdkError("REJECTED");
      }
      acknowledged = kind;
      const view = screen();
      return { ...view, canSign: true };
    },
    async connect() {
      walletStatus = "connecting";
      lastError = undefined;
      try {
        const connected = await config.connector.connect();
        if (connected.chainId !== config.expectedChainId) {
          walletStatus = "wrong-chain";
          session = { role: null };
          lastError = { code: "CHAIN_MISMATCH" };
          return;
        }
        account = deriveVaultAccount({
          chainId: config.chainId,
          pool: config.pool,
          applicationId: config.applicationId,
          poolVersion: config.poolVersion,
          wallet: connected.address,
          signingKey: connected.signingKey ?? `0x${"00".repeat(32)}`,
        });
        vault = createLocalVault({
          store,
          account,
          binding: {
            chainId: config.chainId,
            pool: config.pool,
            applicationId: config.applicationId,
            poolVersion: config.poolVersion,
          },
        });
        bindWorkflow(connected.address);
        session = { role: "pool-user", applicationId: config.applicationId };
        walletStatus = "connected";
        localPhase = undefined;
      } catch (error) {
        const parsed = asError(error);
        walletStatus = parsed.code === "REJECTED" ? "rejected" : "disconnected";
        session = { role: null };
        lastError = parsed;
      }
    },
    disconnect() {
      void config.connector.disconnect();
      walletStatus = "disconnected";
      session = { role: null };
      workflow = undefined;
      vault = undefined;
      account = undefined;
      acknowledged = undefined;
      localPhase = undefined;
    },
    async quote(request: { tokenIn: string; amountIn: string; minUsdcOut: string; deadline: number }) {
      if (!config.quotes) {
        throw new SdkError("UNAVAILABLE");
      }
      localPhase = "quoting";
      try {
        lastQuote = await config.quotes.quote(request);
        localPhase = undefined;
        return lastQuote;
      } catch (error) {
        localPhase = "failed";
        lastError = asError(error);
        throw error;
      }
    },
    async run(kind: WorkflowKind, input: WorkflowInput): Promise<WorkflowResult> {
      if (walletStatus !== "connected" || !workflow) {
        localPhase = "failed";
        const error = new SdkError("REJECTED");
        lastError = error;
        throw error;
      }
      if (acknowledged !== kind) {
        localPhase = "failed";
        const error = new SdkError("REJECTED");
        lastError = error;
        throw error;
      }
      try {
        const result = await workflow.run(kind, input);
        localPhase = result.phase;
        if (result.phase === "finalized") {
          localHistory.push({ kind, txHash: result.txHash, phase: result.phase });
          if (kind === "direct-shield" || kind === "swap-and-shield") {
            localNotes.push({
              value: BigInt(input.value ?? 0),
              visibility: "private",
              txHash: result.txHash,
              finalized: true,
            });
          }
        }
        return result;
      } catch (error) {
        localPhase = "failed";
        lastError = asError(error);
        throw error;
      }
    },
    cancel() {
      workflow?.cancel();
      localPhase = "cancelled";
    },
    async recover() {
      if (!vault) {
        throw new SdkError("RECOVERY_UNSUPPORTED");
      }
      await vault.recover(config.noteEvents ?? []);
    },
    async wipe() {
      if (vault) {
        await vault.clearLocalState();
      }
      localNotes.length = 0;
      localHistory.length = 0;
    },
    renderHtml(width = 1080) {
      const view = { ...screen(), layout: layoutFor(width) };
      return renderDexHtml(view);
    },
  };
}
