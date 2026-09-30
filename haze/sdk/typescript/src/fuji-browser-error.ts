export type BrowserErrorCategory = "proof" | "submit" | "policy" | "swap" | "validation" | "wallet";

export interface ClassifiedBrowserError {
  category: BrowserErrorCategory;
  message: string;
}

export function classifyBrowserError(
  error: unknown,
  phase?: string,
): ClassifiedBrowserError {
  const code = error instanceof Error ? error.message : String(error ?? "");
  const normalized = code.toLowerCase();

  // Explicit validation / user errors
  if (code === "RECIPIENT_ADDRESS_REQUIRED") {
    return { category: "validation", message: "Enter a haze1 recipient" };
  }
  if (code === "DEPOSIT_NOTE_REQUIRED") {
    return { category: "validation", message: "Shield USDC first" };
  }
  if (code === "AUDIT_PUBLIC_KEY_MISSING") {
    return { category: "validation", message: "Audit public key missing or invalid" };
  }
  if (code === "FUJI_REQUIRED" || code === "WALLET_ON_WRONG_CHAIN" || code === "WALLET_UNAVAILABLE") {
    return { category: "wallet", message: "Switch to Avalanche Fuji in your wallet" };
  }
  if (code === "SWAP_VENUE_UNAVAILABLE" || normalized.includes("swap_venue_unavailable") || normalized.includes("swap venue")) {
    return { category: "swap", message: "Swap venue unavailable — try again later" };
  }

  // Policy / compliance reverts (preflight or on-chain)
  if (
    normalized.includes("policy_invalid") ||
    normalized.includes("membership") ||
    normalized.includes("policy_authority") ||
    normalized.includes("compliance")
  ) {
    return { category: "policy", message: "Policy validation failed on-chain (KYC membership required)" };
  }

  // Phase-specific handling
  if (phase === "submitting") {
    if (code === "FUJI_EVENT_NOT_CONFIRMED") {
      return { category: "submit", message: "Transaction submission failed: on-chain event not confirmed" };
    }
    if (code === "APPROVAL_NOT_SUCCESSFUL") {
      return { category: "submit", message: "Token approval transaction was not successful" };
    }
    return { category: "submit", message: "Transaction submission failed — retry" };
  }

  if (phase === "proving") {
    return { category: "proof", message: "Proof generation failed — retry" };
  }

  // Fallbacks
  if (normalized.includes("proof") || normalized.includes("circuit") || normalized.includes("witness") || normalized.includes("wasm") || normalized.includes("zkey")) {
    return { category: "proof", message: "Proof generation failed — retry" };
  }

  return { category: "submit", message: "Transaction failed — retry" };
}
