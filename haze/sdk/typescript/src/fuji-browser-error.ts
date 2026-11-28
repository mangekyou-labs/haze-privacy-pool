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

  // Relayer / infrastructure errors (must be handled before generic policy / membership match)
  if (
    code === "MEMBERSHIP_RELAYER_UNAVAILABLE" ||
    normalized.includes("membership_relayer_unavailable") ||
    normalized.includes("relayer unavailable")
  ) {
    return { category: "policy", message: "Fuji membership relayer unavailable — check relayer service" };
  }

  if (
    code === "GATEKEEPER_AUTHORIZATION_FAILED" ||
    normalized.includes("gatekeeper_authorization_failed") ||
    normalized.includes("unauthorized")
  ) {
    return { category: "policy", message: "Gatekeeper authorization failed — retry" };
  }

  if (normalized.includes("auth_window") || normalized.includes("authorization expired")) {
    return { category: "policy", message: "Authorization window expired — retry" };
  }

  if (normalized.includes("nonce_used")) {
    return { category: "submit", message: "Authorization nonce already used — retry" };
  }

  if (normalized.includes("paused")) {
    return { category: "submit", message: "Pool contract is currently paused" };
  }

  // Swap-specific errors
  if (code === "INSUFFICIENT_PILOT" || normalized.includes("insufficient_pilot") || normalized.includes("insufficient pilot")) {
    return { category: "swap", message: "Insufficient Fuji Pilot tokens in wallet" };
  }
  if (code === "TOKEN_NOT_ALLOWED" || normalized.includes("token_not_allowed")) {
    return { category: "swap", message: "Token not allowed for Swap and Shield" };
  }
  if (code === "SWAP_VENUE_UNAVAILABLE" || normalized.includes("swap_venue_unavailable") || normalized.includes("swap venue")) {
    return { category: "swap", message: "Swap venue unavailable — try again later" };
  }

  // Explicit validation / user errors
  if (code === "RECIPIENT_ADDRESS_REQUIRED" || normalized.includes("recipient_address_required")) {
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
  if (
    normalized.includes("user rejected") ||
    normalized.includes("action rejected") ||
    normalized.includes("rejected") ||
    code === "ACTION_REJECTED"
  ) {
    return { category: "wallet", message: "Transaction was rejected in wallet" };
  }
  if (code === "POLICY_AUTHORITY_REQUIRED" || normalized.includes("policy_authority_required")) {
    return { category: "policy", message: "Policy authority wallet required" };
  }

  // Policy / compliance reverts (preflight or on-chain)
  if (
    normalized.includes("policy_invalid") ||
    normalized.includes("kyc_membership_required") ||
    normalized.includes("kyc") ||
    normalized.includes("compliance")
  ) {
    return { category: "policy", message: "Policy validation failed on-chain (KYC membership required)" };
  }

  // Phase-specific handling
  if (phase === "submitting" || phase === "approving" || phase === "confirming") {
    if (code === "FUJI_EVENT_NOT_CONFIRMED") {
      return { category: "submit", message: "Transaction submission failed: on-chain event not confirmed" };
    }
    if (code === "APPROVAL_NOT_SUCCESSFUL") {
      return { category: "submit", message: "Token approval transaction was not successful" };
    }
    return { category: "submit", message: "Transaction submission failed — retry" };
  }

  if (phase === "authorizing") {
    return { category: "policy", message: "Authorization failed — retry" };
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
