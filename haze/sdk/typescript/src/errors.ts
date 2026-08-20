/** Protocol encoding and version errors. */
export const PROTOCOL_ERROR_CODES = [
  "ENCODING_INVALID",
  "FIELD_OUT_OF_RANGE",
  "VERSION_UNSUPPORTED",
  "DOMAIN_MISMATCH",
  "CHAIN_MISMATCH",
  "APPLICATION_MISMATCH",
  "POOL_VERSION_MISMATCH",
  "CIPHERTEXT_INVALID",
  "COMMITMENT_MISMATCH",
  "RECOVERY_UNSUPPORTED",
] as const;

/** On-chain revert strings used by Haze contracts. */
export const CONTRACT_ERROR_CODES = [
  "AUTH_WINDOW",
  "PAUSED",
  "UNAUTHORIZED",
  "REENTRANCY",
  "TIMELOCK",
  "POLICY_INVALID",
  "NULLIFIER_USED",
  "ROOT_UNKNOWN",
  "STATUS_INVALID",
  "KEYS_MISSING",
] as const;

/** Gatekeeper machine-readable denials. */
export const GATEKEEPER_ERROR_CODES = [
  "USER_INELIGIBLE",
  "POLICY_STALE",
  "TOKEN_NOT_ALLOWED",
  "LIMIT_EXCEEDED",
  "AUTHORIZATION_EXPIRED",
] as const;

/** Provider fail-closed codes reused by quote and transport adapters. */
export const PROVIDER_ERROR_CODES = ["UNAVAILABLE", "REJECTED", "QUOTE_STALE", "CHAIN_MISMATCH"] as const;

export type ProtocolErrorCode = (typeof PROTOCOL_ERROR_CODES)[number];
export type ContractErrorCode = (typeof CONTRACT_ERROR_CODES)[number];
export type GatekeeperErrorCode = (typeof GATEKEEPER_ERROR_CODES)[number];
export type ProviderErrorCode = (typeof PROVIDER_ERROR_CODES)[number];
export type SdkErrorCode =
  | ProtocolErrorCode
  | ContractErrorCode
  | GatekeeperErrorCode
  | ProviderErrorCode;

const ALL_CODES = new Set<string>([
  ...PROTOCOL_ERROR_CODES,
  ...CONTRACT_ERROR_CODES,
  ...GATEKEEPER_ERROR_CODES,
  ...PROVIDER_ERROR_CODES,
]);

/** Typed SDK failure with a stable machine-readable code. */
export class SdkError extends Error {
  readonly code: SdkErrorCode;
  constructor(code: SdkErrorCode) {
    super(code);
    this.code = code;
    this.name = "SdkError";
  }
}

function asCode(value: string): SdkErrorCode | undefined {
  return ALL_CODES.has(value) ? (value as SdkErrorCode) : undefined;
}

/** Extract a known contract revert code from a provider message. */
export function parseContractError(message: string): SdkErrorCode {
  for (const code of [...CONTRACT_ERROR_CODES, ...PROTOCOL_ERROR_CODES]) {
    if (message.includes(code)) {
      return code;
    }
  }
  throw new SdkError("ENCODING_INVALID");
}

/** Extract a typed gatekeeper denial from a JSON body. */
export function parseGatekeeperError(body: { code?: string }): GatekeeperErrorCode {
  const code = asCode(body.code ?? "");
  if (code && (GATEKEEPER_ERROR_CODES as readonly string[]).includes(code)) {
    return code as GatekeeperErrorCode;
  }
  throw new SdkError("ENCODING_INVALID");
}
