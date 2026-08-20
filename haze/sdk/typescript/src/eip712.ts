import { addressWord, bytes32Word, encodeWords, keccakHex, toHex, uintWord } from "./abi.ts";
import { SdkError } from "./errors.ts";
import { keccak256 } from "./keccak.ts";
import { POOL_DOMAIN_NAME, POOL_DOMAIN_VERSION } from "./pool.ts";

export { POOL_DOMAIN_NAME, POOL_DOMAIN_VERSION };

/** Inclusive maximum for EIP-712 `uint48` fields. */
export const UINT48_MAX = (1n << 48n) - 1n;

/** EIP-712 domain type string. */
export const EIP712_DOMAIN_TYPE =
  "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)" as const;

/** Frozen `HazeIntent` type string. */
export const INTENT_TYPE =
  "HazeIntent(bytes32 applicationId,address user,address pool,bytes32 poolVersion,uint8 action,uint256 noteTreeRoot,uint64 applicationPolicyVersion,uint64 hazePolicyVersion,uint256 applicationMembershipRoot,uint256 hazeBlocklistRoot,uint256 inputNullifier0,uint256 inputNullifier1,uint256 outputCommitment0,uint256 outputCommitment1,uint64 publicAmount,address publicRecipient,bytes32 recipientCiphertextHash0,bytes32 recipientCiphertextHash1,uint256 auditDataCommitment,bytes32 auditCiphertextHash,address tokenIn,uint256 amountIn,uint64 minUsdcOut,bytes32 routeHash,uint48 deadline)" as const;

/** Frozen `ApplicationAuthorization` type string. */
export const AUTH_TYPE =
  "ApplicationAuthorization(bytes32 applicationId,address user,address pool,bytes32 poolVersion,uint8 action,bytes32 intentHash,uint64 applicationPolicyVersion,uint64 hazePolicyVersion,uint256 auditDataCommitment,bytes32 auditCiphertextHash,bytes32 nonce,uint48 validAfter,uint48 validUntil)" as const;

/** Frozen shielded-account derivation type string. */
export const KEY_TYPE = "HazeKeyDerivation(address wallet,bytes32 applicationId,bytes32 poolVersion)" as const;

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const ZERO_BYTES32 = `0x${"00".repeat(32)}`;

/** Public fields hashed into a Haze intent. */
export type HazeIntentFields = {
  applicationId: string;
  user: string;
  pool: string;
  poolVersion: string;
  action: number;
  noteTreeRoot: string;
  applicationPolicyVersion: number;
  hazePolicyVersion: number;
  applicationMembershipRoot: string;
  hazeBlocklistRoot: string;
  inputNullifier0: string;
  inputNullifier1: string;
  outputCommitment0: string;
  outputCommitment1: string;
  publicAmount: number;
  publicRecipient: string;
  recipientCiphertextHash0: string;
  recipientCiphertextHash1: string;
  auditDataCommitment: string;
  auditCiphertextHash: string;
  tokenIn: string;
  amountIn: string;
  minUsdcOut: number;
  routeHash: string;
  deadline: number;
};

/** Gatekeeper authorization payload. */
export type ApplicationAuthorizationFields = {
  applicationId: string;
  user: string;
  pool: string;
  poolVersion: string;
  action: number;
  intentHash: string;
  applicationPolicyVersion: number;
  hazePolicyVersion: number;
  auditDataCommitment: string;
  auditCiphertextHash: string;
  nonce: string;
  validAfter: number;
  validUntil: number;
};

function requireUint48(value: number): void {
  if (value < 0 || BigInt(value) > UINT48_MAX) {
    throw new SdkError("FIELD_OUT_OF_RANGE");
  }
}

function requireAction(action: number): void {
  if (action < 1 || action > 5) {
    throw new SdkError("ENCODING_INVALID");
  }
}

function eqHex(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

function validateIntent(fields: HazeIntentFields): void {
  requireAction(fields.action);
  requireUint48(fields.deadline);
  if (fields.action !== 4) {
    const swapZero =
      eqHex(fields.tokenIn, ZERO_ADDRESS) &&
      eqHex(fields.amountIn, ZERO_BYTES32) &&
      fields.minUsdcOut === 0 &&
      eqHex(fields.routeHash, ZERO_BYTES32) &&
      fields.deadline === 0;
    if (!swapZero) {
      throw new SdkError("ENCODING_INVALID");
    }
  }
  if (fields.action === 1) {
    const depositZero =
      eqHex(fields.noteTreeRoot, ZERO_BYTES32) &&
      eqHex(fields.inputNullifier0, ZERO_BYTES32) &&
      eqHex(fields.inputNullifier1, ZERO_BYTES32);
    if (!depositZero) {
      throw new SdkError("ENCODING_INVALID");
    }
  }
}

function validateAuthorization(fields: ApplicationAuthorizationFields): void {
  requireAction(fields.action);
  requireUint48(fields.validAfter);
  requireUint48(fields.validUntil);
}

/** Type hashes matching the committed protocol vectors. */
export function eip712TypeHashes() {
  return {
    domain: keccakHex(Buffer.from(EIP712_DOMAIN_TYPE)),
    intent: keccakHex(Buffer.from(INTENT_TYPE)),
    authorization: keccakHex(Buffer.from(AUTH_TYPE)),
    keyDerivation: keccakHex(Buffer.from(KEY_TYPE)),
  };
}

/** Pool authorization domain separator. */
export function poolDomainSeparator(fields: {
  chainId: number;
  verifyingContract: string;
  name?: string;
  version?: string;
}): string {
  const name = fields.name ?? POOL_DOMAIN_NAME;
  const version = fields.version ?? POOL_DOMAIN_VERSION;
  if (name !== POOL_DOMAIN_NAME || version !== POOL_DOMAIN_VERSION) {
    throw new SdkError("DOMAIN_MISMATCH");
  }
  return keccakHex(
    encodeWords([
      Buffer.from(keccak256(Buffer.from(EIP712_DOMAIN_TYPE))),
      Buffer.from(keccak256(Buffer.from(name))),
      Buffer.from(keccak256(Buffer.from(version))),
      uintWord(fields.chainId),
      addressWord(fields.verifyingContract),
    ]),
  );
}

function typedDataDigest(separator: string, structHash: string): string {
  return keccakHex(
    Buffer.concat([Buffer.from([0x19, 0x01]), Buffer.from(separator.slice(2), "hex"), Buffer.from(structHash.slice(2), "hex")]),
  );
}

/** EIP-712 struct hash for `HazeIntent`. */
export function intentStructHash(fields: HazeIntentFields): string {
  validateIntent(fields);
  const types = eip712TypeHashes();
  return keccakHex(
    encodeWords([
      Buffer.from(types.intent.slice(2), "hex"),
      bytes32Word(fields.applicationId),
      addressWord(fields.user),
      addressWord(fields.pool),
      bytes32Word(fields.poolVersion),
      uintWord(fields.action),
      bytes32Word(fields.noteTreeRoot),
      uintWord(fields.applicationPolicyVersion),
      uintWord(fields.hazePolicyVersion),
      bytes32Word(fields.applicationMembershipRoot),
      bytes32Word(fields.hazeBlocklistRoot),
      bytes32Word(fields.inputNullifier0),
      bytes32Word(fields.inputNullifier1),
      bytes32Word(fields.outputCommitment0),
      bytes32Word(fields.outputCommitment1),
      uintWord(fields.publicAmount),
      addressWord(fields.publicRecipient),
      bytes32Word(fields.recipientCiphertextHash0),
      bytes32Word(fields.recipientCiphertextHash1),
      bytes32Word(fields.auditDataCommitment),
      bytes32Word(fields.auditCiphertextHash),
      addressWord(fields.tokenIn),
      bytes32Word(fields.amountIn),
      uintWord(fields.minUsdcOut),
      bytes32Word(fields.routeHash),
      uintWord(fields.deadline),
    ]),
  );
}

/** Final EIP-712 digest for a pool intent. */
export function intentDigest(fields: HazeIntentFields, chainId: number): string {
  return typedDataDigest(
    poolDomainSeparator({ chainId, verifyingContract: fields.pool }),
    intentStructHash(fields),
  );
}

/** EIP-712 struct hash for `ApplicationAuthorization`. */
export function authorizationStructHash(fields: ApplicationAuthorizationFields): string {
  validateAuthorization(fields);
  const types = eip712TypeHashes();
  return keccakHex(
    encodeWords([
      Buffer.from(types.authorization.slice(2), "hex"),
      bytes32Word(fields.applicationId),
      addressWord(fields.user),
      addressWord(fields.pool),
      bytes32Word(fields.poolVersion),
      uintWord(fields.action),
      bytes32Word(fields.intentHash),
      uintWord(fields.applicationPolicyVersion),
      uintWord(fields.hazePolicyVersion),
      bytes32Word(fields.auditDataCommitment),
      bytes32Word(fields.auditCiphertextHash),
      bytes32Word(fields.nonce),
      uintWord(fields.validAfter),
      uintWord(fields.validUntil),
    ]),
  );
}

/** Final EIP-712 digest for a gatekeeper authorization. */
export function authorizationDigest(fields: ApplicationAuthorizationFields, chainId: number): string {
  return typedDataDigest(
    poolDomainSeparator({ chainId, verifyingContract: fields.pool }),
    authorizationStructHash(fields),
  );
}

export function typedDigestHex(separator: string, structHash: string): string {
  return typedDataDigest(separator, structHash);
}

export function toHexDigest(bytes: Uint8Array): string {
  return toHex(bytes);
}
