export { HAZE_API_VERSION, HAZE_CHAIN_FAMILY, HAZE_PRODUCT_ID } from "./identity.ts";
export {
  CONTRACT_ERROR_CODES,
  GATEKEEPER_ERROR_CODES,
  PROTOCOL_ERROR_CODES,
  PROVIDER_ERROR_CODES,
  SdkError,
  parseContractError,
  parseGatekeeperError,
} from "./errors.ts";
export type { SdkErrorCode } from "./errors.ts";
export { FUJI_COMPATIBILITY, checkCompatibility } from "./versions.ts";
export type { CompatibilityView } from "./versions.ts";
export {
  AUTH_TYPE,
  EIP712_DOMAIN_TYPE,
  INTENT_TYPE,
  KEY_TYPE,
  UINT48_MAX,
  authorizationDigest,
  authorizationStructHash,
  eip712TypeHashes,
  intentDigest,
  intentStructHash,
  poolDomainSeparator,
} from "./eip712.ts";
export type { ApplicationAuthorizationFields, HazeIntentFields } from "./eip712.ts";
export { hashManifest, parseManifest } from "./manifest.ts";
export type { ApplicationManifest } from "./manifest.ts";
export { assertBoundChain, createMemoryTransport } from "./transport.ts";
export type { EvmTransport } from "./transport.ts";
export {
  EMERGENCY_SELECTORS,
  POOL_SELECTORS,
  ROUTER_SELECTORS,
  bindHazePool,
  functionSelector,
} from "./bindings.ts";
export { createStaticQuoteAdapter, createUnavailableQuoteAdapter } from "./quote.ts";
export type { HazeSwapQuote, QuoteAdapter } from "./quote.ts";
export { createGatekeeperClient } from "./gatekeeper.ts";
export {
  decodeHazeAddress,
  encodeHazeAddress,
  encodeHazeAddressBytes,
  requireAddressBinding,
} from "./address.ts";
export type { HazeAddress } from "./address.ts";
export { encodeEnvelope, envelopeHash, parseEnvelope } from "./envelope.ts";
export type { Envelope, EnvelopePurpose } from "./envelope.ts";
export {
  deriveX25519KeyPair,
  openRecipientNote,
  parseRecipientPlaintext,
  recipientAad,
  sealRecipientNote,
} from "./hpke.ts";
export type { RecipientPlaintext } from "./hpke.ts";
export { encryptionKeyHash, noteCommitment, notePublicKey, nullifier } from "./note.ts";
export {
  applicationMember,
  globalBlockedAddress,
  globalBlockedNote,
  requireLivePolicy,
} from "./policy.ts";
export {
  APP_TREE,
  BLOCKLIST_LOWER_SENTINEL,
  BLOCK_TREE,
  TREE_DEPTH,
  blocklistUpperSentinel,
  parentNode,
  rootFromPath,
} from "./merkle.ts";
export { createLocalVault, createMemoryStore, deriveVaultAccount } from "./vault.ts";
export type { NoteEvent, VaultAccount, VaultBinding, VaultNote } from "./vault.ts";

export type {
  ChainRpc,
  DexQuoteSource,
  IdentityProvider,
  KeyManagement,
  ObjectStore,
  ProviderErrorCode,
  SwapQuote,
  SwapQuoteRequest,
} from "./providers.ts";
export { UnavailableDex } from "./providers.ts";
export {
  ProverError,
  SPEND_PUBLIC_CAMEL,
  checkSpendPublicInputs,
  createProverSession,
  deriveShieldedAccount,
  deriveShieldedAccountFromSignature,
  developmentProofDigest,
  handleProverWorkerMessage,
  hashArtifactSet,
  keyDerivationDigest,
  spendPublicInputs,
  verifyDevelopmentSpend,
  verifyProductionSpend,
} from "./prover.ts";
export type {
  ArtifactSet,
  DevelopmentProof,
  ProverErrorCode,
  ShieldedAccount,
  ShieldedAccountRequest,
  ShieldedAccountSignatureRequest,
} from "./prover.ts";
export {
  ApplicationStatus,
  PolicyStatus,
  ReleaseStatus,
  policyIsLive,
  releaseIsExitCapable,
  releaseIsLive,
} from "./registry.ts";
export {
  POOL_DOMAIN_NAME,
  POOL_DOMAIN_VERSION,
  PoolAction,
  isDirectPoolAction,
  isNormalPoolAction,
} from "./pool.ts";
export { SWAP_AND_SHIELD_ACTION, encodeRoute, routeHash, swapRoute } from "./router.ts";
export type { SwapRoute } from "./router.ts";
export {
  EMERGENCY_EXIT_ACTION,
  EMERGENCY_EXIT_COOLDOWN,
  EMERGENCY_EXIT_REQUEST_TYPE,
  EMERGENCY_PUBLIC_CAMEL,
  emergencyExitRequestId,
} from "./emergency.ts";
export type { EmergencyExitRequest } from "./emergency.ts";
export {
  createArtifactCache,
  createBrowserProver,
  generateBrowserSecrets,
  loadFujiProvingArtifacts,
  selectCircuitArtifact,
} from "./browser-prover.ts";
export {
  browserAuditAad,
  decodeBrowserEnvelope,
  encodeBrowserEnvelope,
  openBrowserHpke,
  sealBrowserHpke,
  sealBrowserHpkeToPublicKey,
  deriveBrowserX25519PublicKey,
} from "./browser-crypto.ts";
export type { BrowserEnvelope } from "./browser-crypto.ts";
export { encodeBrowserAuditRecord } from "./browser-audit.ts";
export type { BrowserAuditFacts } from "./browser-audit.ts";
export {
  createBrowserOperationVault,
  createIndexedDbOperationStore,
  createMemoryIndexedDb,
  deriveBrowserVaultKey,
  isConfirmedSpendableInput,
} from "./browser-operation-vault.ts";
export type {
  BrowserOperation,
  BrowserOperationState,
  BrowserOperationStore,
  BrowserVaultBinding,
} from "./browser-operation-vault.ts";
export {
  PRIVATE_TRANSACTION_TOPIC,
  broadcastFujiTransaction,
  decodePrivateTransaction,
  reconcileFujiOperation,
  recoverFujiOperation,
  recoverSpendableNotesFromLogs,
} from "./fuji-reconciliation.ts";
export type { FujiLog, FujiReceipt, FujiRpc } from "./fuji-reconciliation.ts";
export { DEFAULT_HAZE_AUDIT_PUBLIC_KEY, DEFAULT_HAZE_DISCLOSURE_ORIGIN, planFujiWithdrawalDisclosure, requestFujiDisclosure } from "./render-disclosure.ts";
export { ensureFujiMembershipRoot, executeFujiBrowserTransaction, updateFujiMembershipRoot } from "./browser-fuji-flow.ts";
export { classifyBrowserError } from "./fuji-browser-error.ts";
export type { BrowserErrorCategory, ClassifiedBrowserError } from "./fuji-browser-error.ts";
export { createFujiMembershipStore, createMemoryMembershipStore, unionMembershipLeaves } from "./fuji-membership-store.ts";
export type { FujiMembershipStore, MembershipLeaf } from "./fuji-membership-store.ts";
export { buildSealedBrowserTransferWitness, buildSealedBrowserWitness } from "./browser-witness-flow.ts";
export {
  encodeBrowserFujiSpend,
  encodeBrowserGroth16Proof,
  encodeBrowserSwapAndShield,
  encodeErc20Approve,
  encodeMembershipRootUpdate,
  planBrowserFujiSpend,
  swapRouteHash,
} from "./browser-fuji-contracts.ts";
export type {
  ArtifactCache,
  BrowserProverConfig,
  BrowserSecrets,
  BrowserWorker,
  CircuitArtifactManifest,
  FujiProvingArtifact,
  FujiProvingArtifactManifest,
} from "./browser-prover.ts";
export { createWorkflowClient } from "./workflow.ts";
export type {
  WorkflowInput,
  WorkflowKind,
  WorkflowPhase,
  WorkflowResult,
  WorkflowWallet,
} from "./workflow.ts";
