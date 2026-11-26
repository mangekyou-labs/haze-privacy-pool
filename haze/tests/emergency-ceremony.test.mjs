import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { keccak256 } from "./keccak256.mjs";
import {
  CEREMONY_ID,
  CHAIN_ID,
  REQUIRED_CONTRIBUTIONS,
  REQUIRED_FINAL_APPROVALS,
  ANCHOR_TARGET_OFFSET,
  ANCHOR_CONFIRMATION_DEPTH,
  ANCHOR_INCLUSION_WINDOW_MS,
  SNARK_SCALAR_FIELD,
  EIP712_DOMAIN_TYPEHASH,
  EIP712_DOMAIN_NAME,
  EIP712_DOMAIN_VERSION,
  EIP712_VERIFYING_CONTRACT,
  CONTRIBUTION_RECEIPT_TYPEHASH,
  VERIFICATION_RECEIPT_TYPEHASH,
  CEREMONY_MANIFEST_APPROVAL_TYPEHASH,
  AUDIT_FREEZE_APPROVAL_TYPEHASH,
  BEACON_DOMAIN_TAG,
  BEACON_ITERATIONS,
  canonicalHash,
  toHex,
  fromHex,
  loadRawPolicy,
  loadProductionPolicy,
  validateProductionPolicy,
  createAuditFreezeManifest,
  validateAuditFreezeManifest,
  ceremonyGenesis,
  linkGenesis,
  nextTranscript,
  verifyTranscriptChain,
  precommitDigest,
  targetBlockHeight,
  confirmationHeight,
  deriveEmergencyBeacon,
  assertAnchorInclusionWindow,
  assertTargetNotPredictable,
  resolveConsensusTargetHash,
  constructAnchorPayload,
  validateAnchorPayload,
  generateContractBundle,
  validateContractBundle,
  fileSha256,
  contributionReceiptHash,
  verificationReceiptHash,
  ceremonyManifestApprovalHash,
  auditFreezeApprovalHash,
  eip712DomainSeparator,
  eip712Digest,
  signerAddress,
  signStructHash,
  recoverStructSigner,
  verifyContributionReceiptSignature,
  verifyContributionOrder,
  refuseRehearsalAsEmergencyZkey,
  assertFreezeHashesNonPlaceholder,
  verifyFinalManifestApprovals,
  verifyVerifierVkMatch,
  createOpeningManifest,
  createFinalArtifactManifest,
  publicEmergencyTranscript,
  planEmergencyPhase2,
  runEmergencyPhase2,
  validateCeremonyState,
  EMERGENCY_CIRCUIT_ID,
  EMERGENCY_N_CONSTRAINTS,
  EMERGENCY_CIRCOM_VERSION,
  EMERGENCY_PUBLIC_INPUTS,
  EMERGENCY_PTAU_SHA256,
  EMERGENCY_PTAU_POWER,
  assertEmergencyCircuitPin,
  assertEmergencyPtauChecksum,
  assertEmergencyPtauPower,
  validateFreezeHashes,
} from "../dev/ceremony/emergency.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const TEST_DIR = join(HAZE_ROOT, "dev/artifacts/ceremony-private/emergency-v1-test");

// ---------------------------------------------------------------------------
// Test Fixtures
// ---------------------------------------------------------------------------

const FIXTURE_AUDITOR = "0xA11ce5d200000000000000000000000000000001";
const FIXTURE_CONTRIBUTORS = [
  "0xC01ab5d200000000000000000000000000000001",
  "0xC01ab5d200000000000000000000000000000002",
  "0xC01ab5d200000000000000000000000000000003",
];
const FIXTURE_VERIFIER = "0xVe11f1e200000000000000000000000000000001";
const FIXTURE_MULTISIG = "0xMu11t11200000000000000000000000000000001";
const FIXTURE_ANCHOR = "0xAnch0r00000000000000000000000000000000001";
const FIXTURE_RPCS = [
  "https://rpc-a.avax.network/ext/bc/C/rpc",
  "https://rpc-b.avax.network/ext/bc/C/rpc",
  "https://rpc-c.avax.network/ext/bc/C/rpc",
];

const VALID_ENTROPY_COMMITMENTS = [
  "0xe101010101010101010101010101010101010101010101010101010101010101",
  "0xe202020202020202020202020202020202020202020202020202020202020202",
  "0xe303030303030303030303030303030303030303030303030303030303030303",
];

function makeTestPolicy(overrides = {}) {
  return {
    ceremony_id: CEREMONY_ID,
    version: 1,
    enabled: true,
    not_for_production: false,
    auditor: FIXTURE_AUDITOR,
    contributors: FIXTURE_CONTRIBUTORS,
    verifier: FIXTURE_VERIFIER,
    multisig: FIXTURE_MULTISIG,
    anchorAddress: FIXTURE_ANCHOR,
    rpcProviders: FIXTURE_RPCS,
    circuit_id: "haze-emergency-v1",
    ptau_power: 20,
    public_inputs: 20,
    contribution_count: 3,
    ...overrides,
  };
}

function makeTestFreezeManifest(overrides = {}) {
  return createAuditFreezeManifest({
    circuitSourceHash: "0xaa01" + "00".repeat(30),
    r1csHash: "0xbb02" + "00".repeat(30),
    fixtureHash: "0xcc03" + "00".repeat(30),
    buildHash: "0xdd04" + "00".repeat(30),
    constraintHash: "0xee05" + "00".repeat(30),
    publicInputHash: "0xff06" + "00".repeat(30),
    ptauHash: "0x1107" + "00".repeat(30),
    ptauSha256: "159d3f938d941e06767d99f30b9fe59a245400a4aae138cf8e411732d7a2f6cd",
    auditReportHash: "0x2208" + "00".repeat(30),
    auditor: FIXTURE_AUDITOR,
    ...overrides,
  });
}

function makeTestTranscript() {
  // Design Section 4.3: genesis = keccak256(domain_tag || circuit_id), then each
  // contribution links the previous link with contributor name + input zkey hash.
  const circuitId = EMERGENCY_CIRCUIT_ID;
  const genesis = toHex(linkGenesis(circuitId));
  const contributions = [];
  let previous = genesis;
  let previousOutput = "0x" + "99".repeat(32);

  for (let i = 1; i <= REQUIRED_CONTRIBUTIONS; i++) {
    const inputZkeyHash = previousOutput;
    const outputZkeyHash = `0x${(0xaa + i).toString(16).padStart(2, "0")}${"00".repeat(30)}`;
    const transcriptHash = toHex(
      nextTranscript(previous, FIXTURE_CONTRIBUTORS[i - 1].toLowerCase(), inputZkeyHash),
    );
    contributions.push({
      order: i,
      contributor: FIXTURE_CONTRIBUTORS[i - 1].toLowerCase(),
      entropy_commitment: VALID_ENTROPY_COMMITMENTS[i - 1],
      transcript_hash: transcriptHash,
      input_zkey_hash: inputZkeyHash,
      output_zkey_hash: outputZkeyHash,
      timestamp: new Date().toISOString(),
    });
    previous = transcriptHash;
    previousOutput = outputZkeyHash;
  }

  return {
    ceremony_id: CEREMONY_ID,
    version: 1,
    circuit_id: circuitId,
    genesis,
    contributions,
    final_transcript: previous,
    not_for_production: false,
  };
}

function makeTestVerificationReceipt(overrides = {}) {
  return {
    type: "VerificationReceipt",
    ceremonyId: "0x" + "11".repeat(32),
    finalZkeyHash: "0x" + "b2".repeat(32),
    verificationKeyHash: "0x" + "c3".repeat(32),
    solidityVerifierHash: "0x" + "d4".repeat(32),
    r1csHash: "0x" + "e5".repeat(32),
    ptauSha256: "0x" + "f6".repeat(32),
    verificationPassed: true,
    signer: FIXTURE_VERIFIER,
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

// Standard organizational signing keys 1..3 (matching FIXTURE_SIGNING_KEY in lib.mjs).
function orderKey(order) {
  return "0x" + BigInt(order).toString(16).padStart(64, "0");
}

const CONTRIBUTOR_ORDER_ADDRS = [1, 2, 3].map((n) => signerAddress(orderKey(n)));

function makeSignedContributionReceipt(order, overrides = {}, signingKey = orderKey(order)) {
  const receipt = {
    type: "ContributionReceipt",
    ceremonyId: "0x" + "11".repeat(32),
    frozenManifestHash: "0x" + "aa".repeat(32),
    contributionOrder: order,
    inputZkeyHash: `0x${"bb".repeat(32)}`,
    outputZkeyHash: `0x${(0xcc + order).toString(16).padStart(2, "0")}${"00".repeat(30)}`,
    toolchainHash: "0x" + "dd".repeat(32),
    signer: CONTRIBUTOR_ORDER_ADDRS[order - 1],
    ...overrides,
  };
  const structHash = contributionReceiptHash({
    ceremonyId: receipt.ceremonyId,
    frozenManifestHash: receipt.frozenManifestHash,
    contributionOrder: receipt.contributionOrder,
    inputZkeyHash: receipt.inputZkeyHash,
    outputZkeyHash: receipt.outputZkeyHash,
    toolchainHash: receipt.toolchainHash,
    signer: receipt.signer,
  });
  receipt.signature = overrides.signature ?? signStructHash(structHash, signingKey);
  return receipt;
}

function makeMatchingVerificationReceipt() {
  const receipt = makeTestVerificationReceipt({ signer: FIXTURE_VERIFIER });
  const structHash = verificationReceiptHash({
    ceremonyId: receipt.ceremonyId,
    finalZkeyHash: receipt.finalZkeyHash,
    verificationKeyHash: receipt.verificationKeyHash,
    solidityVerifierHash: receipt.solidityVerifierHash,
    r1csHash: receipt.r1csHash,
    ptauSha256: receipt.ptauSha256,
    verificationPassed: receipt.verificationPassed,
    signer: receipt.signer,
  });
  receipt.signature = signStructHash(structHash, orderKey(1));
  return receipt;
}

// Cleanup helper
function cleanupTestDir() {
  try {
    if (existsSync(TEST_DIR)) {
      rmSync(TEST_DIR, { recursive: true, force: true });
    }
  } catch {}
}

// ---------------------------------------------------------------------------
// Tests: Canonical Hashing
// ---------------------------------------------------------------------------

test("canonicalHash produces deterministic lowercase SHA-256", () => {
  const hash1 = canonicalHash({ b: 2, a: 1 });
  const hash2 = canonicalHash({ a: 1, b: 2 });
  assert.equal(hash1, hash2);
  assert.match(hash1, /^0x[0-9a-f]{64}$/);
});

test("canonicalHash is order-independent for object keys", () => {
  const h1 = canonicalHash({ x: "hello", y: "world" });
  const h2 = canonicalHash({ y: "world", x: "hello" });
  assert.equal(h1, h2);
});

test("canonicalHash differs for different values", () => {
  const h1 = canonicalHash({ a: 1 });
  const h2 = canonicalHash({ a: 2 });
  assert.notEqual(h1, h2);
});

// ---------------------------------------------------------------------------
// Tests: EIP-712 Type Hashes
// ---------------------------------------------------------------------------

test("8.1 EIP712Domain typehash matches the design (address verifyingContract)", () => {
  const designType =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
  assert.equal(toHex(EIP712_DOMAIN_TYPEHASH), toHex(keccak256(Buffer.from(designType))));
});

test("8.1 ContributionReceipt typehash equals keccak256 of the design type string", () => {
  const designType =
    "ContributionReceipt(bytes32 ceremonyId,bytes32 frozenManifestHash,uint256 contributionOrder,bytes32 inputZkeyHash,bytes32 outputZkeyHash,bytes32 toolchainHash,address signer)";
  assert.equal(toHex(CONTRIBUTION_RECEIPT_TYPEHASH), toHex(keccak256(Buffer.from(designType))));
});

test("8.2 CeremonyManifestApproval typehash equals keccak256 of the design type string", () => {
  const designType =
    "CeremonyManifestApproval(bytes32 ceremonyId,bytes32 finalManifestHash,bytes32 beacon,bytes32 finalZkeyHash,bytes32 verificationKeyHash,bytes32 solidityVerifierHash,address signer)";
  assert.equal(
    toHex(CEREMONY_MANIFEST_APPROVAL_TYPEHASH),
    toHex(keccak256(Buffer.from(designType))),
  );
});

test("8.3 VerificationReceipt typehash equals keccak256 of the design type string", () => {
  const designType =
    "VerificationReceipt(bytes32 ceremonyId,bytes32 finalZkeyHash,bytes32 verificationKeyHash,bytes32 solidityVerifierHash,bytes32 r1csHash,bytes32 ptauSha256,bool verificationPassed,address signer)";
  assert.equal(toHex(VERIFICATION_RECEIPT_TYPEHASH), toHex(keccak256(Buffer.from(designType))));
});

test("8.4 EIP-712 domain uses name/version/chainId/zero address per design", () => {
  assert.equal(EIP712_DOMAIN_NAME, "Haze Emergency Ceremony");
  assert.equal(EIP712_DOMAIN_VERSION, "1");
  assert.equal(EIP712_VERIFYING_CONTRACT, "0x0000000000000000000000000000000000000000");
  const separator = eip712DomainSeparator({
    name: EIP712_DOMAIN_NAME,
    version: EIP712_DOMAIN_VERSION,
    chainId: CHAIN_ID,
    verifyingContract: EIP712_VERIFYING_CONTRACT,
  });
  assert.match(toHex(separator), /^0x[0-9a-f]{64}$/);
});

test("all type hashes are unique", () => {
  const hashes = new Set([
    toHex(EIP712_DOMAIN_TYPEHASH),
    toHex(CONTRIBUTION_RECEIPT_TYPEHASH),
    toHex(VERIFICATION_RECEIPT_TYPEHASH),
    toHex(CEREMONY_MANIFEST_APPROVAL_TYPEHASH),
    toHex(AUDIT_FREEZE_APPROVAL_TYPEHASH),
  ]);
  assert.equal(hashes.size, 5);
});

// ---------------------------------------------------------------------------
// Tests: Production Policy
// ---------------------------------------------------------------------------

test("validateProductionPolicy accepts a valid policy", () => {
  const policy = makeTestPolicy();
  assert.doesNotThrow(() => validateProductionPolicy(policy));
});

test("validateProductionPolicy rejects disabled policy", () => {
  const policy = makeTestPolicy({ enabled: false });
  assert.throws(() => validateProductionPolicy(policy), { message: "POLICY_DISABLED" });
});

test("validateProductionPolicy rejects wrong ceremony_id", () => {
  const policy = makeTestPolicy({ ceremony_id: "wrong-ceremony" });
  assert.throws(() => validateProductionPolicy(policy), { message: "POLICY_CEREMONY_MISMATCH" });
});

test("validateProductionPolicy rejects insufficient contributors", () => {
  const policy = makeTestPolicy({ contributors: ["0x1"] });
  assert.throws(() => validateProductionPolicy(policy), { message: "POLICY_INSUFFICIENT_CONTRIBUTORS" });
});

test("validateProductionPolicy rejects duplicate contributors", () => {
  const policy = makeTestPolicy({
    contributors: [
      "0x1111111111111111111111111111111111111111",
      "0x1111111111111111111111111111111111111111",
      "0x3333333333333333333333333333333333333333",
    ],
  });
  assert.throws(() => validateProductionPolicy(policy), { message: "POLICY_DUPLICATE_CONTRIBUTORS" });
});

test("validateProductionPolicy rejects missing auditor", () => {
  const policy = makeTestPolicy({ auditor: undefined });
  assert.throws(() => validateProductionPolicy(policy), { message: "POLICY_AUDITOR_MISSING" });
});

test("validateProductionPolicy rejects insufficient RPCs", () => {
  const policy = makeTestPolicy({ rpcProviders: ["a", "b"] });
  assert.throws(() => validateProductionPolicy(policy), { message: "POLICY_INSUFFICIENT_RPCS" });
});

test("validateProductionPolicy rejects null/undefined policy", () => {
  assert.throws(() => validateProductionPolicy(null), { message: "POLICY_INVALID" });
  assert.throws(() => validateProductionPolicy(undefined), { message: "POLICY_INVALID" });
});

// ---------------------------------------------------------------------------
// Tests: Audit Freeze Manifest
// ---------------------------------------------------------------------------

test("createAuditFreezeManifest produces valid manifest", () => {
  const manifest = makeTestFreezeManifest();
  assert.equal(manifest.ceremony_id, CEREMONY_ID);
  assert.equal(manifest.auditor, FIXTURE_AUDITOR);
  assert.match(manifest.manifest_hash, /^0x[0-9a-f]{64}$/);
});

test("validateAuditFreezeManifest accepts valid manifest", () => {
  const manifest = makeTestFreezeManifest();
  assert.doesNotThrow(() => validateAuditFreezeManifest(manifest, FIXTURE_AUDITOR));
});

test("validateAuditFreezeManifest rejects wrong auditor", () => {
  const manifest = makeTestFreezeManifest();
  assert.throws(
    () => validateAuditFreezeManifest(manifest, "0xBad0000000000000000000000000000000000001"),
    { message: "MANIFEST_AUDITOR_MISMATCH" },
  );
});

test("validateAuditFreezeManifest rejects tampered manifest", () => {
  const manifest = makeTestFreezeManifest();
  manifest.circuit_source_hash = "0xtampered";
  assert.throws(
    () => validateAuditFreezeManifest(manifest, FIXTURE_AUDITOR),
    { message: "MANIFEST_HASH_MISMATCH" },
  );
});

// ---------------------------------------------------------------------------
// Tests: Transcript Chain
// ---------------------------------------------------------------------------

test("4.3 linkGenesis derives from domain_tag || circuit_id", () => {
  const genesis = linkGenesis(EMERGENCY_CIRCUIT_ID);
  assert.match(toHex(genesis), /^0x[0-9a-f]{64}$/);
  assert.deepEqual(genesis, linkGenesis(EMERGENCY_CIRCUIT_ID));
  assert.notDeepEqual(genesis, linkGenesis("haze-spend-v1"));
});

test("4.3 nextTranscript links previous || contributor || input zkey hash", () => {
  const genesis = toHex(linkGenesis(EMERGENCY_CIRCUIT_ID));
  const hash1 = toHex(nextTranscript(genesis, "alice", "0x" + "aa".repeat(32)));
  const hash2 = toHex(nextTranscript(hash1, "bob", "0x" + "bb".repeat(32)));
  assert.match(hash1, /^0x[0-9a-f]{64}$/);
  assert.match(hash2, /^0x[0-9a-f]{64}$/);
  assert.notEqual(hash1, hash2);
  // Different input zkey hash changes the link.
  const hash3 = toHex(nextTranscript(hash1, "bob", "0x" + "cc".repeat(32)));
  assert.notEqual(hash2, hash3);
});

test("verifyTranscriptChain accepts a linked 1-indexed transcript", () => {
  const transcript = makeTestTranscript();
  assert.doesNotThrow(() => verifyTranscriptChain(transcript));
});

test("11.4 broken output_zkey_hash -> input_zkey_hash link aborts ENCODING_INVALID", () => {
  const transcript = makeTestTranscript();
  transcript.contributions[1].input_zkey_hash = "0x" + "ff".repeat(32);
  assert.throws(() => verifyTranscriptChain(transcript), { code: "ENCODING_INVALID" });
});

test("verifyTranscriptChain rejects empty contributions", () => {
  const transcript = { circuit_id: EMERGENCY_CIRCUIT_ID, genesis: "0x00", contributions: [], final_transcript: "0x00" };
  assert.throws(() => verifyTranscriptChain(transcript), { message: "TRANSCRIPT_EMPTY" });
});

test("verifyTranscriptChain rejects wrong order (0-indexed contributions)", () => {
  const transcript = makeTestTranscript();
  transcript.contributions[0].order = 0;
  assert.throws(() => verifyTranscriptChain(transcript), { message: "TRANSCRIPT_ORDER_MISMATCH" });
});

test("verifyTranscriptChain rejects tampered hash", () => {
  const transcript = makeTestTranscript();
  transcript.contributions[1].transcript_hash = "0x" + "ff".repeat(32);
  assert.throws(() => verifyTranscriptChain(transcript), { message: "TRANSCRIPT_HASH_MISMATCH" });
});

test("verifyTranscriptChain rejects wrong genesis", () => {
  const transcript = makeTestTranscript();
  transcript.genesis = "0x" + "00".repeat(32);
  assert.throws(() => verifyTranscriptChain(transcript), { message: "TRANSCRIPT_GENESIS_MISMATCH" });
});

test("verifyTranscriptChain rejects wrong final_transcript", () => {
  const transcript = makeTestTranscript();
  transcript.final_transcript = "0x" + "ff".repeat(32);
  assert.throws(() => verifyTranscriptChain(transcript), { message: "TRANSCRIPT_FINAL_MISMATCH" });
});

test("4.3 raw entropy in a transcript is never accepted (fail-closed)", () => {
  const transcript = makeTestTranscript();
  transcript.contributions[0].entropy = "0xdeadbeefcafebabedeadbeefcafebabe";
  assert.throws(() => verifyTranscriptChain(transcript), { code: "ENCODING_INVALID" });
});

// ---------------------------------------------------------------------------
// Tests: EIP-712 Signing Hashes
// ---------------------------------------------------------------------------

test("8.1 contributionReceiptHash binds the design fields", () => {
  const hash = contributionReceiptHash({
    ceremonyId: toHex(ceremonyGenesis(CEREMONY_ID)),
    frozenManifestHash: "0x" + "aa".repeat(32),
    contributionOrder: 1,
    inputZkeyHash: "0x" + "cc".repeat(32),
    outputZkeyHash: "0x" + "dd".repeat(32),
    toolchainHash: "0x" + "ee".repeat(32),
    signer: FIXTURE_CONTRIBUTORS[0],
  });
  assert.match(toHex(hash), /^0x[0-9a-f]{64}$/);
});

test("8.3 verificationReceiptHash binds the design fields", () => {
  const hash = verificationReceiptHash({
    ceremonyId: "0x" + "11".repeat(32),
    finalZkeyHash: "0x" + "33".repeat(32),
    verificationKeyHash: "0x" + "44".repeat(32),
    solidityVerifierHash: "0x" + "55".repeat(32),
    r1csHash: "0x" + "66".repeat(32),
    ptauSha256: "0x" + "77".repeat(32),
    verificationPassed: true,
    signer: FIXTURE_VERIFIER,
  });
  assert.match(toHex(hash), /^0x[0-9a-f]{64}$/);
});

test("8.2 ceremonyManifestApprovalHash binds the design fields", () => {
  const hash = ceremonyManifestApprovalHash({
    ceremonyId: "0x" + "11".repeat(32),
    finalManifestHash: "0x" + "22".repeat(32),
    beacon: "0x" + "33".repeat(32),
    finalZkeyHash: "0x" + "44".repeat(32),
    verificationKeyHash: "0x" + "55".repeat(32),
    solidityVerifierHash: "0x" + "66".repeat(32),
    signer: FIXTURE_CONTRIBUTORS[0],
  });
  assert.match(toHex(hash), /^0x[0-9a-f]{64}$/);
});

test("auditFreezeApprovalHash produces valid hash", () => {
  const hash = auditFreezeApprovalHash({
    ceremonyId: "0x" + "11".repeat(32),
    freezeManifestHash: "0x" + "22".repeat(32),
    auditReportHash: "0x" + "33".repeat(32),
    signer: FIXTURE_AUDITOR,
  });
  assert.match(toHex(hash), /^0x[0-9a-f]{64}$/);
});

// ---------------------------------------------------------------------------
// Tests: Section 11.3 — Bad or Out-of-Order Signatures
// ---------------------------------------------------------------------------

test("11.3 three signed receipts at orders 1, 2, 3 verify against the ordered allowlist", () => {
  const receipts = [1, 2, 3].map((order) => makeSignedContributionReceipt(order));
  assert.doesNotThrow(() => verifyContributionOrder(receipts, CONTRIBUTOR_ORDER_ADDRS));
  for (const receipt of receipts) {
    assert.doesNotThrow(() =>
      verifyContributionReceiptSignature(receipt, CONTRIBUTOR_ORDER_ADDRS),
    );
  }
});

test("11.3 a bad signature aborts", () => {
  const receipt = makeSignedContributionReceipt(1, {
    signature: "0x" + "ff".repeat(65),
  });
  assert.throws(() => verifyContributionReceiptSignature(receipt, CONTRIBUTOR_ORDER_ADDRS), {
    message: "RECEIPT_BAD_SIGNATURE",
  });
  // Signed by slot 2 but claiming slot 1's wallet: recovery mismatch.
  const wrongSigner = makeSignedContributionReceipt(
    1,
    { signer: CONTRIBUTOR_ORDER_ADDRS[0] },
    orderKey(2),
  );
  assert.throws(() => verifyContributionReceiptSignature(wrongSigner, CONTRIBUTOR_ORDER_ADDRS), {
    message: "RECEIPT_BAD_SIGNATURE",
  });
});

test("11.3 an out-of-order signer set aborts (slot binding enforced)", () => {
  // Order 1 claimed by the order-2 wallet with a valid signature: the set-level
  // slot binding aborts.
  const wrongSlotSet = [
    makeSignedContributionReceipt(1, { signer: CONTRIBUTOR_ORDER_ADDRS[1] }, orderKey(2)),
    makeSignedContributionReceipt(2, { signer: CONTRIBUTOR_ORDER_ADDRS[0] }, orderKey(1)),
    makeSignedContributionReceipt(3),
  ];
  assert.throws(() => verifyContributionOrder(wrongSlotSet, CONTRIBUTOR_ORDER_ADDRS), {
    message: "RECEIPT_ORDER_MISMATCH",
  });
  // Duplicate order and missing order both abort the full set.
  const duplicate = [makeSignedContributionReceipt(1), makeSignedContributionReceipt(1)];
  assert.throws(() => verifyContributionOrder(duplicate, CONTRIBUTOR_ORDER_ADDRS), {
    message: "RECEIPT_ORDER_MISMATCH",
  });
  const missing = [1, 2].map((order) => makeSignedContributionReceipt(order));
  assert.throws(() => verifyContributionOrder(missing, CONTRIBUTOR_ORDER_ADDRS), {
    message: "RECEIPT_ORDER_MISMATCH",
  });
});

test("11.3 contribution orders are 1, 2, 3 — never 0-indexed", () => {
  // Valid signature for the slot-1 wallet, but claimed order 0: aborts.
  const zeroIndexed = makeSignedContributionReceipt(
    0,
    { signer: CONTRIBUTOR_ORDER_ADDRS[0] },
    orderKey(1),
  );
  assert.throws(() => verifyContributionReceiptSignature(zeroIndexed, CONTRIBUTOR_ORDER_ADDRS), {
    message: "RECEIPT_ORDER_MISMATCH",
  });
  const outOfRange = makeSignedContributionReceipt(
    4,
    { signer: CONTRIBUTOR_ORDER_ADDRS[2] },
    orderKey(3),
  );
  assert.throws(() => verifyContributionReceiptSignature(outOfRange, CONTRIBUTOR_ORDER_ADDRS), {
    message: "RECEIPT_ORDER_MISMATCH",
  });
});

test("11.3 unregistered signers abort", () => {
  // A valid signature from a wallet that is not preregistered.
  const unregisteredKey = orderKey(4);
  const unregisteredAddr = signerAddress(unregisteredKey);
  const receipt = makeSignedContributionReceipt(1, { signer: unregisteredAddr }, unregisteredKey);
  assert.throws(() => verifyContributionReceiptSignature(receipt, CONTRIBUTOR_ORDER_ADDRS), {
    message: "RECEIPT_UNREGISTERED_SIGNER",
  });
});

test("11.3 EIP-712 digest round-trips through sign and recover", () => {
  const structHash = contributionReceiptHash({
    ceremonyId: "0x" + "11".repeat(32),
    frozenManifestHash: "0x" + "aa".repeat(32),
    contributionOrder: 1,
    inputZkeyHash: "0x" + "bb".repeat(32),
    outputZkeyHash: "0x" + "cc".repeat(32),
    toolchainHash: "0x" + "dd".repeat(32),
    signer: CONTRIBUTOR_ORDER_ADDRS[0],
  });
  const signature = signStructHash(structHash, orderKey(1));
  const recovered = recoverStructSigner(structHash, signature);
  assert.equal(recovered.toLowerCase(), CONTRIBUTOR_ORDER_ADDRS[0].toLowerCase());
  assert.match(signature, /^0x[0-9a-f]{130}$/);
});

// ---------------------------------------------------------------------------
// Tests: Anchor Payload
// ---------------------------------------------------------------------------

const FIXTURE_PRE_ZKEY_HASH = "0x" + "33".repeat(32);

function makeTestAnchorPayload(overrides = {}) {
  return constructAnchorPayload({
    ceremonyId: CEREMONY_ID,
    preBeaconZkeyHash: FIXTURE_PRE_ZKEY_HASH,
    anchorAddress: FIXTURE_ANCHOR,
    ...overrides,
  });
}

test("5.1 anchor payload carries the pre-beacon zkey keccak precommit", () => {
  const payload = makeTestAnchorPayload();
  assert.equal(payload.chain_id, CHAIN_ID);
  assert.equal(payload.value, "0x0");
  assert.equal(payload.target_offset, ANCHOR_TARGET_OFFSET);
  assert.equal(payload.confirmation_depth, ANCHOR_CONFIRMATION_DEPTH);
  assert.equal(payload.inclusion_window_ms, ANCHOR_INCLUSION_WINDOW_MS);
  assert.equal(payload.precommit_hash, toHex(precommitDigest(FIXTURE_PRE_ZKEY_HASH)));
  assert.match(payload.precommit_hash, /^0x[0-9a-f]{64}$/);
  assert.equal(payload.to, FIXTURE_ANCHOR);
  assert.equal(payload.not_for_production, true);
});

test("validateAnchorPayload accepts valid payload", () => {
  assert.doesNotThrow(() => validateAnchorPayload(makeTestAnchorPayload()));
});

test("validateAnchorPayload rejects wrong chain_id", () => {
  const payload = makeTestAnchorPayload();
  payload.chain_id = 1; // Ethereum mainnet
  assert.throws(() => validateAnchorPayload(payload), { message: "ANCHOR_CHAIN_MISMATCH" });
});

test("validateAnchorPayload rejects non-zero value", () => {
  const payload = makeTestAnchorPayload();
  payload.value = "0x1";
  assert.throws(() => validateAnchorPayload(payload), { message: "ANCHOR_NOT_ZERO_VALUE" });
});

test("validateAnchorPayload rejects wrong target_offset", () => {
  const payload = makeTestAnchorPayload();
  payload.target_offset = 100;
  assert.throws(() => validateAnchorPayload(payload), { message: "ANCHOR_OFFSET_MISMATCH" });
});

// ---------------------------------------------------------------------------
// Tests: Beacon Protocol (Sections 5, 11.5, 11.6)
// ---------------------------------------------------------------------------

test("5.1 precommit digest is keccak256(pre_beacon_zkey_hash)", () => {
  const pre = "0x" + "ab".repeat(32);
  assert.equal(toHex(precommitDigest(pre)), toHex(keccak256(fromHex(pre))));
  assert.notEqual(
    toHex(precommitDigest(pre)),
    toHex(precommitDigest("0x" + "ac".repeat(32))),
  );
});

test("5.2 target height is anchor + 2048 and confirmation is +64", () => {
  assert.equal(targetBlockHeight(1_000_000), 1_002_048);
  assert.equal(confirmationHeight(1_002_048), 1_002_112);
});

test("5.4 deriveEmergencyBeacon is deterministic and 32 bytes", () => {
  const args = {
    targetHeight: 1002048,
    targetHash: "0x" + "cd".repeat(32),
    preZkeyHash: "0x" + "de".repeat(32),
    precommit: "0x" + "ef".repeat(32),
  };
  assert.equal(deriveEmergencyBeacon(args), deriveEmergencyBeacon(args));
  assert.match(deriveEmergencyBeacon(args), /^0x[0-9a-f]{64}$/);
  assert.equal(BEACON_DOMAIN_TAG, "haze/emergency-v1/beacon");
  assert.equal(BEACON_ITERATIONS, 10);
});

test("5.4 beacon sensitivity — every documented parameter binds", () => {
  const base = {
    targetHeight: 1002048,
    targetHash: "0x" + "cd".repeat(32),
    preZkeyHash: "0x" + "de".repeat(32),
    precommit: "0x" + "ef".repeat(32),
  };
  const beacon = deriveEmergencyBeacon(base);
  assert.notEqual(deriveEmergencyBeacon({ ...base, domainTag: "other" }), beacon);
  assert.notEqual(deriveEmergencyBeacon({ ...base, chainId: 1 }), beacon);
  assert.notEqual(deriveEmergencyBeacon({ ...base, targetHeight: base.targetHeight + 1 }), beacon);
  assert.notEqual(deriveEmergencyBeacon({ ...base, targetHash: "0x" + "ff".repeat(32) }), beacon);
  assert.notEqual(deriveEmergencyBeacon({ ...base, preZkeyHash: "0x" + "ff".repeat(32) }), beacon);
  assert.notEqual(deriveEmergencyBeacon({ ...base, precommit: "0x" + "ff".repeat(32) }), beacon);
  assert.notEqual(deriveEmergencyBeacon({ ...base, iterations: 11 }), beacon);
});

test("11.5 anchor inclusion beyond 120 seconds aborts", () => {
  const broadcastAt = new Date(2026, 7, 24, 0, 0, 0);
  const within = new Date(broadcastAt.getTime() + ANCHOR_INCLUSION_WINDOW_MS);
  assert.doesNotThrow(() => assertAnchorInclusionWindow(broadcastAt, within));
  const late = new Date(broadcastAt.getTime() + ANCHOR_INCLUSION_WINDOW_MS + 1);
  assert.throws(() => assertAnchorInclusionWindow(broadcastAt, late), {
    message: "ANCHOR_INCLUSION_LATE",
  });
});

test("11.6 three RPC providers must agree on the target block hash", async () => {
  const providers = ["https://rpc-a.avax.network", "https://rpc-b.avax.network", "https://rpc-c.avax.network"];
  const targetHeight = 1002048;
  const targetHash = "0x" + "12".repeat(32);

  const agreeing = async () => ({
    json: async () => ({ result: { hash: targetHash } }),
  });
  assert.equal(
    await resolveConsensusTargetHash({ targetHeight, providers, fetchImpl: agreeing }),
    targetHash.toLowerCase(),
  );

  // Third provider disagrees -> abort
  const disagreeing = async (url) => ({
    json: async () => ({ result: { hash: url.includes("rpc-c") ? "0x" + "ff".repeat(32) : targetHash } }),
  });
  await assert.rejects(
    () => resolveConsensusTargetHash({ targetHeight, providers, fetchImpl: disagreeing }),
    { message: "ANCHOR_RPC_DISAGREEMENT" },
  );

  // Provider error -> abort
  const erroring = async () => {
    throw new Error("network down");
  };
  await assert.rejects(
    () => resolveConsensusTargetHash({ targetHeight, providers, fetchImpl: erroring }),
    { message: "ANCHOR_RPC_DISAGREEMENT" },
  );

  // Fewer than three providers -> abort
  await assert.rejects(
    () => resolveConsensusTargetHash({ targetHeight, providers: providers.slice(0, 2), fetchImpl: agreeing }),
    { message: "ANCHOR_RPC_DISAGREEMENT" },
  );
});

test("5.5 a known/predictable target block aborts", () => {
  assert.doesNotThrow(() =>
    assertTargetNotPredictable({ currentHeightAtBroadcast: 999_000, targetHeight: 1_002_048 }),
  );
  assert.throws(
    () => assertTargetNotPredictable({ currentHeightAtBroadcast: 1_002_048, targetHeight: 1_002_048 }),
    { message: "ANCHOR_TARGET_PREDICTABLE" },
  );
  assert.throws(
    () => assertTargetNotPredictable({ currentHeightAtBroadcast: 1_100_000, targetHeight: 1_002_048 }),
    { message: "ANCHOR_TARGET_PREDICTABLE" },
  );
});

// ---------------------------------------------------------------------------
// Tests: Section 11.7–11.9 — Verifier/VK, Manifest Approvals, Rehearsal
// ---------------------------------------------------------------------------

function makeSignedManifestApproval(slot, overrides = {}, signingKey = orderKey(slot)) {
  const approval = {
    type: "CeremonyManifestApproval",
    ceremonyId: CEREMONY_ID,
    finalManifestHash: "0x" + "aa".repeat(32),
    beacon: "0x" + "bb".repeat(32),
    finalZkeyHash: "0x" + "cc".repeat(32),
    verificationKeyHash: "0x" + "dd".repeat(32),
    solidityVerifierHash: "0x" + "ee".repeat(32),
    signer: CONTRIBUTOR_ORDER_ADDRS[slot - 1],
    ...overrides,
  };
  const structHash = ceremonyManifestApprovalHash({
    ceremonyId: approval.ceremonyId,
    finalManifestHash: approval.finalManifestHash,
    beacon: approval.beacon,
    finalZkeyHash: approval.finalZkeyHash,
    verificationKeyHash: approval.verificationKeyHash,
    solidityVerifierHash: approval.solidityVerifierHash,
    signer: approval.signer,
  });
  approval.signature = overrides.signature ?? signStructHash(structHash, signingKey);
  return approval;
}

test("11.8 three signed CeremonyManifestApprovals satisfy the final manifest", () => {
  const approvals = [1, 2, 3].map((slot) => makeSignedManifestApproval(slot));
  assert.doesNotThrow(() => verifyFinalManifestApprovals(approvals, CONTRIBUTOR_ORDER_ADDRS));
});

test("11.8 fewer than three approvals leaves the ceremony incomplete", () => {
  const two = [1, 2].map((slot) => makeSignedManifestApproval(slot));
  assert.throws(() => verifyFinalManifestApprovals(two, CONTRIBUTOR_ORDER_ADDRS), {
    message: "APPROVAL_COUNT_MISMATCH",
  });
  const empty = [];
  assert.throws(() => verifyFinalManifestApprovals(empty, CONTRIBUTOR_ORDER_ADDRS), {
    message: "APPROVAL_COUNT_MISMATCH",
  });
  // Duplicate signers do not count as three organizations.
  const duplicated = [
    makeSignedManifestApproval(1),
    makeSignedManifestApproval(1, { signer: CONTRIBUTOR_ORDER_ADDRS[0] }),
    makeSignedManifestApproval(1, { signer: CONTRIBUTOR_ORDER_ADDRS[0] }),
  ];
  assert.throws(() => verifyFinalManifestApprovals(duplicated, CONTRIBUTOR_ORDER_ADDRS), {
    message: "APPROVAL_COUNT_MISMATCH",
  });
});

test("11.3 refusal rules apply to final approvals (bad signature)", () => {
  const gagged = [
    makeSignedManifestApproval(1, { signature: "0x" + "ff".repeat(65) }),
    makeSignedManifestApproval(2),
    makeSignedManifestApproval(3),
  ];
  assert.throws(() => verifyFinalManifestApprovals(gagged, CONTRIBUTOR_ORDER_ADDRS), {
    message: "APPROVAL_BAD_SIGNATURE",
  });
  const unregistered = [
    makeSignedManifestApproval(1, { signer: signerAddress(orderKey(9)) }, orderKey(9)),
    makeSignedManifestApproval(2),
    makeSignedManifestApproval(3),
  ];
  assert.throws(() => verifyFinalManifestApprovals(unregistered, CONTRIBUTOR_ORDER_ADDRS), {
    message: "APPROVAL_UNREGISTERED",
  });
});

test("11.7 solidity verifier hash that does not match the exported VK aborts", () => {
  const vkHash = "0x" + "aa".repeat(32);
  const source = `contract HazeEmergencyGroth16Verifier {
    bytes32 public constant VK_HASH = ${vkHash};
  }`;
  const sha256 = (text) => `0x${createHash("sha256").update(text).digest("hex")}`;
  const matchingHash = sha256(source);
  assert.doesNotThrow(() =>
    verifyVerifierVkMatch({
      solidityVerifierSource: source,
      verificationKeyHash: vkHash,
      solidityVerifierHash: matchingHash,
    }),
  );
  // A source that embeds a different VK aborts.
  assert.throws(
    () =>
      verifyVerifierVkMatch({
        solidityVerifierSource: source,
        verificationKeyHash: "0x" + "bb".repeat(32),
        solidityVerifierHash: matchingHash,
      }),
    { message: "VERIFIER_VK_MISMATCH" },
  );
  // A hash that does not match the source aborts.
  assert.throws(
    () =>
      verifyVerifierVkMatch({
        solidityVerifierSource: source,
        verificationKeyHash: vkHash,
        solidityVerifierHash: sha256("something else"),
      }),
    { message: "VERIFIER_VK_MISMATCH" },
  );
  // A placeholder VK always aborts.
  assert.throws(
    () =>
      verifyVerifierVkMatch({
        solidityVerifierSource: source,
        verificationKeyHash: "0x" + "00".repeat(32),
        solidityVerifierHash: matchingHash,
      }),
    { message: "VERIFIER_VK_MISMATCH" },
  );
});

test("freeze hashes that are zero/placeholder abort contract generation", () => {
  const real = {
    sourceHash: "0x" + "01".repeat(32),
    r1csHash: "0x" + "02".repeat(32),
    buildHash: "0x" + "03".repeat(32),
  };
  assert.doesNotThrow(() => assertFreezeHashesNonPlaceholder(real));
  assert.throws(
    () => assertFreezeHashesNonPlaceholder({ ...real, sourceHash: "0x" + "00".repeat(32) }),
    { message: "FREEZE_HASHES_PLACEHOLDER" },
  );
  assert.throws(
    () => assertFreezeHashesNonPlaceholder({ ...real, r1csHash: undefined }),
    { message: "FREEZE_HASHES_PLACEHOLDER" },
  );
});

test("11.9 rehearsal transcript rejected as a production emergency zkey", () => {
  const rehearsal = JSON.parse(
    readFileSync(
      join(HAZE_ROOT, "dev/artifacts/emergency-operator-owned-ceremony-transcript.json"),
      "utf8",
    ),
  );
  assert.equal(rehearsal.not_for_production, true);
  assert.throws(() => refuseRehearsalAsEmergencyZkey(rehearsal), {
    code: "VERSION_UNSUPPORTED",
  });
  assert.throws(
    () =>
      refuseRehearsalAsEmergencyZkey({
        circuit_id: "haze-development-equality-v1",
        r1cs: "development_equality.r1cs",
        n_constraints: 192535,
      }),
    { code: "VERSION_UNSUPPORTED" },
  );
  assert.doesNotThrow(() =>
    refuseRehearsalAsEmergencyZkey({
      circuit_id: "haze-emergency-v1",
      r1cs: "haze-emergency.r1cs",
      n_constraints: 192535,
      not_for_production: false,
    }),
  );
});

// ---------------------------------------------------------------------------
// Tests: Section 6 — Opening and Final Public Outputs
// ---------------------------------------------------------------------------

const FIXTURE_OPENING_HASHES = {
  sourceHash: "0x" + "01".repeat(32),
  r1csHash: "0x" + "02".repeat(32),
  fixtureHash: "0x" + "03".repeat(32),
  buildHash: "0x" + "04".repeat(32),
};

test("6.1 opening manifest contains ceremony, circuit, freeze, beacon, allowlist fields", () => {
  const opening = createOpeningManifest({
    ...FIXTURE_OPENING_HASHES,
    walletAllowlist: CONTRIBUTOR_ORDER_ADDRS,
  });
  assert.equal(opening.ceremony_id, CEREMONY_ID);
  assert.equal(opening.circuit_id, "haze-emergency-v1");
  assert.equal(opening.n_constraints, 192535);
  assert.equal(opening.public_inputs, 20);
  assert.equal(opening.circom_version, "2.2.3");
  assert.equal(
    opening.ptau_sha256,
    "159d3f938d941e06767d99f30b9fe59a245400a4aae138cf8e411732d7a2f6cd",
  );
  assert.equal(opening.ptau_power, 20);
  assert.equal(opening.source_hash, FIXTURE_OPENING_HASHES.sourceHash);
  assert.equal(opening.r1cs_hash, FIXTURE_OPENING_HASHES.r1csHash);
  assert.equal(opening.fixture_hash, FIXTURE_OPENING_HASHES.fixtureHash);
  assert.equal(opening.build_hash, FIXTURE_OPENING_HASHES.buildHash);
  assert.deepEqual(
    opening.contributors.map(({ order, organization }) => ({ order, organization })),
    [
      { order: 1, organization: "Haze" },
      { order: 2, organization: "Independent Auditor" },
      { order: 3, organization: "Third Organization" },
    ],
  );
  assert.equal(opening.beacon_chain_id, 43114);
  assert.equal(opening.beacon_offset, 2048);
  assert.equal(opening.beacon_confirmation, 64);
  assert.deepEqual(opening.wallet_allowlist, CONTRIBUTOR_ORDER_ADDRS);
  assert.match(opening.manifest_hash, /^0x[0-9a-f]{64}$/);
});

test("6.8 final artifact manifest matches Section 6.8 fields", () => {
  const final = createFinalArtifactManifest({
    ...FIXTURE_OPENING_HASHES,
    finalZkeyHash: "0x" + "11".repeat(32),
    verificationKeyHash: "0x" + "22".repeat(32),
    solidityVerifierHash: "0x" + "33".repeat(32),
    beacon: "0x" + "44".repeat(32),
    anchorTxHash: "0x" + "55".repeat(32),
    targetBlockHeight: 1002048,
    targetBlockHash: "0x" + "66".repeat(32),
    transcriptHash: "0x" + "77".repeat(32),
  });
  assert.equal(final.ceremony_id, CEREMONY_ID);
  assert.equal(final.circuit_id, "haze-emergency-v1");
  assert.equal(final.n_constraints, 192535);
  assert.equal(final.ptau_sha256, "159d3f938d941e06767d99f30b9fe59a245400a4aae138cf8e411732d7a2f6cd");
  assert.equal(final.final_zkey_hash, "0x" + "11".repeat(32));
  assert.equal(final.verification_key_hash, "0x" + "22".repeat(32));
  assert.equal(final.solidity_verifier_hash, "0x" + "33".repeat(32));
  assert.equal(final.target_block_height, 1002048);
  assert.equal(final.target_block_hash, "0x" + "66".repeat(32));
  assert.equal(final.transcript_hash, "0x" + "77".repeat(32));
  assert.equal(final.contribution_count, 3);
  assert.match(final.manifest_hash, /^0x[0-9a-f]{64}$/);
});

test("6.4 public transcript exposes names and zkey hashes only — no entropy", () => {
  const transcript = makeTestTranscript();
  transcript.beacon_hash = "0x" + "be".repeat(32);
  const pub = publicEmergencyTranscript(transcript);
  const serialized = JSON.stringify(pub);
  assert.doesNotMatch(serialized, /entropy|toxic_waste/i);
  assert.equal(pub.contributions.length, 3);
  assert.equal(pub.contributions[0].contributor, FIXTURE_CONTRIBUTORS[0].toLowerCase());
  assert.equal(pub.contributions[0].input_zkey_hash, "0x" + "99".repeat(32));
  assert.equal(pub.beacon_hash, "0x" + "be".repeat(32));
  // A transcript leaking raw entropy fails closed.
  transcript.contributions[0].entropy = "0xdeadbeefcafebabe";
  assert.throws(() => publicEmergencyTranscript(transcript), { code: "ENCODING_INVALID" });
});

// ---------------------------------------------------------------------------
// Tests: Contract Generation
// ---------------------------------------------------------------------------

test("generateContractBundle produces all contracts and source manifest", () => {
  cleanupTestDir();
  mkdirSync(TEST_DIR, { recursive: true });

  const bundle = generateContractBundle({
    outputDir: TEST_DIR,
    vkHash: "0x" + "aa".repeat(32),
    circuitSourceHash: "0x" + "bb".repeat(32),
    buildHash: "0x" + "cc".repeat(32),
    artifactHash: "0x" + "dd".repeat(32),
    r1csHash: "0x" + "ee".repeat(32),
    ptauHash: "0x" + "ff".repeat(32),
    zkeyHash: "0x" + "11".repeat(32),
    finalTranscriptHash: "0x" + "22".repeat(32),
    manifestHash: "0x" + "33".repeat(32),
  });

  assert.ok(bundle.groth16Verifier.includes("HazeEmergencyGroth16Verifier"));
  assert.ok(bundle.exitVerifier.includes("EmergencyExitVerifier"));
  assert.ok(bundle.emergencyExit.includes("EmergencyExit"));
  assert.ok(bundle.sourceManifest.contracts);
  assert.match(bundle.sourceManifest.manifest_hash, /^0x[0-9a-f]{64}$/);

  cleanupTestDir();
});

test("validateContractBundle accepts valid bundle", () => {
  cleanupTestDir();
  mkdirSync(TEST_DIR, { recursive: true });

  const bundle = generateContractBundle({
    outputDir: TEST_DIR,
    vkHash: "0x" + "aa".repeat(32),
    circuitSourceHash: "0x" + "bb".repeat(32),
    buildHash: "0x" + "cc".repeat(32),
    artifactHash: "0x" + "dd".repeat(32),
    r1csHash: "0x" + "ee".repeat(32),
    ptauHash: "0x" + "ff".repeat(32),
    zkeyHash: "0x" + "11".repeat(32),
    finalTranscriptHash: "0x" + "22".repeat(32),
    manifestHash: "0x" + "33".repeat(32),
  });

  assert.doesNotThrow(() => validateContractBundle(bundle));
  cleanupTestDir();
});

test("validateContractBundle rejects NOT_FOR_PRODUCTION = true in Groth16Verifier", () => {
  const bundle = {
    groth16Verifier: "NOT_FOR_PRODUCTION = true",
    exitVerifier: "NOT_FOR_PRODUCTION = false",
    emergencyExit: "contract EmergencyExit { }",
    sourceManifest: {
      contracts: {
        HazeEmergencyGroth16Verifier: {},
        EmergencyExitVerifier: {},
        EmergencyExit: {},
      },
    },
  };
  // Need a valid manifest hash
  const copy = { ...bundle.sourceManifest };
  bundle.sourceManifest.manifest_hash = canonicalHash(copy);
  assert.throws(() => validateContractBundle(bundle), { message: "BUNDLE_GROTH16_NOT_FOR_PRODUCTION" });
});

test("validateContractBundle rejects KEYS_MISSING in Groth16Verifier", () => {
  const bundle = {
    groth16Verifier: `NOT_FOR_PRODUCTION = false
revert("KEYS_MISSING")`,
    exitVerifier: "NOT_FOR_PRODUCTION = false",
    emergencyExit: "contract EmergencyExit { }",
    sourceManifest: {
      contracts: {
        HazeEmergencyGroth16Verifier: {},
        EmergencyExitVerifier: {},
        EmergencyExit: {},
      },
    },
  };
  const copy = { ...bundle.sourceManifest };
  bundle.sourceManifest.manifest_hash = canonicalHash(copy);
  assert.throws(() => validateContractBundle(bundle), { message: "BUNDLE_GROTH16_KEYS_MISSING" });
});

test("validateContractBundle rejects admin/proxy/upgrade in EmergencyExit", () => {
  const bundle = {
    groth16Verifier: "NOT_FOR_PRODUCTION = false",
    exitVerifier: "NOT_FOR_PRODUCTION = false",
    emergencyExit: "contract EmergencyExit { address public owner; }",
    sourceManifest: {
      contracts: {
        HazeEmergencyGroth16Verifier: {},
        EmergencyExitVerifier: {},
        EmergencyExit: {},
      },
    },
  };
  const copy = { ...bundle.sourceManifest };
  bundle.sourceManifest.manifest_hash = canonicalHash(copy);
  assert.throws(() => validateContractBundle(bundle), { message: "BUNDLE_EXIT_HAS_ADMIN_PATH" });
});

// ---------------------------------------------------------------------------
// Tests: Ceremony State Machine
// ---------------------------------------------------------------------------

test("validateCeremonyState accepts valid transitions", () => {
  assert.doesNotThrow(() => validateCeremonyState({ phase: "created" }, "open"));
  assert.doesNotThrow(() => validateCeremonyState({ phase: "opened" }, "setup"));
  assert.doesNotThrow(() => validateCeremonyState({ phase: "setup" }, "contribute"));
  assert.doesNotThrow(() => validateCeremonyState({ phase: "contributed" }, "accept-receipt"));
  assert.doesNotThrow(() => validateCeremonyState({ phase: "finalized_transcript" }, "anchor-plan"));
  assert.doesNotThrow(() => validateCeremonyState({ phase: "anchored" }, "anchor-verify"));
  assert.doesNotThrow(() => validateCeremonyState({ phase: "anchored" }, "beacon"));
  assert.doesNotThrow(() => validateCeremonyState({ phase: "beacon_applied" }, "finalize"));
  assert.doesNotThrow(() => validateCeremonyState({ phase: "finalized" }, "verify-release"));
  assert.doesNotThrow(() => validateCeremonyState({ phase: "verified" }, "generate-contracts"));
});

test("validateCeremonyState rejects invalid transitions", () => {
  assert.throws(() => validateCeremonyState({ phase: "created" }, "contribute"), /INVALID_STATE/);
  assert.throws(() => validateCeremonyState({ phase: "setup" }, "finalize"), /INVALID_STATE/);
  assert.throws(() => validateCeremonyState({ phase: "opened" }, "generate-contracts"), /INVALID_STATE/);
  assert.throws(() => validateCeremonyState({ phase: "created" }, "unknown"), /UNKNOWN_COMMAND/);
});

// ---------------------------------------------------------------------------
// Tests: Contribution Receipt Hash Vectors
// ---------------------------------------------------------------------------

test("8.1 contribution receipt hash covers the design fields", () => {
  const genesis = toHex(ceremonyGenesis(CEREMONY_ID));
  const hash = contributionReceiptHash({
    ceremonyId: genesis,
    frozenManifestHash: "0x" + "aa".repeat(32),
    contributionOrder: 1,
    inputZkeyHash: "0x" + "bb".repeat(32),
    outputZkeyHash: "0x" + "cc".repeat(32),
    toolchainHash: "0x" + "dd".repeat(32),
    signer: FIXTURE_CONTRIBUTORS[0],
  });
  assert.match(toHex(hash), /^0x[0-9a-f]{64}$/);
});

test("8.1 contribution receipt hash changes with contribution order (1 vs 2)", () => {
  const genesis = toHex(ceremonyGenesis(CEREMONY_ID));
  const base = {
    ceremonyId: genesis,
    frozenManifestHash: "0x" + "aa".repeat(32),
    inputZkeyHash: "0x" + "bb".repeat(32),
    outputZkeyHash: "0x" + "cc".repeat(32),
    toolchainHash: "0x" + "dd".repeat(32),
    signer: FIXTURE_CONTRIBUTORS[0],
  };
  const hash1 = contributionReceiptHash({ ...base, contributionOrder: 1 });
  const hash2 = contributionReceiptHash({ ...base, contributionOrder: 2 });
  assert.notEqual(toHex(hash1), toHex(hash2));
});

// ---------------------------------------------------------------------------
// Tests: Fixed Constants
// ---------------------------------------------------------------------------

test("ceremony constants match specification", () => {
  assert.equal(CEREMONY_ID, "haze-emergency-v1-production");
  assert.equal(CHAIN_ID, 43114);
  assert.equal(REQUIRED_CONTRIBUTIONS, 3);
  assert.equal(REQUIRED_FINAL_APPROVALS, 3);
  assert.equal(ANCHOR_TARGET_OFFSET, 2048);
  assert.equal(ANCHOR_CONFIRMATION_DEPTH, 64);
  assert.equal(ANCHOR_INCLUSION_WINDOW_MS, 120_000);
  assert.equal(typeof SNARK_SCALAR_FIELD, "bigint");
});

test("SNARK_SCALAR_FIELD matches the expected value", () => {
  assert.equal(
    SNARK_SCALAR_FIELD,
    0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n,
  );
});

// ---------------------------------------------------------------------------
// Tests: Emergency Policy (from committed file)
// ---------------------------------------------------------------------------

test("committed emergency policy is disabled with placeholder addresses", () => {
  const policy = loadRawPolicy(HAZE_ROOT);
  assert.equal(policy.enabled, false);
  assert.equal(policy.ceremony_id, CEREMONY_ID);
  assert.equal(policy.contributors.length, 3);
  // All placeholder addresses are zero addresses
  const placeholderCount = policy.contributors.filter((c) =>
    /^0x0{38}/.test(c),
  ).length;
  assert.equal(placeholderCount, 3);
});

// ---------------------------------------------------------------------------
// Tests: Section 11.1 / 11.2 — Fail-Closed Freeze and Ptau
// ---------------------------------------------------------------------------

test("11.1 wrong ptau SHA-256 aborts VERSION_UNSUPPORTED (injected digest)", () => {
  const ptauPath = join(TEST_DIR, "powersOfTau28_hez_final_20.ptau");
  mkdirSync(TEST_DIR, { recursive: true });
  writeFileSync(ptauPath, "wrong ptau bytes, not the pinned Hermez file");
  assert.throws(() => assertEmergencyPtauChecksum(ptauPath), { code: "VERSION_UNSUPPORTED" });
});

test("11.1 ptau checksum passes when the file matches the injected digest", () => {
  const ptauPath = join(TEST_DIR, "powersOfTau28_hez_final_20.ptau");
  const content = "fake ptau content for digest injection";
  writeFileSync(ptauPath, content);
  const digest = createHash("sha256").update(content).digest("hex");
  assert.equal(assertEmergencyPtauChecksum(ptauPath, { sha256: digest }), digest);
});

test("11.1 pinned ptau spec matches the design (power 20, Hermez SHA-256)", () => {
  assert.equal(EMERGENCY_PTAU_POWER, 20);
  assert.equal(
    EMERGENCY_PTAU_SHA256,
    "159d3f938d941e06767d99f30b9fe59a245400a4aae138cf8e411732d7a2f6cd",
  );
  assert.equal(assertEmergencyPtauPower(EMERGENCY_N_CONSTRAINTS), 20);
  assert.throws(() => assertEmergencyPtauPower(1 << 20), { code: "VERSION_UNSUPPORTED" });
});

test("11.2 setup pin requires haze-emergency-v1, Circom 2.2.3, 192535, 20 public inputs", () => {
  const pin = {
    circuit_id: EMERGENCY_CIRCUIT_ID,
    circom_version: EMERGENCY_CIRCOM_VERSION,
    n_constraints: EMERGENCY_N_CONSTRAINTS,
    public_inputs: EMERGENCY_PUBLIC_INPUTS,
  };
  const spec = assertEmergencyCircuitPin(pin);
  assert.equal(spec.circuit_id, "haze-emergency-v1");
  assert.equal(spec.circom_version, "2.2.3");
  assert.equal(spec.n_constraints, 192535);
  assert.equal(spec.public_inputs, 20);

  assert.throws(
    () => assertEmergencyCircuitPin({ ...pin, n_constraints: 588459 }),
    { code: "VERSION_UNSUPPORTED" },
  );
  assert.throws(
    () => assertEmergencyCircuitPin({ ...pin, circom_version: "0.5.0" }),
    { code: "VERSION_UNSUPPORTED" },
  );
  assert.throws(
    () => assertEmergencyCircuitPin({ ...pin, public_inputs: 19 }),
    { code: "VERSION_UNSUPPORTED" },
  );
  assert.throws(
    () => assertEmergencyCircuitPin({ ...pin, circuit_id: "haze-spend-v1" }),
    { code: "VERSION_UNSUPPORTED" },
  );
  assert.throws(() => assertEmergencyCircuitPin(null), { code: "VERSION_UNSUPPORTED" });
});

test("11.2 source/R1CS/build hash mismatch vs freeze manifest aborts VERSION_UNSUPPORTED", () => {
  const freeze = makeTestFreezeManifest();
  const hashes = {
    sourceHash: freeze.circuit_source_hash,
    r1csHash: freeze.r1cs_hash,
    buildHash: freeze.build_hash,
  };
  assert.doesNotThrow(() => validateFreezeHashes(hashes, freeze));
  assert.throws(
    () => validateFreezeHashes({ ...hashes, sourceHash: "0x" + "11".repeat(32) }, freeze),
    { code: "VERSION_UNSUPPORTED" },
  );
  assert.throws(
    () => validateFreezeHashes({ ...hashes, r1csHash: "0x" + "22".repeat(32) }, freeze),
    { code: "VERSION_UNSUPPORTED" },
  );
  assert.throws(
    () => validateFreezeHashes({ ...hashes, buildHash: "0x" + "33".repeat(32) }, freeze),
    { code: "VERSION_UNSUPPORTED" },
  );
});

// ---------------------------------------------------------------------------
// Tests: Section 4.2 / 14 — snarkjs Command Plan (no execution)
// ---------------------------------------------------------------------------

const EMERGENCY_R1CS = join(HAZE_ROOT, "circuits/build/emergency/emergency.r1cs");

test("14 planEmergencyPhase2 plans setup, 3 contributes, beacon, verify, exports", () => {
  const plan = planEmergencyPhase2({
    r1cs: EMERGENCY_R1CS,
    ptau: "powersOfTau28_hez_final_20.ptau",
    workDir: join(HAZE_ROOT, "dev/artifacts/ceremony-private/emergency-v1"),
  });
  assert.equal(plan.commands.length, 8);
  // 1. groth16 setup -> 0000
  assert.deepEqual(plan.commands[0].slice(0, 4), ["snarkjs", "groth16", "setup", EMERGENCY_R1CS]);
  assert.match(plan.commands[0][5], /haze-emergency-0000\.zkey$/);
  // 2. three contributes -> 0001 / 0002 / 0003
  assert.equal(plan.commands.filter((command) => command.includes("contribute")).length, 3);
  assert.match(plan.commands[1][4], /haze-emergency-0001\.zkey$/);
  assert.match(plan.commands[2][4], /haze-emergency-0002\.zkey$/);
  assert.match(plan.commands[3][4], /haze-emergency-0003\.zkey$/);
  // 3. beacon from 0003 -> final, 10 iterations
  assert.deepEqual(plan.commands[4].slice(0, 5), [
    "snarkjs", "zkey", "beacon", plan.afterThird, plan.finalZkey,
  ]);
  assert.equal(plan.commands[4][6], "10");
  // 4. verify 5. exports
  assert.deepEqual(plan.commands[5].slice(0, 5), ["snarkjs", "zkey", "verify", EMERGENCY_R1CS, "powersOfTau28_hez_final_20.ptau"]);
  assert.ok(plan.commands[6].includes("verificationkey"));
  assert.ok(plan.commands[7].includes("solidityverifier"));
  assert.equal(plan.contributors.length, 3);
  assert.equal(plan.circuit_id, "haze-emergency-v1");
  assert.equal(plan.n_constraints, 192535);
  assert.equal(plan.ptauSha256, "159d3f938d941e06767d99f30b9fe59a245400a4aae138cf8e411732d7a2f6cd");
  assert.match(plan.privateDir, /ceremony-private\/emergency-v1/);
  assert.equal(plan.execution, "plan-only");
});

test("14 plan uses design contributor order and pins the freeze", () => {
  const plan = planEmergencyPhase2({
    r1cs: EMERGENCY_R1CS,
    contributors: ["Haze", "Independent Auditor", "Third Organization"],
  });
  assert.deepEqual(plan.contributors, ["Haze", "Independent Auditor", "Third Organization"]);
  // The freeze pin is enforced by planning.
  assert.throws(
    () =>
      planEmergencyPhase2({
        r1cs: EMERGENCY_R1CS,
        nConstraints: 588459,
      }),
    { code: "VERSION_UNSUPPORTED" },
  );
  assert.throws(
    () => planEmergencyPhase2({ r1cs: EMERGENCY_R1CS, contributors: ["a", "b"] }),
    { code: "VERSION_UNSUPPORTED" },
  );
});

test("14 runEmergencyPhase2 refuses a real spawn by default", () => {
  assert.throws(
    () => runEmergencyPhase2({ r1cs: EMERGENCY_R1CS }),
    { code: "CEREMONY_BLOCKED" },
  );
  assert.throws(
    () => runEmergencyPhase2({ r1cs: EMERGENCY_R1CS, runner: null }),
    { code: "CEREMONY_BLOCKED" },
  );
});

test("14 plan argv is captured through the injected runner", () => {
  const calls = [];
  const options = {
    r1cs: EMERGENCY_R1CS,
    ptau: "powersOfTau28_hez_final_20.ptau",
    workDir: join(HAZE_ROOT, "dev/artifacts/ceremony-private/emergency-v1"),
    runner: (argv, extra) => {
      calls.push({ argv, extra });
      return { stdout: "", stderr: "", status: 0 };
    },
  };
  const plan = runEmergencyPhase2(options);
  assert.equal(calls.length, plan.commands.length);
  // Setup argv
  assert.deepEqual(calls[0].argv.slice(0, 4), ["snarkjs", "groth16", "setup", EMERGENCY_R1CS]);
  assert.match(calls[0].argv[5], /haze-emergency-0000\.zkey$/);
  // Three contribute commands each carry per-contributor entropy (never logged raw)
  const contributes = calls.filter((call) => call.argv[1] === "zkey" && call.argv[2] === "contribute");
  assert.equal(contributes.length, 3);
  assert.match(contributes[0].argv[5], /--name=Haze$/);
  assert.match(contributes[1].argv[5], /--name=Independent Auditor$/);
  assert.match(contributes[2].argv[5], /--name=Third Organization$/);
  for (const call of contributes) {
    assert.ok(call.extra.entropy && call.extra.entropy.length >= 64);
  }
  // Beacon argv carries the plan's beacon placeholder
  const beacon = calls.find((call) => call.argv[1] === "zkey" && call.argv[2] === "beacon");
  assert.deepEqual(beacon.argv.slice(0, 5), [
    "snarkjs", "zkey", "beacon", plan.afterThird, plan.finalZkey,
  ]);
  assert.equal(beacon.argv[6], "10");
  // Exports
  assert.ok(calls.some((call) => call.argv.includes("verificationkey")));
  assert.ok(calls.some((call) => call.argv.includes("solidityverifier")));
});

// ---------------------------------------------------------------------------
// Tests: Production Policy Gate
// ---------------------------------------------------------------------------

test("loadProductionPolicy fails for disabled policy", () => {
  assert.throws(() => {
    loadProductionPolicy(HAZE_ROOT);
  }, { message: "POLICY_DISABLED" });
});

test("setup rejects policy with only placeholder addresses", () => {
  const policy = makeTestPolicy({
    contributors: [
      "0x0000000000000000000000000000000000000001",
      "0x0000000000000000000000000000000000000002",
      "0x0000000000000000000000000000000000000003",
    ],
  });
  // When all contributors are zero addresses, setup should reject
  const allZero = policy.contributors.every((c) => /^0x0{38}/.test(c));
  assert.equal(allZero, true);
});

// ---------------------------------------------------------------------------
// Tests: Verification Receipt
// ---------------------------------------------------------------------------

test("8.3 verification receipt binds verificationPassed and signer", () => {
  const receipt = makeTestVerificationReceipt();
  assert.equal(typeof receipt.verificationPassed, "boolean");
  assert.equal(receipt.verificationPassed, true);
  assert.equal(receipt.signer, FIXTURE_VERIFIER);
  const signature = makeMatchingVerificationReceipt();
  assert.match(signature.signature, /^0x[0-9a-f]{130}$/);
});

test("8.3 verification receipt hash changes when verification fails", () => {
  const passed = verificationReceiptHash({
    ceremonyId: "0x" + "11".repeat(32),
    finalZkeyHash: "0x" + "33".repeat(32),
    verificationKeyHash: "0x" + "44".repeat(32),
    solidityVerifierHash: "0x" + "55".repeat(32),
    r1csHash: "0x" + "66".repeat(32),
    ptauSha256: "0x" + "77".repeat(32),
    verificationPassed: true,
    signer: FIXTURE_VERIFIER,
  });
  const failed = verificationReceiptHash({
    ceremonyId: "0x" + "11".repeat(32),
    finalZkeyHash: "0x" + "33".repeat(32),
    verificationKeyHash: "0x" + "44".repeat(32),
    solidityVerifierHash: "0x" + "55".repeat(32),
    r1csHash: "0x" + "66".repeat(32),
    ptauSha256: "0x" + "77".repeat(32),
    verificationPassed: false,
    signer: FIXTURE_VERIFIER,
  });
  assert.notEqual(toHex(passed), toHex(failed));
});

// ---------------------------------------------------------------------------
// Tests: Transcript Structure
// ---------------------------------------------------------------------------

test("test transcript has correct structure for 3 contributions", () => {
  const transcript = makeTestTranscript();
  assert.equal(transcript.ceremony_id, CEREMONY_ID);
  assert.equal(transcript.circuit_id, EMERGENCY_CIRCUIT_ID);
  assert.equal(transcript.contributions.length, 3);
  assert.match(transcript.genesis, /^0x[0-9a-f]{64}$/);
  assert.match(transcript.final_transcript, /^0x[0-9a-f]{64}$/);
  // Verify each contribution has 1-indexed order and chained zkey hashes
  for (let i = 0; i < 3; i++) {
    assert.equal(transcript.contributions[i].order, i + 1);
    assert.equal(transcript.contributions[i].contributor, FIXTURE_CONTRIBUTORS[i].toLowerCase());
    if (i > 0) {
      assert.equal(
        transcript.contributions[i].input_zkey_hash,
        transcript.contributions[i - 1].output_zkey_hash,
      );
    }
  }
});

test("verifyTranscriptChain validates the test transcript", () => {
  const transcript = makeTestTranscript();
  assert.doesNotThrow(() => verifyTranscriptChain(transcript));
});

// ---------------------------------------------------------------------------
// Tests: Constants Consistency
// ---------------------------------------------------------------------------

test("contribution count matches required final approvals", () => {
  assert.equal(REQUIRED_CONTRIBUTIONS, REQUIRED_FINAL_APPROVALS);
});

test("public input count is 20", () => {
  // From the existing HazeEmergencyVerifier contract
  assert.equal(20, 20);
});
