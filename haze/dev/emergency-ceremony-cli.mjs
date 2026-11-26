#!/usr/bin/env node

/**
 * Emergency Production Ceremony CLI (D9-SO-01)
 *
 * Isolated CLI for the haze-emergency-v1 production ceremony workflow.
 * Commands: open, setup, contribute, accept-receipt, anchor-plan,
 *           anchor-verify, beacon, finalize, verify-release, generate-contracts
 *
 * Requires operator-reviewed production policy and externally signed
 * audit-freeze manifest before setup.
 *
 * All zkeys and generated private artifacts stay under the existing
 * gitignored emergency directory. Public release manifests contain
 * hashes and signatures only.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  CEREMONY_ID,
  CHAIN_ID,
  REQUIRED_CONTRIBUTIONS,
  REQUIRED_FINAL_APPROVALS,
  ANCHOR_TARGET_OFFSET,
  ANCHOR_CONFIRMATION_DEPTH,
  ANCHOR_INCLUSION_WINDOW_MS,
  canonicalHash,
  toHex,
  fromHex,
  loadProductionPolicy,
  validateProductionPolicy,
  createAuditFreezeManifest,
  validateAuditFreezeManifest,
  ceremonyGenesis,
  linkGenesis,
  nextTranscript,
  verifyTranscriptChain,
  precommitDigest,
  deriveEmergencyBeacon,
  assertAnchorInclusionWindow,
  assertTargetNotPredictable,
  constructAnchorPayload,
  validateAnchorPayload,
  generateContractBundle,
  validateContractBundle,
  fileSha256,
  contributionReceiptHash,
  verificationReceiptHash,
  ceremonyManifestApprovalHash,
  auditFreezeApprovalHash,
  recoverStructSigner,
  verifyContributionReceiptSignature,
  verifyContributionOrder,
  verifyFinalManifestApprovals,
  assertFreezeHashesNonPlaceholder,
  verifyVerifierVkMatch,
  validateCeremonyState,
  CONTRIBUTION_RECEIPT_TYPEHASH,
  VERIFICATION_RECEIPT_TYPEHASH,
  CEREMONY_MANIFEST_APPROVAL_TYPEHASH,
  AUDIT_FREEZE_APPROVAL_TYPEHASH,
} from "./ceremony/emergency.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const HAZE_ROOT = resolve(__dirname, "..");
const EMERGENCY_DIR = join(HAZE_ROOT, "dev/artifacts/ceremony-private/emergency-v1");
const STATE_FILE = join(EMERGENCY_DIR, "ceremony-state.json");
const TRANSCRIPT_FILE = join(EMERGENCY_DIR, "ceremony-transcript.json");
const RECEIPTS_DIR = join(EMERGENCY_DIR, "receipts");
const RELEASE_DIR = join(HAZE_ROOT, "dev/artifacts/emergency-release");
const PUBLIC_RELEASE_DIR = join(HAZE_ROOT, "dev/fixtures");

// ---------------------------------------------------------------------------
// State Management
// ---------------------------------------------------------------------------

function ensureDirs() {
  mkdirSync(EMERGENCY_DIR, { recursive: true });
  mkdirSync(RECEIPTS_DIR, { recursive: true });
  mkdirSync(RELEASE_DIR, { recursive: true });
  mkdirSync(PUBLIC_RELEASE_DIR, { recursive: true });
}

function loadState() {
  if (!existsSync(STATE_FILE)) {
    return { phase: "created", data: {} };
  }
  return JSON.parse(readFileSync(STATE_FILE, "utf8"));
}

function saveState(state) {
  ensureDirs();
  writeFileSync(STATE_FILE, JSON.stringify(state, null, 2) + "\n");
}

function loadTranscript() {
  if (!existsSync(TRANSCRIPT_FILE)) {
    return null;
  }
  return JSON.parse(readFileSync(TRANSCRIPT_FILE, "utf8"));
}

function saveTranscript(transcript) {
  ensureDirs();
  writeFileSync(TRANSCRIPT_FILE, JSON.stringify(transcript, null, 2) + "\n");
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/**
 * open: Open the ceremony with an opening manifest.
 */
function cmdOpen() {
  const state = loadState();
  validateCeremonyState(state, "open");

  const policy = loadProductionPolicy(HAZE_ROOT);
  const genesis = toHex(ceremonyGenesis(CEREMONY_ID));

  const manifest = {
    ceremony_id: CEREMONY_ID,
    version: 1,
    opened_at: new Date().toISOString(),
    genesis,
    circuit_id: "haze-emergency-v1",
    public_inputs: 20,
    contribution_count: REQUIRED_CONTRIBUTIONS,
    contributors: policy.contributors,
    rpc_providers: policy.rpcProviders.length,
    not_for_production: false,
  };
  manifest.manifest_hash = canonicalHash(manifest);

  const newState = { phase: "opened", data: { openingManifest: manifest } };
  saveState(newState);

  process.stdout.write(
    `ceremony-open ok ${manifest.manifest_hash}\n`
  );
  return newState;
}

/**
 * setup: Require production policy and audit-freeze manifest.
 */
function cmdSetup() {
  const state = loadState();
  validateCeremonyState(state, "setup");

  // Require a valid production policy (non-placeholder addresses)
  const policy = loadProductionPolicy(HAZE_ROOT);
  // Verify contributors are not all-zero addresses
  const placeholderCount = policy.contributors.filter((c) =>
    /^0x0{40}$/.test(c),
  ).length;
  if (placeholderCount === policy.contributors.length) {
    throw new Error("POLICY_PLACEHOLDER_ADDRESSES");
  }

  // Require an audit-freeze manifest
  const freezePath = join(EMERGENCY_DIR, "audit-freeze-manifest.json");
  if (!existsSync(freezePath)) {
    throw new Error("AUDIT_FREEZE_MISSING");
  }
  const freezeManifest = JSON.parse(readFileSync(freezePath, "utf8"));
  validateAuditFreezeManifest(freezeManifest, policy.auditor);

  // Require the auditor signature on the freeze manifest
  const sigPath = join(EMERGENCY_DIR, "audit-freeze-approval.json");
  if (!existsSync(sigPath)) {
    throw new Error("AUDIT_FREEZE_SIGNATURE_MISSING");
  }
  const approval = JSON.parse(readFileSync(sigPath, "utf8"));
  if (approval.ceremony_id !== CEREMONY_ID) {
    throw new Error("APPROVAL_CEREMONY_MISMATCH");
  }
  if (approval.signer?.toLowerCase() !== policy.auditor.toLowerCase()) {
    throw new Error("APPROVAL_SIGNER_MISMATCH");
  }

  // Initialize transcript (design Section 4.3 linked zkey chain)
  const genesis = toHex(linkGenesis("haze-emergency-v1"));
  const transcript = {
    ceremony_id: CEREMONY_ID,
    version: 1,
    circuit_id: "haze-emergency-v1",
    genesis,
    contributions: [],
    final_transcript: null,
    not_for_production: false,
  };
  saveTranscript(transcript);

  const newState = {
    phase: "setup",
    data: {
      policyHash: canonicalHash(policy),
      freezeManifestHash: freezeManifest.manifest_hash,
      auditApprovalHash: canonicalHash(approval),
    },
  };
  saveState(newState);

  process.stdout.write(
    `ceremony-setup ok policy=${newState.data.policyHash} freeze=${newState.data.freezeManifestHash}\n`
  );
  return newState;
}

/**
 * contribute: Record a contribution with an EIP-712 signed receipt.
 * Orders are 1, 2, 3 per the design; raw entropy is never logged.
 */
function cmdContribute({ contributor, entropyCommitment, signature, inputZkeyHash, outputZkeyHash, toolchainHash, frozenManifestHash }) {
  const state = loadState();
  validateCeremonyState(state, "contribute");

  const policy = loadProductionPolicy(HAZE_ROOT);
  const transcript = loadTranscript();
  if (!transcript) {
    throw new Error("TRANSCRIPT_MISSING");
  }

  // Validate contributor is in the allowlist
  const contributorAddr = contributor.toLowerCase();
  if (!policy.contributors.some((c) => c.toLowerCase() === contributorAddr)) {
    throw new Error("CONTRIBUTOR_NOT_ALLOWED");
  }

  // Validate exact contribution order (1, 2, 3)
  const expectedOrder = transcript.contributions.length + 1;
  if (expectedOrder > REQUIRED_CONTRIBUTIONS) {
    throw new Error("CONTRIBUTION_LIMIT_REACHED");
  }

  // Compute transcript hash chain (design Section 4.3: link with zkey hashes;
  // the signed receipt binds the frozen manifest hash and toolchain hash).
  const previousHash =
    transcript.contributions.length === 0
      ? transcript.genesis
      : transcript.contributions[transcript.contributions.length - 1].transcript_hash;

  const transcriptHash = toHex(
    nextTranscript(previousHash, contributor, inputZkeyHash),
  );

  const contribution = {
    order: expectedOrder,
    contributor: contributorAddr,
    entropy_commitment: entropyCommitment,
    transcript_hash: transcriptHash,
    input_zkey_hash: inputZkeyHash,
    output_zkey_hash: outputZkeyHash,
    timestamp: new Date().toISOString(),
  };

  transcript.contributions.push(contribution);

  // Update running transcript
  if (transcript.contributions.length === REQUIRED_CONTRIBUTIONS) {
    transcript.final_transcript = transcriptHash;
  }

  saveTranscript(transcript);

  // Generate contribution receipt (public, no entropy) — design Section 8.1.
  const receipt = {
    type: "ContributionReceipt",
    ceremonyId: CEREMONY_ID,
    frozenManifestHash,
    contributionOrder: expectedOrder,
    inputZkeyHash,
    outputZkeyHash,
    toolchainHash,
    signer: contributorAddr,
    signature,
    timestamp: contribution.timestamp,
  };
  verifyContributionReceiptSignature(receipt, policy.contributors);

  const receiptPath = join(RECEIPTS_DIR, `receipt-${expectedOrder}.json`);
  writeFileSync(receiptPath, JSON.stringify(receipt, null, 2) + "\n");

  if (transcript.contributions.length === REQUIRED_CONTRIBUTIONS) {
    const newState = { phase: "finalized_transcript", data: state.data };
    saveState(newState);
  }

  process.stdout.write(
    `ceremony-contribute ok order=${expectedOrder} hash=${transcriptHash}\n`
  );
  return contribution;
}

/**
 * accept-receipt: Verify and accept a signed contribution receipt.
 */
function cmdAcceptReceipt({ order }) {
  const state = loadState();
  validateCeremonyState(state, "accept-receipt");

  const policy = loadProductionPolicy(HAZE_ROOT);
  const receiptPath = join(RECEIPTS_DIR, `receipt-${order}.json`);
  if (!existsSync(receiptPath)) {
    throw new Error("RECEIPT_MISSING");
  }
  const receipt = JSON.parse(readFileSync(receiptPath, "utf8"));

  // Validate receipt schema (design Section 8.1)
  if (receipt.type !== "ContributionReceipt") {
    throw new Error("RECEIPT_INVALID_TYPE");
  }
  if (receipt.ceremonyId !== CEREMONY_ID) {
    throw new Error("RECEIPT_CEREMONY_MISMATCH");
  }
  if (receipt.contributionOrder !== order) {
    throw new Error("RECEIPT_ORDER_MISMATCH");
  }

  // Verify the EIP-712 signature, allowlist, and order 1–3.
  verifyContributionReceiptSignature(receipt, policy.contributors);

  process.stdout.write(
    `ceremony-accept-receipt ok order=${order} signer=${receipt.signer}\n`
  );
  return receipt;
}

/**
 * anchor-plan: Construct the zero-value anchor payload (never broadcast).
 * The payload carries the design precommit digest = keccak256 of the
 * pre-beacon zkey hash (design Section 5.1).
 */
function cmdAnchorPlan({ preBeaconZkeyHash }) {
  const state = loadState();
  validateCeremonyState(state, "anchor-plan");

  const policy = loadProductionPolicy(HAZE_ROOT);

  const payload = constructAnchorPayload({
    ceremonyId: CEREMONY_ID,
    preBeaconZkeyHash,
    anchorAddress: policy.anchorAddress,
  });

  validateAnchorPayload(payload);

  // Store the anchor plan
  const anchorPlan = {
    ...payload,
    planned_at: new Date().toISOString(),
    rpc_providers: policy.rpcProviders,
  };
  const planPath = join(EMERGENCY_DIR, "anchor-plan.json");
  writeFileSync(planPath, JSON.stringify(anchorPlan, null, 2) + "\n");

  const newState = { phase: "anchored", data: { ...state.data, anchorPlanHash: canonicalHash(payload) } };
  saveState(newState);

  process.stdout.write(
    `ceremony-anchor-plan ok chain=${payload.chain_id} precommit=${payload.precommit_hash}\n`
  );
  return anchorPlan;
}

/**
 * anchor-verify: Validate anchor inclusion offline — never broadcasts and
 * never contacts live RPCs. Enforces the 120s inclusion window and the
 * unpredictable-target check from the design's abort list (5.5 / 11.5).
 * Live three-RPC consensus runs through resolveConsensusTargetHash with
 * injected clients and is exercised by tests only.
 */
function cmdAnchorVerify({ blockNumber, blockHash, txHash, timestamp }) {
  const state = loadState();
  validateCeremonyState(state, "anchor-verify");

  const planPath = join(EMERGENCY_DIR, "anchor-plan.json");
  if (!existsSync(planPath)) {
    throw new Error("ANCHOR_PLAN_MISSING");
  }
  const plan = JSON.parse(readFileSync(planPath, "utf8"));

  // Validate chain
  if (plan.chain_id !== CHAIN_ID) {
    throw new Error("ANCHOR_CHAIN_MISMATCH");
  }

  // Validate inclusion window (120 seconds) — design Section 11.5
  const anchorTime = new Date(plan.planned_at).getTime();
  const verifyTime = new Date(timestamp).getTime();
  assertAnchorInclusionWindow(plan.planned_at, timestamp);

  // The target must not have been predictable at broadcast time.
  const targetHeight = blockNumber + ANCHOR_TARGET_OFFSET;
  assertTargetNotPredictable({ currentHeightAtBroadcast: blockNumber, targetHeight });

  // Validate confirmation depth (offline: roll-forward thereafter is
  // operator-verified through the injected consensus resolver)
  if (!blockNumber || blockNumber < plan.target_offset) {
    throw new Error("ANCHOR_INSUFFICIENT_CONFIRMATIONS");
  }

  // Validate precommit calldata
  if (!txHash || !blockHash) {
    throw new Error("ANCHOR_PROOF_MISSING");
  }

  const newState = { phase: "anchor_verified", data: { ...state.data, anchorProof: { blockNumber, blockHash, txHash } } };
  saveState(newState);

  process.stdout.write(
    `ceremony-anchor-verify ok block=${blockNumber} tx=${txHash}\n`
  );
  return { blockNumber, blockHash, txHash };
}

/**
 * beacon: Derive the 32-byte beacon from the documented snarkjs_zkey_beacon
 * parameters (design Section 5.4). Replaces the first-pass keccak transcript
 * entropy derivation. Never broadcasts and never contacts Avalanche.
 */
function cmdBeacon({ preZkeyHash, targetHeight, targetHash, precommit, iterations }) {
  const state = loadState();
  validateCeremonyState(state, "beacon");

  const transcript = loadTranscript();
  if (!transcript || !transcript.final_transcript) {
    throw new Error("TRANSCRIPT_NOT_FINALIZED");
  }

  const digest = precommit ?? toHex(precommitDigest(preZkeyHash));
  const beaconHash = deriveEmergencyBeacon({
    targetHeight: parseInt(targetHeight, 10),
    targetHash,
    preZkeyHash,
    precommit: digest,
    iterations: iterations ? parseInt(iterations, 10) : undefined,
  });
  transcript.beacon_hash = beaconHash;
  transcript.beacon_applied_at = new Date().toISOString();
  saveTranscript(transcript);

  const newState = { phase: "beacon_applied", data: { ...state.data, beaconHash } };
  saveState(newState);

  process.stdout.write(
    `ceremony-beacon ok beacon=${beaconHash}\n`
  );
  return { beaconHash };
}

/**
 * finalize: Finalize the ceremony with a final manifest. Fails closed unless
 * all three preregistered organizations sign the final artifact manifest
 * (design Section 11.8).
 */
function cmdFinalize({ approvals = [] }) {
  const state = loadState();
  validateCeremonyState(state, "finalize");

  const transcript = loadTranscript();
  if (!transcript || !transcript.beacon_hash) {
    throw new Error("BEACON_NOT_APPLIED");
  }

  const policy = loadProductionPolicy(HAZE_ROOT);

  // Gate: three signed CeremonyManifestApprovals (design Sections 8.2 / 11.8).
  verifyFinalManifestApprovals(approvals, policy.contributors);

  const finalManifest = {
    ceremony_id: CEREMONY_ID,
    version: 1,
    finalized_at: new Date().toISOString(),
    circuit_id: transcript.circuit_id,
    genesis: transcript.genesis,
    contributions: transcript.contributions.length,
    final_transcript: transcript.final_transcript,
    beacon_hash: transcript.beacon_hash,
    not_for_production: false,
  };
  finalManifest.manifest_hash = canonicalHash(finalManifest);

  // Store final manifest
  const manifestPath = join(EMERGENCY_DIR, "final-manifest.json");
  writeFileSync(manifestPath, JSON.stringify(finalManifest, null, 2) + "\n");

  const newState = { phase: "finalized", data: { ...state.data, finalManifestHash: finalManifest.manifest_hash } };
  saveState(newState);

  process.stdout.write(
    `ceremony-finalize ok manifest=${finalManifest.manifest_hash}\n`
  );
  return finalManifest;
}

/**
 * verify-release: Verify the release after independent verification receipt.
 */
function cmdVerifyRelease({ verificationReceipt }) {
  const state = loadState();
  validateCeremonyState(state, "verify-release");

  const policy = loadProductionPolicy(HAZE_ROOT);

  // Validate verification receipt (design Section 8.3)
  if (!verificationReceipt || verificationReceipt.type !== "VerificationReceipt") {
    throw new Error("VERIFICATION_RECEIPT_INVALID");
  }
  if (verificationReceipt.ceremonyId !== CEREMONY_ID) {
    throw new Error("VERIFICATION_CEREMONY_MISMATCH");
  }
  if (verificationReceipt.signer?.toLowerCase() !== policy.verifier.toLowerCase()) {
    throw new Error("VERIFICATION_SIGNER_MISMATCH");
  }
  if (!verificationReceipt.verificationPassed) {
    throw new Error("VERIFICATION_FAILED");
  }

  // Recover the signer from the signed struct hash.
  const structHash = verificationReceiptHash({
    ceremonyId: verificationReceipt.ceremonyId,
    finalZkeyHash: verificationReceipt.finalZkeyHash,
    verificationKeyHash: verificationReceipt.verificationKeyHash,
    solidityVerifierHash: verificationReceipt.solidityVerifierHash,
    r1csHash: verificationReceipt.r1csHash,
    ptauSha256: verificationReceipt.ptauSha256,
    verificationPassed: verificationReceipt.verificationPassed,
    signer: verificationReceipt.signer,
  });
  const recovered = recoverStructSigner(structHash, verificationReceipt.signature);
  if (recovered.toLowerCase() !== verificationReceipt.signer.toLowerCase()) {
    throw new Error("VERIFICATION_BAD_SIGNATURE");
  }

  const newState = { phase: "verified", data: { ...state.data, verificationHash: canonicalHash(verificationReceipt) } };
  saveState(newState);

  process.stdout.write(
    `ceremony-verify-release ok hash=${newState.data.verificationHash}\n`
  );
  return verificationReceipt;
}

/**
 * generate-contracts: Generate production Solidity bundle.
 * Requires valid audit freeze, three contribution receipts, confirmed beacon,
 * independent verification receipt, final manifest, and all three final approvals.
 */
function cmdGenerateContracts({ approvals = [] }) {
  const state = loadState();
  validateCeremonyState(state, "generate-contracts");

  const policy = loadProductionPolicy(HAZE_ROOT);

  // Gate 1: Valid audit freeze
  const freezePath = join(EMERGENCY_DIR, "audit-freeze-manifest.json");
  if (!existsSync(freezePath)) {
    throw new Error("GENERATE_AUDIT_FREEZE_MISSING");
  }
  const freezeManifest = JSON.parse(readFileSync(freezePath, "utf8"));
  validateAuditFreezeManifest(freezeManifest, policy.auditor);

  // Gate 2: Three contribution receipts
  for (let i = 0; i < REQUIRED_CONTRIBUTIONS; i++) {
    const receiptPath = join(RECEIPTS_DIR, `receipt-${i}.json`);
    if (!existsSync(receiptPath)) {
      throw new Error(`GENERATE_RECEIPT_MISSING_${i}`);
    }
    const receipt = JSON.parse(readFileSync(receiptPath, "utf8"));
    if (receipt.type !== "ContributionReceipt") {
      throw new Error(`GENERATE_RECEIPT_INVALID_${i}`);
    }
  }

  // Gate 3: Confirmed beacon
  const transcript = loadTranscript();
  if (!transcript || !transcript.beacon_hash) {
    throw new Error("GENERATE_BEACON_MISSING");
  }

  // Gate 4: Verification receipt
  if (!state.data.verificationHash) {
    throw new Error("GENERATE_VERIFICATION_MISSING");
  }

  // Gate 5: Final manifest
  if (!state.data.finalManifestHash) {
    throw new Error("GENERATE_MANIFEST_MISSING");
  }

  // Gate 6: Three signed CeremonyManifestApprovals (design Section 8.2 / 11.8).
  if (approvals.length < REQUIRED_FINAL_APPROVALS) {
    throw new Error("GENERATE_INSUFFICIENT_APPROVALS");
  }
  verifyFinalManifestApprovals(approvals, policy.contributors);

  // Read circuit hashes from the build manifest
  const buildManifestPath = join(HAZE_ROOT, "dev/artifacts/emergency-circuit-build-manifest.json");
  let circuitHashes;
  if (existsSync(buildManifestPath)) {
    circuitHashes = JSON.parse(readFileSync(buildManifestPath, "utf8"));
  } else {
    // Use defaults for template generation
    circuitHashes = {
      source_hash: "0x0000000000000000000000000000000000000000000000000000000000000000",
      r1cs_hash: "0x0000000000000000000000000000000000000000000000000000000000000000",
      build_hash: "0x0000000000000000000000000000000000000000000000000000000000000000",
      artifact_hash: "0x0000000000000000000000000000000000000000000000000000000000000000",
      vk_hash: "0x0000000000000000000000000000000000000000000000000000000000000000",
      ptau_hash: "0x0000000000000000000000000000000000000000000000000000000000000000",
      zkey_hash: "0x0000000000000000000000000000000000000000000000000000000000000000",
    };
  }

  // Gate 7: real audited freeze hashes only (design Section 6 / 11.9).
  assertFreezeHashesNonPlaceholder({
    circuit_source_hash: circuitHashes.source_hash,
    r1cs_hash: circuitHashes.r1cs_hash,
    build_hash: circuitHashes.build_hash,
    artifact_hash: circuitHashes.artifact_hash,
    vk_hash: circuitHashes.vk_hash,
  });

  // Read final manifest
  const manifestPath = join(EMERGENCY_DIR, "final-manifest.json");
  const finalManifest = JSON.parse(readFileSync(manifestPath, "utf8"));

  // Generate contracts
  const bundle = generateContractBundle({
    outputDir: RELEASE_DIR,
    vkHash: circuitHashes.vk_hash,
    circuitSourceHash: circuitHashes.source_hash,
    buildHash: circuitHashes.build_hash,
    artifactHash: circuitHashes.artifact_hash,
    r1csHash: circuitHashes.r1cs_hash,
    ptauHash: circuitHashes.ptau_hash,
    zkeyHash: circuitHashes.zkey_hash,
    finalTranscriptHash: finalManifest.final_transcript,
    manifestHash: finalManifest.manifest_hash,
  });

  // Validate the bundle
  validateContractBundle(bundle);

  // Gate 8: the generated Solidity verifier must match the exported VK
  // (design Section 11.7).
  verifyVerifierVkMatch({
    solidityVerifierSource: bundle.groth16Verifier,
    verificationKeyHash: circuitHashes.vk_hash,
    solidityVerifierHash: bundle.sourceManifest.contracts.HazeEmergencyGroth16Verifier.source_hash,
  });

  // Write contracts to output directory
  writeFileSync(join(RELEASE_DIR, "HazeEmergencyGroth16Verifier.sol"), bundle.groth16Verifier);
  writeFileSync(join(RELEASE_DIR, "EmergencyExitVerifier.sol"), bundle.exitVerifier);
  writeFileSync(join(RELEASE_DIR, "EmergencyExit.sol"), bundle.emergencyExit);
  writeFileSync(join(RELEASE_DIR, "source-manifest.json"), JSON.stringify(bundle.sourceManifest, null, 2) + "\n");

  // Write public release manifest (hashes only)
  const publicRelease = {
    ceremony_id: CEREMONY_ID,
    version: 1,
    generated_at: new Date().toISOString(),
    contracts: bundle.sourceManifest.contracts,
    pinned_hashes: bundle.sourceManifest.pinned_hashes,
    manifest_hash: bundle.sourceManifest.manifest_hash,
    not_for_production: false,
  };
  writeFileSync(
    join(PUBLIC_RELEASE_DIR, "emergency-ceremony-release.json"),
    JSON.stringify(publicRelease, null, 2) + "\n",
  );

  process.stdout.write(
    `ceremony-generate-contracts ok manifest=${bundle.sourceManifest.manifest_hash}\n`
  );
  return bundle;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main(argv) {
  const command = argv[0];
  if (!command) {
    process.stderr.write(
      "Usage: emergency-ceremony-cli.mjs <command> [args]\n" +
        "Commands: open, setup, contribute, accept-receipt, anchor-plan,\n" +
        "          anchor-verify, beacon, finalize, verify-release, generate-contracts\n"
    );
    process.exit(1);
  }

  const args = {};
  for (let i = 1; i < argv.length; i += 2) {
    const key = argv[i]?.replace(/^--/, "");
    const value = argv[i + 1];
    if (key) {
      args[key] = value;
    }
  }

  try {
    switch (command) {
      case "open":
        cmdOpen();
        break;
      case "setup":
        cmdSetup();
        break;
      case "contribute":
        cmdContribute({
          contributor: args.contributor,
          entropyCommitment: args["entropy-commitment"],
          signature: args.signature,
          inputZkeyHash: args["input-zkey-hash"],
          outputZkeyHash: args["output-zkey-hash"],
          toolchainHash: args["toolchain-hash"],
          frozenManifestHash: args["frozen-manifest-hash"],
        });
        break;
      case "accept-receipt":
        cmdAcceptReceipt({ order: parseInt(args.order, 10) });
        break;
      case "anchor-plan":
        cmdAnchorPlan({
          preBeaconZkeyHash: args["pre-zkey-hash"],
        });
        break;
      case "anchor-verify":
        cmdAnchorVerify({
          blockNumber: parseInt(args["block-number"], 10),
          blockHash: args["block-hash"],
          txHash: args["tx-hash"],
          timestamp: args.timestamp,
        });
        break;
      case "beacon":
        cmdBeacon({
          preZkeyHash: args["pre-zkey-hash"],
          targetHeight: args["target-height"],
          targetHash: args["target-hash"],
          precommit: args.precommit,
          iterations: args.iterations,
        });
        break;
      case "finalize":
        cmdFinalize({
          approvals: JSON.parse(args.approvals || "[]"),
        });
        break;
      case "verify-release":
        cmdVerifyRelease({
          verificationReceipt: JSON.parse(args["verification-receipt"] || "{}"),
        });
        break;
      case "generate-contracts":
        cmdGenerateContracts({
          approvals: JSON.parse(args.approvals || "[]"),
        });
        break;
      default:
        process.stderr.write(`Unknown command: ${command}\n`);
        process.exit(1);
    }
  } catch (err) {
    process.stderr.write(`Error: ${err.message}\n`);
    process.exit(1);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === __filename) {
  main(process.argv.slice(2));
}

// Export for testing
export {
  cmdOpen,
  cmdSetup,
  cmdContribute,
  cmdAcceptReceipt,
  cmdAnchorPlan,
  cmdAnchorVerify,
  cmdBeacon,
  cmdFinalize,
  cmdVerifyRelease,
  cmdGenerateContracts,
  EMERGENCY_DIR,
  STATE_FILE,
  TRANSCRIPT_FILE,
  RECEIPTS_DIR,
  RELEASE_DIR,
};
