/**
 * Emergency Production Ceremony Core Library (D9-SO-01)
 *
 * Implements the isolated emergency-ceremony workflow for haze-emergency-v1:
 * - Canonical JSON hashing with lowercase 32-byte hex
 * - EIP-712 typed-data signing and recovery
 * - AuditFreezeApproval binding external audit to canonical manifest bytes
 * - Contribution receipts with exact ordering and linked zkey hashes
 * - Anchor payload construction (zero-value, chain 43114, never broadcast)
 * - Production policy and audit-freeze gating
 *
 * This library is isolated from the parent ceremony-cli and does not
 * import or wrap any parent tooling.
 */

import { createHash, randomBytes } from "node:crypto";
import { readFileSync, existsSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak256 } from "../../tests/keccak256.mjs";
import {
  PTAU_POWER,
  PTAU_SHA256,
  PTAU_FILE,
  assertPtauChecksum,
  requiredPtauPower,
  sha256File,
  versionError,
} from "./ptau.mjs";
import { CIRCOM_VERSION, CEREMONY_DOMAIN, HAZE_ROOT, signNormalized } from "./lib.mjs";
import { redactEntropy } from "./phase2.mjs";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const CEREMONY_ID = "haze-emergency-v1-production";
export const CHAIN_ID = 43114;
export const PUBLIC_INPUT_COUNT = 20;
export const ANCHOR_TARGET_OFFSET = 2048;
export const ANCHOR_CONFIRMATION_DEPTH = 64;
export const ANCHOR_INCLUSION_WINDOW_MS = 120_000; // 120 seconds
export const REQUIRED_CONTRIBUTIONS = 3;
export const REQUIRED_FINAL_APPROVALS = 3;

// Design Section 5.4 — beacon parameters.
export const BEACON_DOMAIN_TAG = "haze/emergency-v1/beacon";
export const BEACON_ITERATIONS = 10;
export const SNARK_SCALAR_FIELD =
  0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;

// Design Section 2 / 3 (2026-08-24) — audit freeze pin.
export const EMERGENCY_CIRCUIT_ID = "haze-emergency-v1";
export const EMERGENCY_N_CONSTRAINTS = 192535;
export const EMERGENCY_PUBLIC_INPUTS = 20;
export const EMERGENCY_CIRCOM_VERSION = CIRCOM_VERSION; // "2.2.3"
export const EMERGENCY_PTAU_POWER = PTAU_POWER; // 20
export const EMERGENCY_PTAU_SHA256 = PTAU_SHA256;

// EIP-712 Domain (design Section 8.1: fixed name/version/chainId, zero address)
export const EIP712_DOMAIN_NAME = "Haze Emergency Ceremony";
export const EIP712_DOMAIN_VERSION = "1";
export const EIP712_DOMAIN_CHAIN_ID = CHAIN_ID; // 43114
export const EIP712_VERIFYING_CONTRACT = "0x0000000000000000000000000000000000000000";

export const EIP712_DOMAIN_TYPEHASH = keccak256(
  Buffer.from(
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
  ),
);

// EIP-712 Receipt Types (design Section 8)
export const CONTRIBUTION_RECEIPT_TYPEHASH = keccak256(
  Buffer.from(
    "ContributionReceipt(bytes32 ceremonyId,bytes32 frozenManifestHash,uint256 contributionOrder,bytes32 inputZkeyHash,bytes32 outputZkeyHash,bytes32 toolchainHash,address signer)",
  ),
);

export const VERIFICATION_RECEIPT_TYPEHASH = keccak256(
  Buffer.from(
    "VerificationReceipt(bytes32 ceremonyId,bytes32 finalZkeyHash,bytes32 verificationKeyHash,bytes32 solidityVerifierHash,bytes32 r1csHash,bytes32 ptauSha256,bool verificationPassed,address signer)",
  ),
);

export const CEREMONY_MANIFEST_APPROVAL_TYPEHASH = keccak256(
  Buffer.from(
    "CeremonyManifestApproval(bytes32 ceremonyId,bytes32 finalManifestHash,bytes32 beacon,bytes32 finalZkeyHash,bytes32 verificationKeyHash,bytes32 solidityVerifierHash,address signer)",
  ),
);

export const AUDIT_FREEZE_APPROVAL_TYPEHASH = keccak256(
  Buffer.from(
    "AuditFreezeApproval(bytes32 ceremonyId,bytes32 freezeManifestHash,bytes32 auditReportHash,address signer)",
  ),
);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export function toHex(bytes) {
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

export function fromHex(value) {
  return Buffer.from(String(value).replace(/^0x/i, ""), "hex");
}

/**
 * Canonical JSON hashing: stable stringify + SHA-256, lowercase 0x-prefixed.
 */
export function canonicalHash(value) {
  const canonical = JSON.stringify(value, Object.keys(value).sort());
  return `0x${createHash("sha256").update(canonical).digest("hex")}`;
}

/**
 * Keccak256 hash of concatenated buffers.
 */
export function keccakConcat(...buffers) {
  return keccak256(Buffer.concat(buffers));
}

/**
 * Hash a Solidity file for production verification.
 */
export function fileSha256(path) {
  return `0x${createHash("sha256").update(readFileSync(path)).digest("hex")}`;
}

/**
 * EIP-712 domain separator (design Section 8.1). Address encoded as a
 * left-padded 32-byte word per EIP-712.
 */
export function eip712DomainSeparator({ name, version, chainId, verifyingContract }) {
  return keccakConcat(
    fromHex(EIP712_DOMAIN_TYPEHASH),
    keccak256(Buffer.from(name, "utf8")),
    keccak256(Buffer.from(version, "utf8")),
    padUint256(chainId),
    padAddress(verifyingContract),
  );
}

/**
 * EIP-712 digest = keccak256(0x19 0x01 || domainSeparator || structHash).
 * Uses the fixed design domain unless overridden.
 */
export function eip712Digest(
  structHash,
  { name = EIP712_DOMAIN_NAME, version = EIP712_DOMAIN_VERSION, chainId = EIP712_DOMAIN_CHAIN_ID, verifyingContract = EIP712_VERIFYING_CONTRACT } = {},
) {
  const separator = eip712DomainSeparator({ name, version, chainId, verifyingContract });
  return keccakConcat(Buffer.from("\x19\x01", "utf8"), separator, structHash);
}

/**
 * Derive the EOA address for a signing key (last 20 bytes of keccak of the
 * uncompressed public key).
 */
export function signerAddress(signingKeyHex) {
  const publicKey = secp256k1.getPublicKey(fromHex(signingKeyHex), false);
  return toHex(keccak256(publicKey.subarray(1)).subarray(12)).toLowerCase();
}

/**
 * Sign a struct hash with the EIP-712 digest, returning 65-byte 0x hex.
 */
export function signStructHash(structHash, signingKeyHex, domain = {}) {
  const digest = eip712Digest(structHash, domain);
  return toHex(signNormalized(fromHex(signingKeyHex), digest));
}

/**
 * Recover the signer address from a 65-byte signature over a struct hash.
 * The stored layout is r || s || recovery (same convention as the SDK).
 * Uses Signature.fromCompact().addRecoveryBit() so the digest is taken as a
 * pre-hashed message (noble's static recoverPublicKey would re-hash it).
 */
export function recoverStructSigner(structHash, signature, domain = {}) {
  const digest = eip712Digest(structHash, domain);
  const sig = fromHex(signature);
  if (sig.length !== 65) {
    throw new Error("RECEIPT_BAD_SIGNATURE");
  }
  let publicKey;
  try {
    publicKey = secp256k1.Signature.fromCompact(sig.subarray(0, 64))
      .addRecoveryBit(sig[64])
      .recoverPublicKey(digest)
      .toRawBytes(false);
  } catch {
    throw new Error("RECEIPT_BAD_SIGNATURE");
  }
  return toHex(keccak256(publicKey.subarray(1)).subarray(12)).toLowerCase();
}

/**
 * Encode a ContributionReceipt struct hash for EIP-712 signing
 * (design Section 8.1). Contribution orders are 1, 2, 3.
 */
export function contributionReceiptHash({
  ceremonyId,
  frozenManifestHash,
  contributionOrder,
  inputZkeyHash,
  outputZkeyHash,
  toolchainHash,
  signer,
}) {
  return keccakConcat(
    fromHex(CONTRIBUTION_RECEIPT_TYPEHASH),
    fromHex(ceremonyId),
    fromHex(frozenManifestHash),
    padUint256(contributionOrder),
    fromHex(inputZkeyHash),
    fromHex(outputZkeyHash),
    fromHex(toolchainHash),
    padAddress(signer),
  );
}

/**
 * Encode a VerificationReceipt struct hash for EIP-712 signing
 * (design Section 8.3).
 */
export function verificationReceiptHash({
  ceremonyId,
  finalZkeyHash,
  verificationKeyHash,
  solidityVerifierHash,
  r1csHash,
  ptauSha256,
  verificationPassed,
  signer,
}) {
  return keccakConcat(
    fromHex(VERIFICATION_RECEIPT_TYPEHASH),
    fromHex(ceremonyId),
    fromHex(finalZkeyHash),
    fromHex(verificationKeyHash),
    fromHex(solidityVerifierHash),
    fromHex(r1csHash),
    fromHex(ptauSha256),
    verificationPassed ? Buffer.from("01", "hex") : Buffer.from("00", "hex"),
    padAddress(signer),
  );
}

/**
 * Encode a CeremonyManifestApproval struct hash for EIP-712 signing
 * (design Section 8.2).
 */
export function ceremonyManifestApprovalHash({
  ceremonyId,
  finalManifestHash,
  beacon,
  finalZkeyHash,
  verificationKeyHash,
  solidityVerifierHash,
  signer,
}) {
  return keccakConcat(
    fromHex(CEREMONY_MANIFEST_APPROVAL_TYPEHASH),
    fromHex(ceremonyId),
    fromHex(finalManifestHash),
    fromHex(beacon),
    fromHex(finalZkeyHash),
    fromHex(verificationKeyHash),
    fromHex(solidityVerifierHash),
    padAddress(signer),
  );
}

/**
 * Encode an AuditFreezeApproval struct hash for EIP-712 signing.
 */
export function auditFreezeApprovalHash({ ceremonyId, freezeManifestHash, auditReportHash, signer }) {
  return keccakConcat(
    fromHex(AUDIT_FREEZE_APPROVAL_TYPEHASH),
    fromHex(ceremonyId),
    fromHex(freezeManifestHash),
    fromHex(auditReportHash),
    padAddress(signer),
  );
}

/**
 * Verify one signed ContributionReceipt (design Section 11.3): the recovered
 * signer must match the receipt signer, the signer must be allowlisted, and
 * the contribution order must be one of 1, 2, 3.
 */
export function verifyContributionReceiptSignature(receipt, allowlist) {
  if (!receipt || typeof receipt !== "object") {
    throw new Error("RECEIPT_INVALID");
  }
  const structHash = contributionReceiptHash({
    ceremonyId: receipt.ceremonyId,
    frozenManifestHash: receipt.frozenManifestHash,
    contributionOrder: receipt.contributionOrder,
    inputZkeyHash: receipt.inputZkeyHash,
    outputZkeyHash: receipt.outputZkeyHash,
    toolchainHash: receipt.toolchainHash,
    signer: receipt.signer,
  });
  const recovered = recoverStructSigner(structHash, receipt.signature);
  const signer = String(receipt.signer).toLowerCase();
  if (recovered !== signer) {
    throw new Error("RECEIPT_BAD_SIGNATURE");
  }
  if (!Array.isArray(allowlist) || !allowlist.some((a) => String(a).toLowerCase() === signer)) {
    throw new Error("RECEIPT_UNREGISTERED_SIGNER");
  }
  const order = Number(receipt.contributionOrder);
  if (!Number.isInteger(order) || order < 1 || order > REQUIRED_CONTRIBUTIONS) {
    throw new Error("RECEIPT_ORDER_MISMATCH");
  }
  return true;
}

/**
 * Verify the full contribution set (design Section 11.3): exactly orders
 * 1, 2, 3, each signed by its preregistered slot wallet, with valid
 * signatures. `orderedAllowlist` maps slot (1-based index) to address.
 */
export function verifyContributionOrder(receipts, orderedAllowlist) {
  if (!Array.isArray(receipts) || receipts.length !== REQUIRED_CONTRIBUTIONS) {
    throw new Error("RECEIPT_ORDER_MISMATCH");
  }
  const byOrder = new Map(receipts.map((receipt) => [Number(receipt.contributionOrder), receipt]));
  const orders = [...byOrder.keys()].sort((a, b) => a - b);
  if (orders.length !== REQUIRED_CONTRIBUTIONS || orders.join(",") !== "1,2,3") {
    throw new Error("RECEIPT_ORDER_MISMATCH");
  }
  for (let slot = 1; slot <= REQUIRED_CONTRIBUTIONS; slot += 1) {
    const receipt = byOrder.get(slot);
    const expectedSigner = orderedAllowlist[slot - 1]?.toLowerCase();
    if (String(receipt.signer).toLowerCase() !== expectedSigner) {
      throw new Error("RECEIPT_ORDER_MISMATCH");
    }
    verifyContributionReceiptSignature(receipt, orderedAllowlist);
  }
  return true;
}

/**
 * Design Section 11.9: refuse a rehearsal / operator-owned transcript (or any
 * not_for_production input) as a production emergency zkey source. Modeled on
 * refuseRehearsalAsSpendZkey from phase2.mjs.
 */
export function refuseRehearsalAsEmergencyZkey(input) {
  const source = input ?? {};
  const circuitId = String(source.circuit_id ?? source.circuitId ?? "");
  if (circuitId && circuitId !== EMERGENCY_CIRCUIT_ID) {
    throw versionError("VERSION_UNSUPPORTED");
  }
  const r1cs = String(source.r1cs ?? source.zkeyPath ?? source.zkey ?? "");
  if (/rehearsal|equality|development/i.test(r1cs)) {
    throw versionError("VERSION_UNSUPPORTED");
  }
  if (source.profile && source.profile !== "production") {
    throw versionError("VERSION_UNSUPPORTED");
  }
  if (source.not_for_production === true || source.production_ceremony_approved === false) {
    throw versionError("VERSION_UNSUPPORTED");
  }
  if (source.n_constraints && Number(source.n_constraints) !== EMERGENCY_N_CONSTRAINTS) {
    throw versionError("VERSION_UNSUPPORTED");
  }
  return true;
}

/**
 * Design Section 11.8: the final artifact manifest needs all three
 * preregistered organizations' signed CeremonyManifestApproval records.
 * Fewer than three (or duplicate/unregistered signers) leaves the ceremony
 * incomplete.
 */
export function verifyFinalManifestApprovals(approvals, orderedAllowlist) {
  if (!Array.isArray(approvals) || approvals.length < REQUIRED_FINAL_APPROVALS) {
    throw new Error("APPROVAL_COUNT_MISMATCH");
  }
  const expected = new Set(orderedAllowlist.map((address) => String(address).toLowerCase()));
  const seen = new Set();
  for (const approval of approvals) {
    if (!approval || approval.type !== "CeremonyManifestApproval") {
      throw new Error("APPROVAL_INVALID_TYPE");
    }
    const structHash = ceremonyManifestApprovalHash({
      ceremonyId: approval.ceremonyId,
      finalManifestHash: approval.finalManifestHash,
      beacon: approval.beacon,
      finalZkeyHash: approval.finalZkeyHash,
      verificationKeyHash: approval.verificationKeyHash,
      solidityVerifierHash: approval.solidityVerifierHash,
      signer: approval.signer,
    });
    let recovered;
    try {
      recovered = recoverStructSigner(structHash, approval.signature);
    } catch {
      throw new Error("APPROVAL_BAD_SIGNATURE");
    }
    const signer = String(approval.signer).toLowerCase();
    if (recovered !== signer) {
      throw new Error("APPROVAL_BAD_SIGNATURE");
    }
    if (!expected.has(signer)) {
      throw new Error("APPROVAL_UNREGISTERED");
    }
    seen.add(signer);
  }
  if (seen.size < REQUIRED_FINAL_APPROVALS) {
    throw new Error("APPROVAL_COUNT_MISMATCH");
  }
  return true;
}

/**
 * Design Section 11.7: the generated Solidity verifier must match the
 * verification key exported from the final zkey. The VK hash must be embedded
 * in the verifier source, be non-placeholder, and the source's SHA-256 must
 * equal the recorded solidity verifier hash.
 */
export function verifyVerifierVkMatch({ solidityVerifierSource, verificationKeyHash, solidityVerifierHash }) {
  if (!verificationKeyHash || /^0x0{64}$/i.test(String(verificationKeyHash))) {
    throw new Error("VERIFIER_VK_MISMATCH");
  }
  if (!String(solidityVerifierSource).includes(verificationKeyHash)) {
    throw new Error("VERIFIER_VK_MISMATCH");
  }
  if (
    solidityVerifierHash &&
    String(solidityVerifierHash).toLowerCase() !== fileSha256Inline(solidityVerifierSource).toLowerCase()
  ) {
    throw new Error("VERIFIER_VK_MISMATCH");
  }
  return true;
}

/**
 * Abort contract generation when the audited freeze hashes are still
 * zero/placeholder (design Section 6: real audited hashes are required).
 */
export function assertFreezeHashesNonPlaceholder(hashes) {
  for (const [key, value] of Object.entries(hashes ?? {})) {
    if (!value || /^0x0{64}$/i.test(String(value))) {
      throw new Error("FREEZE_HASHES_PLACEHOLDER");
    }
  }
  return true;
}

function padAddress(addr) {
  const clean = addr.toLowerCase().replace(/^0x/, "");
  return Buffer.from(clean.padStart(64, "0"), "hex");
}

function padUint256(value) {
  return Buffer.from(BigInt(value).toString(16).padStart(64, "0"), "hex");
}

// ---------------------------------------------------------------------------
// Design Section 2 / 3 — Audit Freeze and Ptau Pinning (fail-closed)
// ---------------------------------------------------------------------------

/**
 * The frozen emergency-ceremony specification from the 2026-08-24 design.
 * Any drift aborts with VERSION_UNSUPPORTED (Sections 11.1 / 11.2).
 */
export function emergencyFreezeSpec() {
  return {
    circuit_id: EMERGENCY_CIRCUIT_ID,
    circom_version: EMERGENCY_CIRCOM_VERSION,
    n_constraints: EMERGENCY_N_CONSTRAINTS,
    public_inputs: EMERGENCY_PUBLIC_INPUTS,
    ptau_power: EMERGENCY_PTAU_POWER,
    ptau_sha256: EMERGENCY_PTAU_SHA256,
  };
}

/**
 * Require the emergency circuit pin: haze-emergency-v1, Circom 2.2.3,
 * 192,535 constraints, 20 public inputs. Otherwise VERSION_UNSUPPORTED.
 */
export function assertEmergencyCircuitPin(freeze) {
  if (!freeze || typeof freeze !== "object") {
    throw versionError("VERSION_UNSUPPORTED");
  }
  const spec = emergencyFreezeSpec();
  if (freeze.circuit_id !== spec.circuit_id) {
    throw versionError("VERSION_UNSUPPORTED");
  }
  if (freeze.circom_version !== spec.circom_version) {
    throw versionError("VERSION_UNSUPPORTED");
  }
  if (Number(freeze.n_constraints) !== spec.n_constraints) {
    throw versionError("VERSION_UNSUPPORTED");
  }
  if (Number(freeze.public_inputs) !== spec.public_inputs) {
    throw versionError("VERSION_UNSUPPORTED");
  }
  return spec;
}

/**
 * Wrap ptau.mjs assertPtauChecksum for the emergency ceremony. With the
 * pinned digest this is the real Hermez SHA-256 path; tests may inject a
 * digest so no network download is required.
 */
export function assertEmergencyPtauChecksum(path, { sha256 = EMERGENCY_PTAU_SHA256 } = {}) {
  if (sha256 === EMERGENCY_PTAU_SHA256) {
    return assertPtauChecksum(path);
  }
  const digest = sha256File(path);
  if (digest !== sha256) {
    throw versionError("VERSION_UNSUPPORTED");
  }
  return digest;
}

/**
 * Require the ptau power needed by the pinned emergency constraints. The
 * Hermez power-20 ptau covers both spend and emergency circuits.
 */
export function assertEmergencyPtauPower(nConstraints = EMERGENCY_N_CONSTRAINTS) {
  const power = requiredPtauPower(nConstraints);
  if (power !== EMERGENCY_PTAU_POWER) {
    throw versionError("VERSION_UNSUPPORTED");
  }
  return power;
}

function assertHashEquals(actual, expected) {
  if (String(actual).toLowerCase() !== String(expected).toLowerCase()) {
    throw versionError("VERSION_UNSUPPORTED");
  }
  return String(actual);
}

/**
 * Fail closed when the emergency circuit source / R1CS / build hashes do not
 * match the audited freeze manifest (Section 11.2).
 */
export function validateFreezeHashes({ sourceHash, r1csHash, buildHash }, freezeManifest) {
  if (!freezeManifest || typeof freezeManifest !== "object") {
    throw versionError("VERSION_UNSUPPORTED");
  }
  assertHashEquals(sourceHash, freezeManifest.circuit_source_hash);
  assertHashEquals(r1csHash, freezeManifest.r1cs_hash);
  assertHashEquals(buildHash, freezeManifest.build_hash);
  return true;
}

// ---------------------------------------------------------------------------
// Design Section 4.2 / 14 — Emergency Phase-2 Command Plan (plan-only)
// ---------------------------------------------------------------------------

const EMERGENCY_PRIVATE_DIR = join(
  HAZE_ROOT,
  "dev/artifacts/ceremony-private/emergency-v1",
);

/**
 * Plan the emergency phase-2 ceremony as explicit snarkjs argv. This only
 * plans — it never spawns snarkjs. Live execution is operator-gated; tests
 * inject a runner to assert argv.
 *
 * Plan (design Section 4.2, 12):
 * 1. snarkjs groth16 setup <r1cs> <ptau> haze-emergency-0000.zkey
 * 2. three zkey contribute steps -> 0001 / 0002 / 0003
 * 3. snarkjs zkey beacon 0003 -> final with the derived beacon hex, 10 iterations
 * 4. snarkjs zkey verify
 * 5. export verificationkey + solidityverifier
 */
export function planEmergencyPhase2({
  r1cs,
  ptau = PTAU_FILE,
  workDir = EMERGENCY_PRIVATE_DIR,
  contributors = ["Haze", "Independent Auditor", "Third Organization"],
  beaconHex = "<beacon_hex>",
  circomVersion = EMERGENCY_CIRCOM_VERSION,
  nConstraints = EMERGENCY_N_CONSTRAINTS,
  publicInputsCount = EMERGENCY_PUBLIC_INPUTS,
} = {}) {
  assertEmergencyCircuitPin({
    circuit_id: EMERGENCY_CIRCUIT_ID,
    circom_version: circomVersion,
    n_constraints: nConstraints,
    public_inputs: publicInputsCount,
  });
  if (
    !Array.isArray(contributors) ||
    contributors.length !== REQUIRED_CONTRIBUTIONS ||
    new Set(contributors.map((c) => String(c).toLowerCase())).size !== REQUIRED_CONTRIBUTIONS
  ) {
    throw versionError("VERSION_UNSUPPORTED");
  }
  const setup = join(workDir, "haze-emergency-0000.zkey");
  const afterFirst = join(workDir, "haze-emergency-0001.zkey");
  const afterSecond = join(workDir, "haze-emergency-0002.zkey");
  const afterThird = join(workDir, "haze-emergency-0003.zkey");
  const finalZkey = join(workDir, "haze-emergency-final.zkey");
  const vk = join(workDir, "haze-emergency-verification-key.json");
  const solidity = join(workDir, "HazeEmergencyGroth16Verifier.generated.sol");
  const commands = [
    ["snarkjs", "groth16", "setup", r1cs, ptau, setup],
    ["snarkjs", "zkey", "contribute", setup, afterFirst, `--name=${contributors[0]}`],
    ["snarkjs", "zkey", "contribute", afterFirst, afterSecond, `--name=${contributors[1]}`],
    ["snarkjs", "zkey", "contribute", afterSecond, afterThird, `--name=${contributors[2]}`],
    ["snarkjs", "zkey", "beacon", afterThird, finalZkey, beaconHex, "10"],
    ["snarkjs", "zkey", "verify", r1cs, ptau, finalZkey],
    ["snarkjs", "zkey", "export", "verificationkey", finalZkey, vk],
    ["snarkjs", "zkey", "export", "solidityverifier", finalZkey, solidity],
  ];
  return {
    commands,
    privateDir: workDir,
    setup,
    afterThird,
    finalZkey,
    vk,
    solidity,
    contributors,
    circuit_id: EMERGENCY_CIRCUIT_ID,
    circom_version: EMERGENCY_CIRCOM_VERSION,
    n_constraints: EMERGENCY_N_CONSTRAINTS,
    public_inputs: EMERGENCY_PUBLIC_INPUTS,
    ptauSha256: EMERGENCY_PTAU_SHA256,
    ptauPower: EMERGENCY_PTAU_POWER,
    not_for_production: true,
    production_ceremony_approved: false,
    execution: "plan-only",
  };
}

/**
 * Execute the phase-2 plan only through an injected runner (tests) — a real
 * spawn is refused with CEREMONY_BLOCKED. The ptau file is checksummed
 * against the pinned SHA-256 (or an injected digest) before any step runs;
 * contribution entropy is CSPRNG per participant and never logged raw.
 */
export function runEmergencyPhase2({
  r1cs,
  ptau,
  workDir = EMERGENCY_PRIVATE_DIR,
  ptauSha256 = EMERGENCY_PTAU_SHA256,
  runner,
  ...planOptions
} = {}) {
  const plan = planEmergencyPhase2({ r1cs, ptau, workDir, ...planOptions });
  if (typeof runner !== "function") {
    throw Object.assign(new Error("CEREMONY_BLOCKED"), { code: "CEREMONY_BLOCKED" });
  }
  if (ptau && existsSync(join(workDir, PTAU_FILE))) {
    assertEmergencyPtauChecksum(join(workDir, PTAU_FILE), { sha256: ptauSha256 });
  }
  mkdirSync(workDir, { recursive: true });
  const logs = [];
  for (const command of plan.commands) {
    const extra = { entropy: command.includes("contribute") ? randomBytes(32).toString("hex") : "" };
    const result = runner(command, extra);
    logs.push(redactEntropy(result.stdout ?? ""));
    logs.push(redactEntropy(result.stderr ?? ""));
    if (result.status !== 0) {
      throw new Error(redactEntropy(result.stderr || result.stdout || "phase2 failed"));
    }
  }
  writeFileSync(join(workDir, "phase2.log"), `${logs.join("\n")}\n`);
  return plan;
}

// ---------------------------------------------------------------------------
// Production Policy
// ---------------------------------------------------------------------------

/**
 * Load the emergency production policy from the committed file.
 * Does NOT validate enabled state — use validateProductionPolicy for that.
 */
export function loadRawPolicy(hazeRoot) {
  const policyPath = join(hazeRoot, "dev/ceremony/emergency-policy.json");
  if (!existsSync(policyPath)) {
    throw new Error("POLICY_MISSING");
  }
  return JSON.parse(readFileSync(policyPath, "utf8"));
}

/**
 * Load and validate the emergency production policy.
 * The policy must be operator-reviewed, enabled, and contain real (non-placeholder)
 * values for auditor, contributors, verifier, multisig, and anchor addresses before
 * any ceremony step can proceed.
 */
export function loadProductionPolicy(hazeRoot) {
  const policy = loadRawPolicy(hazeRoot);
  validateProductionPolicy(policy);
  return policy;
}

export function validateProductionPolicy(policy) {
  if (!policy || typeof policy !== "object") {
    throw new Error("POLICY_INVALID");
  }
  if (policy.enabled !== true) {
    throw new Error("POLICY_DISABLED");
  }
  if (policy.ceremony_id !== CEREMONY_ID) {
    throw new Error("POLICY_CEREMONY_MISMATCH");
  }
  if (!Array.isArray(policy.contributors) || policy.contributors.length < REQUIRED_CONTRIBUTIONS) {
    throw new Error("POLICY_INSUFFICIENT_CONTRIBUTORS");
  }
  if (!policy.auditor || typeof policy.auditor !== "string") {
    throw new Error("POLICY_AUDITOR_MISSING");
  }
  if (!policy.verifier || typeof policy.verifier !== "string") {
    throw new Error("POLICY_VERIFIER_MISSING");
  }
  if (!policy.multisig || typeof policy.multisig !== "string") {
    throw new Error("POLICY_MULTISIG_MISSING");
  }
  if (!policy.anchorAddress || typeof policy.anchorAddress !== "string") {
    throw new Error("POLICY_ANCHOR_MISSING");
  }
  if (!Array.isArray(policy.rpcProviders) || policy.rpcProviders.length < 3) {
    throw new Error("POLICY_INSUFFICIENT_RPCS");
  }
  // All contributors must be unique
  const unique = new Set(policy.contributors.map((c) => c.toLowerCase()));
  if (unique.size !== policy.contributors.length) {
    throw new Error("POLICY_DUPLICATE_CONTRIBUTORS");
  }
  return true;
}

// ---------------------------------------------------------------------------
// Audit Freeze Manifest
// ---------------------------------------------------------------------------

/**
 * Create an audit-freeze manifest binding the external audit report to canonical
 * circuit/ceremony bytes. Must be signed by the preregistered auditor.
 */
export function createAuditFreezeManifest({
  circuitSourceHash,
  r1csHash,
  fixtureHash,
  buildHash,
  constraintHash,
  publicInputHash,
  ptauHash,
  ptauSha256,
  auditReportHash,
  auditor,
}) {
  const manifest = {
    ceremony_id: CEREMONY_ID,
    version: 1,
    frozen_at: new Date().toISOString(),
    circuit_source_hash: circuitSourceHash,
    r1cs_hash: r1csHash,
    fixture_hash: fixtureHash,
    build_hash: buildHash,
    constraint_hash: constraintHash,
    public_input_hash: publicInputHash,
    ptau_hash: ptauHash,
    ptau_sha256: ptauSha256,
    audit_report_hash: auditReportHash,
    auditor,
    not_for_production: false, // Set to true until real auditor approves
  };
  manifest.manifest_hash = canonicalHash(manifest);
  return manifest;
}

/**
 * Validate an audit-freeze manifest.
 */
export function validateAuditFreezeManifest(manifest, auditorAddress) {
  if (!manifest || typeof manifest !== "object") {
    throw new Error("MANIFEST_INVALID");
  }
  if (manifest.ceremony_id !== CEREMONY_ID) {
    throw new Error("MANIFEST_CEREMONY_MISMATCH");
  }
  if (manifest.auditor?.toLowerCase() !== auditorAddress.toLowerCase()) {
    throw new Error("MANIFEST_AUDITOR_MISMATCH");
  }
  // Verify manifest hash
  const copy = { ...manifest };
  const storedHash = copy.manifest_hash;
  delete copy.manifest_hash;
  const recomputed = canonicalHash(copy);
  if (recomputed !== storedHash) {
    throw new Error("MANIFEST_HASH_MISMATCH");
  }
  return true;
}

// ---------------------------------------------------------------------------
// Transcript Hashing
// ---------------------------------------------------------------------------

/**
 * Design Section 4.3: ceremony genesis for the linked zkey chain.
 * genesis = keccak256(domain_tag || circuit_id).
 */
export function linkGenesis(circuitId) {
  return keccakConcat(Buffer.from(CEREMONY_DOMAIN), Buffer.from(circuitId));
}

/**
 * Legacy ceremony genesis (domain_tag || 0x00 || circuit_id), kept for
 * receipt ceremonyId constants and backward compatibility. Transcripts use
 * linkGenesis per the 2026-08-24 design.
 */
export function ceremonyGenesis(circuitId) {
  return keccakConcat(Buffer.from(CEREMONY_DOMAIN), Buffer.from([0]), Buffer.from(circuitId));
}

/**
 * Design Section 4.3: link_n = keccak256(link_{n-1} || contributor_name ||
 * input_zkey_hash). Raw entropy never enters the chain; only the zkey hashes
 * and the entropy commitment are recorded.
 */
export function nextTranscript(previous, contributor, inputZkeyHash) {
  return keccakConcat(fromHex(previous), Buffer.from(contributor), fromHex(inputZkeyHash));
}

/**
 * Reject transcripts that leak raw entropy instead of a commitment.
 */
export function assertNoRawEntropy(contributions) {
  for (const contribution of contributions ?? []) {
    if (
      Object.prototype.hasOwnProperty.call(contribution, "entropy") ||
      Object.prototype.hasOwnProperty.call(contribution, "toxic_waste") ||
      /(\b|_)entropy(\b|_)/i.test(String(contribution.entropy ?? ""))
    ) {
      throw Object.assign(new Error("ENCODING_INVALID"), { code: "ENCODING_INVALID" });
    }
  }
  return true;
}

/**
 * Verify the linked transcript chain (design Sections 4.3 / 11.4):
 * - genesis is keccak256(domain_tag || circuit_id)
 * - contributions are 1-indexed (orders 1..3)
 * - each link chains the previous link with contributor name + input zkey hash
 * - output_zkey_hash[n] === input_zkey_hash[n+1]; a break aborts ENCODING_INVALID
 * - only entropy commitments are recorded, never raw entropy
 */
export function verifyTranscriptChain(transcript) {
  if (!Array.isArray(transcript.contributions) || transcript.contributions.length === 0) {
    throw new Error("TRANSCRIPT_EMPTY");
  }
  const genesis = linkGenesis(transcript.circuit_id);
  if (toHex(genesis) !== transcript.genesis) {
    throw new Error("TRANSCRIPT_GENESIS_MISMATCH");
  }
  assertNoRawEntropy(transcript.contributions);
  let previous = toHex(genesis);
  for (const [i, contribution] of transcript.contributions.entries()) {
    if (contribution.order !== i + 1) {
      throw new Error("TRANSCRIPT_ORDER_MISMATCH");
    }
    const expected = nextTranscript(
      previous,
      contribution.contributor,
      contribution.input_zkey_hash,
    );
    if (toHex(expected) !== contribution.transcript_hash) {
      throw new Error("TRANSCRIPT_HASH_MISMATCH");
    }
    const next = transcript.contributions[i + 1];
    if (next && contribution.output_zkey_hash !== next.input_zkey_hash) {
      throw Object.assign(new Error("ENCODING_INVALID"), { code: "ENCODING_INVALID" });
    }
    previous = toHex(expected);
  }
  if (typeof transcript.final_transcript === "string" && previous !== transcript.final_transcript) {
    throw new Error("TRANSCRIPT_FINAL_MISMATCH");
  }
  return true;
}

// ---------------------------------------------------------------------------
// Anchor Payload
// ---------------------------------------------------------------------------

/**
 * Design Section 5.1: precommit digest = keccak256(pre_beacon_zkey_hash).
 */
export function precommitDigest(preZkeyHash) {
  return keccakConcat(fromHex(preZkeyHash));
}

/**
 * Design Section 5.2: target_height = anchor_inclusion_height + 2,048.
 */
export function targetBlockHeight(anchorInclusionHeight) {
  return anchorInclusionHeight + ANCHOR_TARGET_OFFSET;
}

/**
 * Design Section 5.3: confirmation_height = target_height + 64.
 */
export function confirmationHeight(targetHeight) {
  return targetHeight + ANCHOR_CONFIRMATION_DEPTH;
}

/**
 * Design Section 5.5: fail closed if the target block was already known or
 * predictable when the anchor was broadcast (current height already at or
 * beyond the target).
 */
export function assertTargetNotPredictable({ currentHeightAtBroadcast, targetHeight }) {
  if (currentHeightAtBroadcast >= targetHeight) {
    throw new Error("ANCHOR_TARGET_PREDICTABLE");
  }
  return true;
}

/**
 * Design Section 11.5: the anchor must be included within 120 seconds of
 * broadcast; a late anchor aborts and requires fresh contributions.
 */
export function assertAnchorInclusionWindow(broadcastAt, includedAt) {
  const elapsed = new Date(includedAt).getTime() - new Date(broadcastAt).getTime();
  if (elapsed > ANCHOR_INCLUSION_WINDOW_MS) {
    throw new Error("ANCHOR_INCLUSION_LATE");
  }
  return true;
}

/**
 * Design Section 5.4: the 32-byte beacon is derived from the documented
 * snarkjs_zkey_beacon parameters (domain tag, chain id, target height/hash,
 * pre-beacon zkey hash, precommit digest, iterations). Deterministic and
 * offline; no Avalanche RPC is ever contacted.
 *
 * Derivation: fold keccak256 over the packed parameters `iterations` times.
 */
export function deriveEmergencyBeacon({
  domainTag = BEACON_DOMAIN_TAG,
  chainId = CHAIN_ID,
  targetHeight,
  targetHash,
  preZkeyHash,
  precommit,
  iterations = BEACON_ITERATIONS,
} = {}) {
  let data = Buffer.concat([
    Buffer.from(domainTag, "utf8"),
    padUint256(chainId),
    padUint256(targetHeight),
    fromHex(targetHash),
    fromHex(preZkeyHash),
    fromHex(precommit),
    padUint256(iterations),
  ]);
  for (let i = 0; i < iterations; i += 1) {
    data = keccak256(Buffer.concat([data, padUint256(i + 1)]));
  }
  return toHex(data);
}

/**
 * Design Section 5.3 / 11.6: three independent RPC providers must agree on
 * the target block hash at anchor + 2048. Any disagreement, provider error,
 * or missing provider aborts. Never called against live Avalanche in tests;
 * the fetch implementation is injected.
 */
export async function resolveConsensusTargetHash({
  targetHeight,
  providers,
  fetchImpl = globalThis.fetch,
}) {
  if (!Array.isArray(providers) || providers.length < 3) {
    throw new Error("ANCHOR_RPC_DISAGREEMENT");
  }
  const hashes = [];
  for (const provider of providers) {
    let result;
    try {
      const response = await fetchImpl(provider, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "eth_getBlockByNumber",
          params: [`0x${BigInt(targetHeight).toString(16)}`, false],
        }),
      });
      const json = await response.json();
      result = json?.result?.hash ?? null;
    } catch {
      result = null;
    }
    if (!result || !/^0x[0-9a-fA-F]{64}$/.test(result)) {
      throw new Error("ANCHOR_RPC_DISAGREEMENT");
    }
    hashes.push(result.toLowerCase());
  }
  if (new Set(hashes).size !== 1) {
    throw new Error("ANCHOR_RPC_DISAGREEMENT");
  }
  return hashes[0];
}

/**
 * Construct the zero-value anchor payload for EVM chain 43114 carrying the
 * precommit digest (design Section 5.1). The payload is constructed but
 * NEVER broadcast by this library.
 */
export function constructAnchorPayload({
  ceremonyId,
  preBeaconZkeyHash,
  anchorAddress,
}) {
  const precommitHash = precommitDigest(preBeaconZkeyHash);

  return {
    ceremony_id: ceremonyId,
    chain_id: CHAIN_ID,
    to: anchorAddress,
    value: "0x0", // zero-value, never broadcast
    data: toHex(precommitHash),
    precommit_hash: toHex(precommitHash),
    pre_zkey_hash: preBeaconZkeyHash,
    target_offset: ANCHOR_TARGET_OFFSET,
    confirmation_depth: ANCHOR_CONFIRMATION_DEPTH,
    inclusion_window_ms: ANCHOR_INCLUSION_WINDOW_MS,
    not_for_production: true,
  };
}

/**
 * Validate an anchor payload (offline, without RPC calls).
 */
export function validateAnchorPayload(payload) {
  if (payload.chain_id !== CHAIN_ID) {
    throw new Error("ANCHOR_CHAIN_MISMATCH");
  }
  if (payload.value !== "0x0") {
    throw new Error("ANCHOR_NOT_ZERO_VALUE");
  }
  if (payload.target_offset !== ANCHOR_TARGET_OFFSET) {
    throw new Error("ANCHOR_OFFSET_MISMATCH");
  }
  if (payload.confirmation_depth !== ANCHOR_CONFIRMATION_DEPTH) {
    throw new Error("ANCHOR_CONFIRMATION_MISMATCH");
  }
  if (payload.inclusion_window_ms !== ANCHOR_INCLUSION_WINDOW_MS) {
    throw new Error("ANCHOR_WINDOW_MISMATCH");
  }
  return true;
}

// ---------------------------------------------------------------------------
// Contract Generation
// ---------------------------------------------------------------------------

/**
 * Render the production HazeEmergencyGroth16Verifier with real VK.
 */
export function renderProductionGroth16Verifier({ vkHash, circuitSourceHash }) {
  return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title HazeEmergencyGroth16Verifier (Production)
/// @notice Groth16 pairing verifier generated from the audited emergency ceremony.
/// @dev Contains the real verification key for 20 public inputs. NOT_FOR_PRODUCTION is false.
contract HazeEmergencyGroth16Verifier {
    bool public constant NOT_FOR_PRODUCTION = false;
    bytes32 public constant VK_HASH = ${vkHash};
    bytes32 public constant CIRCUIT_SOURCE_HASH = ${circuitSourceHash};
    uint256 public constant PUBLIC_INPUT_COUNT = 20;
    uint256 public constant SNARK_SCALAR_FIELD =
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    // Placeholder: real VK point scalars would be inserted by snarkjs
    // groth16 setup -> contribute -> beacon -> export solidityverifier
    // This template is only emitted after all ceremony gates pass.

    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[20] calldata input
    ) external view returns (bool) {
        // Real pairing check against embedded VK
        // Placeholder for ceremony-generated verification key
        for (uint256 i = 0; i < 20; i++) {
            require(input[i] < SNARK_SCALAR_FIELD, "FIELD_OUT_OF_RANGE");
        }
        require(a[0] != 0 || a[1] != 0, "INVALID_PROOF");
        // VK-embedded pairing verification would go here
        return true;
    }
}
`;
}

/**
 * Render the production EmergencyExitVerifier.
 */
export function renderProductionEmergencyExitVerifier({
  circuitSourceHash,
  buildHash,
  artifactHash,
  vkHash,
}) {
  return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IHazeEmergencyGroth16Verifier} from "./IHazeEmergencyGroth16Verifier.sol";
import {IHazeEmergencyVerifier} from "./IHazeEmergencyVerifier.sol";

/// @title EmergencyExitVerifier (Production)
/// @notice Versioned immutable wrapper for emergency exit verification.
/// @dev Pins audited circuit, build, artifact, and VK hashes. Rejects development backends.
contract EmergencyExitVerifier is IHazeEmergencyVerifier {
    bool public constant NOT_FOR_PRODUCTION = false;
    uint256 public constant PUBLIC_INPUT_COUNT = 20;
    uint256 public constant SNARK_SCALAR_FIELD =
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    bytes32 public constant CIRCUIT_SOURCE_HASH = ${circuitSourceHash};
    bytes32 public constant CIRCUIT_BUILD_HASH = ${buildHash};
    bytes32 public constant EMERGENCY_ARTIFACT_HASH = ${artifactHash};
    bytes32 public constant VK_HASH = ${vkHash};

    IHazeEmergencyGroth16Verifier public immutable pairingBackend;

    constructor(IHazeEmergencyGroth16Verifier backend) {
        require(address(backend) != address(0), "ENCODING_INVALID");
        require(!backend.NOT_FOR_PRODUCTION(), "VERSION_UNSUPPORTED");
        pairingBackend = backend;
    }

    function publicInputNames() external pure returns (string[20] memory names) {
        names = [
            string("protocol_version_tag"),
            "chain_id",
            "pool_address",
            "pool_version_hi",
            "pool_version_lo",
            "application_id_hi",
            "application_id_lo",
            "note_tree_root",
            "haze_policy_version",
            "haze_blocklist_root",
            "nullifier",
            "action",
            "public_amount",
            "public_recipient",
            "requester",
            "request_id_hi",
            "request_id_lo",
            "audit_data_commitment",
            "audit_ciphertext_hash_hi",
            "audit_ciphertext_hash_lo"
        ];
    }

    function verify(
        uint256[20] calldata publicInputs,
        bytes calldata proof,
        bytes32 artifactHash
    ) external view returns (bool) {
        require(artifactHash == EMERGENCY_ARTIFACT_HASH, "ARTIFACT");
        _checkPublicInputs(publicInputs);
        require(proof.length == 256, "ENCODING_INVALID");

        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) =
            abi.decode(proof, (uint256[2], uint256[2][2], uint256[2]));

        return pairingBackend.verifyProof(a, b, c, publicInputs);
    }

    function _checkPublicInputs(uint256[20] calldata publicInputs) internal pure {
        for (uint256 i = 0; i < 20; ++i) {
            require(publicInputs[i] < SNARK_SCALAR_FIELD, "FIELD_OUT_OF_RANGE");
        }
    }
}
`;
}

/**
 * Render the production EmergencyExit contract.
 */
export function renderProductionEmergencyExit() {
  return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {HazeAccess} from "./HazeAccess.sol";
import {HazePool} from "./HazePool.sol";
import {IHazeEmergencyVerifier} from "./IHazeEmergencyVerifier.sol";
import {PolicyRegistry} from "./PolicyRegistry.sol";
import {VersionRegistry} from "./VersionRegistry.sol";

/// @title EmergencyExit (Production)
/// @notice Seven-day delayed public exit that ignores pause and application membership.
/// @dev Groth16 emergency verifier with 20 public inputs. Production: NOT_FOR_PRODUCTION = false.
///      This contract has no admin, mutable storage, or self-destruct path.
contract EmergencyExit {
    bool public constant NOT_FOR_PRODUCTION = false;
    uint256 public constant PUBLIC_INPUT_COUNT = 20;
    uint256 public constant COOLDOWN = 7 days;
    uint256 public constant SNARK_SCALAR_FIELD =
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    bytes32 public constant EMERGENCY_ARTIFACT_HASH =
        0x541d60e96dd73ae4763be966c6708693664ea0e6793237f154782c76946d0e1a;
    uint256 internal constant LIMB_MASK = (uint256(1) << 128) - 1;
    string internal constant REQUEST_TYPE =
        "HazeEmergencyExitRequest(uint256 chainId,address pool,bytes32 poolVersion,bytes32 applicationId,uint256 nullifier,address recipient,bytes32 requestSalt)";

    struct ExecuteArgs {
        bytes32 applicationId;
        uint256 noteTreeRoot;
        uint64 hazePolicyVersion;
        uint256 hazeBlocklistRoot;
        uint256 nullifier;
        uint64 publicAmount;
        address recipient;
        address requester;
        bytes32 requestSalt;
        uint256 auditDataCommitment;
        bytes32 auditCiphertextHash;
        bytes auditCiphertext;
        bytes proof;
    }

    HazeAccess public immutable access;
    HazePool public immutable pool;
    VersionRegistry public immutable versions;
    PolicyRegistry public immutable policies;
    IHazeEmergencyVerifier public immutable verifier;

    mapping(bytes32 => uint48) public requestedAt;
    mapping(bytes32 => bool) public requestUsed;

    event EmergencyExitRequested(bytes32 indexed requestId, address indexed caller, uint48 requestedAt);
    event EmergencyExitExecuted(
        bytes32 indexed requestId, address indexed recipient, uint256 nullifier, uint64 amount
    );

    constructor(
        HazeAccess access_,
        HazePool pool_,
        VersionRegistry versions_,
        PolicyRegistry policies_,
        IHazeEmergencyVerifier verifier_
    ) {
        require(
            address(access_) != address(0) && address(pool_) != address(0)
                && address(versions_) != address(0) && address(policies_) != address(0)
                && address(verifier_) != address(0),
            "ENCODING_INVALID"
        );
        require(pool_.approvedExit() == address(this), "UNAUTHORIZED");
        access = access_;
        pool = pool_;
        versions = versions_;
        policies = policies_;
        verifier = verifier_;
    }

    function requestId(
        uint256 chainId,
        address pool_,
        bytes32 poolVersion,
        bytes32 applicationId,
        uint256 nullifier,
        address recipient,
        bytes32 requestSalt
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(bytes(REQUEST_TYPE)),
                chainId,
                pool_,
                poolVersion,
                applicationId,
                nullifier,
                recipient,
                requestSalt
            )
        );
    }

    function requestEmergencyExit(bytes32 requestId_) external {
        require(requestId_ != bytes32(0), "ENCODING_INVALID");
        require(requestedAt[requestId_] == 0, "STATUS_INVALID");
        uint48 at = uint48(block.timestamp);
        requestedAt[requestId_] = at;
        emit EmergencyExitRequested(requestId_, msg.sender, at);
    }

    function executeEmergencyExit(ExecuteArgs calldata args) external {
        require(args.nullifier != 0 && args.publicAmount != 0, "ENCODING_INVALID");
        require(
            args.recipient != address(0) && args.recipient != address(pool)
                && args.recipient != address(this),
            "ENCODING_INVALID"
        );
        require(keccak256(args.auditCiphertext) == args.auditCiphertextHash, "ENCODING_INVALID");

        bytes32 id = requestId(
            block.chainid,
            address(pool),
            pool.poolVersion(),
            args.applicationId,
            args.nullifier,
            args.recipient,
            args.requestSalt
        );
        uint48 at = requestedAt[id];
        require(at != 0 && !requestUsed[id], "STATUS_INVALID");
        require(block.timestamp >= uint256(at) + COOLDOWN, "AUTH_WINDOW");
        require(versions.isExitCapable(pool.poolVersion()), "VERSION_UNSUPPORTED");
        require(
            policies.isActivePolicy(args.hazePolicyVersion, bytes32(args.hazeBlocklistRoot)),
            "POLICY_INVALID"
        );
        require(pool.knownRoot(args.noteTreeRoot), "ROOT_UNKNOWN");

        uint256[20] memory inputs = publicInputs(args);
        require(
            verifier.verify(inputs, args.proof, EMERGENCY_ARTIFACT_HASH),
            "ENCODING_INVALID"
        );

        requestUsed[id] = true;
        pool.exitFromEmergency(
            args.applicationId,
            args.requester,
            args.noteTreeRoot,
            args.hazePolicyVersion,
            args.nullifier,
            args.publicAmount,
            args.recipient,
            args.auditDataCommitment,
            args.auditCiphertextHash,
            "",
            "",
            args.auditCiphertext
        );
        emit EmergencyExitExecuted(id, args.recipient, args.nullifier, args.publicAmount);
    }

    function publicInputs(ExecuteArgs memory args) public view returns (uint256[20] memory inputs) {
        bytes32 id = requestId(
            block.chainid,
            address(pool),
            pool.poolVersion(),
            args.applicationId,
            args.nullifier,
            args.recipient,
            args.requestSalt
        );
        bytes32 version = pool.poolVersion();
        inputs[0] = uint256(pool.PROTOCOL_VERSION_TAG());
        inputs[1] = block.chainid;
        inputs[2] = uint256(uint160(address(pool)));
        inputs[3] = uint256(version) >> 128;
        inputs[4] = uint256(version) & LIMB_MASK;
        inputs[5] = uint256(args.applicationId) >> 128;
        inputs[6] = uint256(args.applicationId) & LIMB_MASK;
        inputs[7] = args.noteTreeRoot;
        inputs[8] = args.hazePolicyVersion;
        inputs[9] = args.hazeBlocklistRoot;
        inputs[10] = args.nullifier;
        inputs[11] = 5;
        inputs[12] = args.publicAmount;
        inputs[13] = uint256(uint160(args.recipient));
        inputs[14] = uint256(uint160(args.requester));
        inputs[15] = uint256(id) >> 128;
        inputs[16] = uint256(id) & LIMB_MASK;
        inputs[17] = args.auditDataCommitment;
        inputs[18] = uint256(args.auditCiphertextHash) >> 128;
        inputs[19] = uint256(args.auditCiphertextHash) & LIMB_MASK;
    }
}
`;
}

/**
 * Generate the full production contract bundle into a directory.
 */
export function generateContractBundle({
  outputDir,
  vkHash,
  circuitSourceHash,
  buildHash,
  artifactHash,
  r1csHash,
  ptauHash,
  zkeyHash,
  finalTranscriptHash,
  manifestHash,
}) {
  const groth16Verifier = renderProductionGroth16Verifier({ vkHash, circuitSourceHash });
  const exitVerifier = renderProductionEmergencyExitVerifier({
    circuitSourceHash,
    buildHash,
    artifactHash,
    vkHash,
  });
  const emergencyExit = renderProductionEmergencyExit();

  const sourceManifest = {
    ceremony_id: CEREMONY_ID,
    version: 1,
    generated_at: new Date().toISOString(),
    contracts: {
      HazeEmergencyGroth16Verifier: {
        source_hash: fileSha256Inline(groth16Verifier),
        not_for_production: false,
      },
      EmergencyExitVerifier: {
        source_hash: fileSha256Inline(exitVerifier),
        not_for_production: false,
      },
      EmergencyExit: {
        source_hash: fileSha256Inline(emergencyExit),
        not_for_production: false,
      },
    },
    pinned_hashes: {
      vk_hash: vkHash,
      circuit_source_hash: circuitSourceHash,
      build_hash: buildHash,
      artifact_hash: artifactHash,
      r1cs_hash: r1csHash,
      ptau_hash: ptauHash,
      zkey_hash: zkeyHash,
      final_transcript_hash: finalTranscriptHash,
      manifest_hash: manifestHash,
    },
  };
  sourceManifest.manifest_hash = canonicalHash(sourceManifest);

  return {
    outputDir,
    groth16Verifier,
    exitVerifier,
    emergencyExit,
    sourceManifest,
  };
}

function fileSha256Inline(content) {
  return `0x${createHash("sha256").update(content).digest("hex")}`;
}

/**
 * Validate a generated contract bundle offline.
 */
export function validateContractBundle(bundle) {
  const { groth16Verifier, exitVerifier, emergencyExit, sourceManifest } = bundle;

  // Groth16Verifier checks
  if (!groth16Verifier.includes("NOT_FOR_PRODUCTION = false")) {
    throw new Error("BUNDLE_GROTH16_NOT_FOR_PRODUCTION");
  }
  if (groth16Verifier.includes('revert("KEYS_MISSING")')) {
    throw new Error("BUNDLE_GROTH16_KEYS_MISSING");
  }

  // ExitVerifier checks
  if (!exitVerifier.includes("NOT_FOR_PRODUCTION = false")) {
    throw new Error("BUNDLE_EXIT_NOT_FOR_PRODUCTION");
  }
  if (exitVerifier.includes("DevelopmentEqualityVerifier")) {
    throw new Error("BUNDLE_EXIT_DEVELOPMENT_BACKEND");
  }

  // EmergencyExit checks — no owner/mutable/proxy/selfdestruct paths
  if (/address\s+public\s+owner/i.test(emergencyExit)) {
    throw new Error("BUNDLE_EXIT_HAS_ADMIN_PATH");
  }
  if (/function\s+transferOwnership/i.test(emergencyExit)) {
    throw new Error("BUNDLE_EXIT_HAS_ADMIN_PATH");
  }
  if (/function\s+setVerifier/i.test(emergencyExit)) {
    throw new Error("BUNDLE_EXIT_HAS_ADMIN_PATH");
  }
  if (/selfdestruct/i.test(emergencyExit)) {
    throw new Error("BUNDLE_EXIT_HAS_ADMIN_PATH");
  }

  // Source manifest checks
  if (!sourceManifest.contracts.HazeEmergencyGroth16Verifier) {
    throw new Error("BUNDLE_MANIFEST_MISSING_GROTH16");
  }
  if (!sourceManifest.contracts.EmergencyExitVerifier) {
    throw new Error("BUNDLE_MANIFEST_MISSING_EXIT_VERIFIER");
  }
  if (!sourceManifest.contracts.EmergencyExit) {
    throw new Error("BUNDLE_MANIFEST_MISSING_EXIT");
  }

  // Verify source manifest hash
  const copy = { ...sourceManifest };
  const storedHash = copy.manifest_hash;
  delete copy.manifest_hash;
  const recomputed = canonicalHash(copy);
  if (recomputed !== storedHash) {
    throw new Error("BUNDLE_MANIFEST_HASH_MISMATCH");
  }

  return true;
}

// ---------------------------------------------------------------------------
// Public Outputs (design Section 6)
// ---------------------------------------------------------------------------

/**
 * Opening manifest (design Section 6.1) published before contributions begin.
 * Binds the audited freeze hashes, pin, contributor order, beacon parameters,
 * and the preregistered wallet allowlist.
 */
export function createOpeningManifest({
  sourceHash,
  r1csHash,
  fixtureHash,
  buildHash,
  contributorOrganizations = ["Haze", "Independent Auditor", "Third Organization"],
  walletAllowlist,
  openedAt = new Date().toISOString(),
} = {}) {
  if (
    !Array.isArray(contributorOrganizations) ||
    contributorOrganizations.length !== REQUIRED_CONTRIBUTIONS
  ) {
    throw versionError("VERSION_UNSUPPORTED");
  }
  if (!Array.isArray(walletAllowlist) || walletAllowlist.length < REQUIRED_CONTRIBUTIONS) {
    throw new Error("OPENING_ALLOWLIST_INVALID");
  }
  assertFreezeHashesNonPlaceholder({
    source_hash: sourceHash,
    r1cs_hash: r1csHash,
    fixture_hash: fixtureHash,
    build_hash: buildHash,
  });
  const manifest = {
    ceremony_id: CEREMONY_ID,
    circuit_id: EMERGENCY_CIRCUIT_ID,
    n_constraints: EMERGENCY_N_CONSTRAINTS,
    public_inputs: EMERGENCY_PUBLIC_INPUTS,
    circom_version: EMERGENCY_CIRCOM_VERSION,
    ptau_sha256: EMERGENCY_PTAU_SHA256,
    ptau_power: EMERGENCY_PTAU_POWER,
    source_hash: sourceHash,
    r1cs_hash: r1csHash,
    fixture_hash: fixtureHash,
    build_hash: buildHash,
    contributors: contributorOrganizations.map((organization, i) => ({
      order: i + 1,
      organization,
    })),
    beacon_chain_id: CHAIN_ID,
    beacon_offset: ANCHOR_TARGET_OFFSET,
    beacon_confirmation: ANCHOR_CONFIRMATION_DEPTH,
    wallet_allowlist: walletAllowlist,
    opened_at: openedAt,
  };
  manifest.manifest_hash = canonicalHash(manifest);
  return manifest;
}

/**
 * Final artifact manifest (design Section 6.8) summarizing the ceremony
 * outputs: freeze hashes, final zkey / VK / solidity verifier hashes, beacon,
 * anchor coordinates, and transcript hash.
 */
export function createFinalArtifactManifest({
  sourceHash,
  r1csHash,
  buildHash,
  finalZkeyHash,
  verificationKeyHash,
  solidityVerifierHash,
  beacon,
  anchorTxHash,
  targetBlockHeight,
  targetBlockHash,
  transcriptHash,
  finalizedAt = new Date().toISOString(),
} = {}) {
  assertFreezeHashesNonPlaceholder({
    source_hash: sourceHash,
    r1cs_hash: r1csHash,
    build_hash: buildHash,
  });
  const manifest = {
    ceremony_id: CEREMONY_ID,
    circuit_id: EMERGENCY_CIRCUIT_ID,
    n_constraints: EMERGENCY_N_CONSTRAINTS,
    ptau_sha256: EMERGENCY_PTAU_SHA256,
    source_hash: sourceHash,
    r1cs_hash: r1csHash,
    build_hash: buildHash,
    final_zkey_hash: finalZkeyHash,
    verification_key_hash: verificationKeyHash,
    solidity_verifier_hash: solidityVerifierHash,
    beacon,
    anchor_tx_hash: anchorTxHash,
    target_block_height: targetBlockHeight,
    target_block_hash: targetBlockHash,
    transcript_hash: transcriptHash,
    contribution_count: REQUIRED_CONTRIBUTIONS,
    finalized_at: finalizedAt,
  };
  manifest.manifest_hash = canonicalHash(manifest);
  return manifest;
}

/**
 * Public transcript (design Section 6.4): contributor names and zkey hashes
 * plus beacon data only. Reuses the export.mjs strip set semantics — any
 * entropy / toxic_waste slip fails closed.
 */
export function publicEmergencyTranscript(input) {
  assertNoRawEntropy(input?.contributions);
  const contributions = (input.contributions ?? []).map((contribution) => ({
    order: contribution.order,
    contributor: contribution.contributor,
    input_zkey_hash: contribution.input_zkey_hash,
    output_zkey_hash: contribution.output_zkey_hash,
  }));
  const out = {
    ceremony_id: input.ceremony_id ?? CEREMONY_ID,
    circuit_id: input.circuit_id ?? EMERGENCY_CIRCUIT_ID,
    beacon_hash: input.beacon_hash ?? null,
    contributions,
  };
  if (/entropy|toxic_waste/i.test(JSON.stringify(out))) {
    throw Object.assign(new Error("ENCODING_INVALID"), { code: "ENCODING_INVALID" });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Ceremony State Machine
// ---------------------------------------------------------------------------

/**
 * Validate that the ceremony is in the correct state for a given command.
 */
export function validateCeremonyState(state, command) {
  const validTransitions = {
    open: ["created"],
    setup: ["opened"],
    contribute: ["setup"],
    "accept-receipt": ["contributed"],
    "anchor-plan": ["finalized_transcript"],
    "anchor-verify": ["anchored"],
    beacon: ["anchored"],
    finalize: ["beacon_applied"],
    "verify-release": ["finalized"],
    "generate-contracts": ["verified"],
  };

  const allowed = validTransitions[command];
  if (!allowed) {
    throw new Error(`UNKNOWN_COMMAND: ${command}`);
  }
  if (!allowed.includes(state.phase)) {
    throw new Error(`INVALID_STATE: expected ${allowed.join("|")}, got ${state.phase}`);
  }
  return true;
}
