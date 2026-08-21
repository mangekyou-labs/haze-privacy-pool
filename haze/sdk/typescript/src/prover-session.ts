import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import { secp256k1 } from "@noble/curves/secp256k1";
import { x25519 } from "@noble/curves/ed25519";
import { keccak256 } from "./keccak.ts";
import { ProverError, type DevelopmentProof, type WorkerOutbound } from "./prover-types.ts";
export { ProverError, type DevelopmentProof, type ProverErrorCode } from "./prover-types.ts";

const KEY_DOMAIN_NAME = "Haze Shielded Account";
const KEY_DOMAIN_VERSION = "1";
const KEY_TYPE = "HazeKeyDerivation(address wallet,bytes32 applicationId,bytes32 poolVersion)";
const DOMAIN_TYPE =
  "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const SPENDING_SECRET_LABEL = "haze/avalanche/v1/hkdf/spending-secret";
const X25519_LABEL = "haze/avalanche/v1/hkdf/x25519";
const LOCAL_VAULT_LABEL = "haze/avalanche/v1/hkdf/local-vault";
const MEMBERSHIP_BLINDING_LABEL = "haze/avalanche/v1/hkdf/membership-blinding";
const BN254_R = Buffer.from("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", "hex");

/** Circom public inputs in frozen circuit order. */
export const SPEND_PUBLIC_CAMEL = [
  "protocolVersionTag",
  "chainId",
  "poolAddress",
  "poolVersionHi",
  "poolVersionLo",
  "applicationIdHi",
  "applicationIdLo",
  "noteTreeRoot",
  "applicationPolicyVersion",
  "hazePolicyVersion",
  "applicationMembershipRoot",
  "hazeBlocklistRoot",
  "inputNullifier0",
  "inputNullifier1",
  "outputCommitment0",
  "outputCommitment1",
  "action",
  "publicAmount",
  "publicRecipient",
  "authorizedUser",
  "intentHashHi",
  "intentHashLo",
  "recipientCiphertextHash0Hi",
  "recipientCiphertextHash0Lo",
  "recipientCiphertextHash1Hi",
  "recipientCiphertextHash1Lo",
  "auditDataCommitment",
  "auditCiphertextHashHi",
  "auditCiphertextHashLo",
] as const;

export type ShieldedAccountRequest = {
  chainId: number;
  pool: string;
  wallet: string;
  applicationId: string;
  poolVersion: string;
  signingKey: string;
};

export type ShieldedAccount = {
  wallet: string;
  spendingSecret: string;
  spendingCounter: number;
  x25519PublicKey: string;
  x25519Secret: string;
  localVaultKey: string;
  membershipBlinding: string;
};

export type ArtifactSet = {
  circuit: string;
  fixture: string;
  manifest: string;
};

export type OperatorGroth16Proof = {
  profile: "operator-owned";
  notForProduction: true;
  protocol: "groth16";
  proof: {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
  };
  publicSignals: string[];
};

const PROVE_META = new Set(["zkeyPath", "wasmPath", "circuit_id", "circuitId"]);

async function pathExists(path: string) {
  try {
    const { existsSync } = await import("node:fs");
    return existsSync(path);
  } catch {
    return false;
  }
}

function toCircomInput(circom: Record<string, unknown>) {
  const input: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(circom)) {
    if (PROVE_META.has(key)) {
      continue;
    }
    input[key] = toFieldValue(value);
  }
  return input;
}

function toFieldValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((entry) => toFieldValue(entry));
  }
  if (typeof value === "string") {
    if (value.startsWith("0x") || value.startsWith("0X")) {
      return BigInt(value).toString();
    }
    return value;
  }
  if (typeof value === "number" || typeof value === "bigint") {
    return value.toString();
  }
  throw new ProverError("WITNESS_INVALID");
}

function fieldWord(value: string) {
  let n: bigint;
  try {
    n = BigInt(value);
  } catch {
    throw new ProverError("PROOF_INVALID");
  }
  if (n < 0n) {
    throw new ProverError("PROOF_INVALID");
  }
  return Buffer.from(n.toString(16).padStart(64, "0"), "hex");
}

/** ABI-encode snarkjs Groth16 (a, swapped G2 b, c) as the pairing wrap's 256-byte proof. */
export function encodeOperatorGroth16Proof(proof: OperatorGroth16Proof) {
  const a = proof.proof?.pi_a;
  const b = proof.proof?.pi_b;
  const c = proof.proof?.pi_c;
  if (!Array.isArray(a) || a.length < 2 || !Array.isArray(c) || c.length < 2) {
    throw new ProverError("PROOF_INVALID");
  }
  if (!Array.isArray(b) || b.length < 2 || !Array.isArray(b[0]) || !Array.isArray(b[1])) {
    throw new ProverError("PROOF_INVALID");
  }
  if (b[0].length < 2 || b[1].length < 2) {
    throw new ProverError("PROOF_INVALID");
  }
  const words = [a[0], a[1], b[0][1], b[0][0], b[1][1], b[1][0], c[0], c[1]];
  if (words.some((word) => typeof word !== "string")) {
    throw new ProverError("PROOF_INVALID");
  }
  return `0x${Buffer.concat(words.map((word) => fieldWord(word))).toString("hex")}`;
}

async function proveOperatorGroth16(
  circom: Record<string, unknown>,
  zkeyPath: string,
  wasmPath: string,
): Promise<OperatorGroth16Proof> {
  let groth16: {
    fullProve: (
      input: Record<string, unknown>,
      wasm: string,
      zkey: string,
    ) => Promise<{ proof: OperatorGroth16Proof["proof"]; publicSignals: string[] }>;
  };
  try {
    ({ groth16 } = await import("snarkjs"));
  } catch {
    throw new ProverError("KEYS_MISSING");
  }
  try {
    const result = await groth16.fullProve(toCircomInput(circom), wasmPath, zkeyPath);
    return {
      profile: "operator-owned",
      notForProduction: true,
      protocol: "groth16",
      proof: result.proof,
      publicSignals: result.publicSignals,
    };
  } catch (error) {
    if (error instanceof ProverError) {
      throw error;
    }
    throw new ProverError("PROOF_INVALID");
  }
}

function hexToBuf(value: string) {
  return Buffer.from(value.replace(/^0x/i, ""), "hex");
}

function toHex(bytes: Uint8Array) {
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

function pad32(bytes: Uint8Array) {
  const out = Buffer.alloc(32);
  Buffer.from(bytes).copy(out, 32 - bytes.length);
  return out;
}

function addressWord(address: string) {
  return pad32(hexToBuf(address));
}

function keccakBuf(...parts: Uint8Array[]) {
  return Buffer.from(keccak256(Buffer.concat(parts.map((part) => Buffer.from(part)))));
}

function domainSeparator(chainId: number, pool: string) {
  return keccakBuf(
    keccak256(Buffer.from(DOMAIN_TYPE)),
    keccak256(Buffer.from(KEY_DOMAIN_NAME)),
    keccak256(Buffer.from(KEY_DOMAIN_VERSION)),
    pad32(hexToBuf(`0x${chainId.toString(16)}`)),
    addressWord(pool),
  );
}

function keyStructHash(wallet: string, applicationId: string, poolVersion: string) {
  return keccakBuf(
    keccak256(Buffer.from(KEY_TYPE)),
    addressWord(wallet),
    hexToBuf(applicationId),
    hexToBuf(poolVersion),
  );
}

function typedDigest(separator: Uint8Array, structHash: Uint8Array) {
  return keccakBuf(Buffer.from([0x19, 0x01]), separator, structHash);
}

/** EIP-712 digest for `HazeKeyDerivation`. */
export function keyDerivationDigest(request: ShieldedAccountRequest) {
  return toHex(
    typedDigest(
      domainSeparator(request.chainId, request.pool),
      keyStructHash(request.wallet, request.applicationId, request.poolVersion),
    ),
  );
}

function hmacSha256(key: Uint8Array, data: Uint8Array) {
  return Buffer.from(hmac(sha256, key, data));
}

function extract(salt: Buffer, ikm: Buffer) {
  return hmacSha256(salt.length === 0 ? Buffer.alloc(32) : salt, ikm);
}

function expand(prk: Buffer, info: Buffer, length: number) {
  const blocks = Math.ceil(length / 32);
  let previous = Buffer.alloc(0);
  const out = [];
  for (let i = 1; i <= blocks; i += 1) {
    previous = hmacSha256(prk, Buffer.concat([previous, info, Buffer.from([i])]));
    out.push(previous);
  }
  return Buffer.concat(out).subarray(0, length);
}

function deriveLabeled(ikm: Buffer, label: string, counter: number) {
  const info = Buffer.concat([Buffer.from(label), Buffer.alloc(4)]);
  info.writeUInt32BE(counter, label.length);
  const prk = extract(Buffer.alloc(0), ikm);
  return expand(prk, info, 32);
}

function deriveSpendingSecret(ikm: Buffer) {
  for (let counter = 0; counter < 256; counter += 1) {
    const candidate = deriveLabeled(ikm, SPENDING_SECRET_LABEL, counter);
    if (candidate.equals(Buffer.alloc(32))) {
      continue;
    }
    if (candidate.compare(BN254_R) >= 0) {
      continue;
    }
    return { spendingSecret: toHex(candidate), spendingCounter: counter };
  }
  throw new ProverError("UNSUPPORTED_RECOVERY");
}

function hpkeX25519Public(ikm: Buffer) {
  const suiteId = Buffer.concat([Buffer.from("KEM"), Buffer.from([0x00, 0x20])]);
  const labeledIkm = Buffer.concat([Buffer.from("HPKE-v1"), suiteId, Buffer.from("dkp_prk"), ikm]);
  const dkpPrk = extract(Buffer.alloc(0), labeledIkm);
  const labeledInfo = Buffer.concat([
    Buffer.from([0x00, 0x20]),
    Buffer.from("HPKE-v1"),
    suiteId,
    Buffer.from("sk"),
  ]);
  const sk = expand(dkpPrk, labeledInfo, 32);
  return Buffer.from(x25519.getPublicKey(sk));
}

function recoverWallet(digest: Uint8Array, normalized: Uint8Array) {
  const recovered = secp256k1.Signature.fromCompact(normalized.subarray(0, 64))
    .addRecoveryBit(normalized[64])
    .recoverPublicKey(digest)
    .toRawBytes(false);
  const address = keccak256(recovered.subarray(1)).subarray(12);
  return toHex(address);
}

function signNormalized(signingKey: Uint8Array, digest: Uint8Array) {
  const signed = secp256k1.sign(digest, signingKey, { prehash: false });
  const low = signed.normalizeS();
  const recovery = signed.recovery === undefined ? 0 : signed.recovery;
  const flipped = signed.hasHighS() ? recovery ^ 1 : recovery;
  if (flipped > 1) {
    throw new ProverError("UNSUPPORTED_RECOVERY");
  }
  const out = Buffer.alloc(65);
  Buffer.from(low.toCompactRawBytes()).copy(out);
  out[64] = flipped;
  return out;
}

/** Derive spending and encryption keys from the documented wallet message. */
export function deriveShieldedAccount(request: ShieldedAccountRequest): ShieldedAccount {
  const digest = typedDigest(
    domainSeparator(request.chainId, request.pool),
    keyStructHash(request.wallet, request.applicationId, request.poolVersion),
  );
  const normalized = signNormalized(hexToBuf(request.signingKey), digest);
  const wallet = recoverWallet(digest, normalized);
  if (wallet.toLowerCase() !== request.wallet.toLowerCase()) {
    throw new ProverError("UNSUPPORTED_RECOVERY");
  }
  const ikm = Buffer.from(normalized);
  const spending = deriveSpendingSecret(ikm);
  const x25519Secret = deriveLabeled(ikm, X25519_LABEL, 0);
  return {
    wallet: request.wallet.toLowerCase(),
    spendingSecret: spending.spendingSecret,
    spendingCounter: spending.spendingCounter,
    x25519PublicKey: toHex(hpkeX25519Public(x25519Secret)),
    x25519Secret: toHex(x25519Secret),
    localVaultKey: toHex(deriveLabeled(ikm, LOCAL_VAULT_LABEL, 0)),
    membershipBlinding: toHex(deriveLabeled(ikm, MEMBERSHIP_BLINDING_LABEL, 0)),
  };
}

/** Extract frozen-order spend public inputs. */
export function spendPublicInputs(circom: Record<string, unknown>) {
  return SPEND_PUBLIC_CAMEL.map((key) => {
    const value = circom[key];
    if (typeof value === "string") {
      return value;
    }
    if (typeof value === "number") {
      return String(value);
    }
    throw new ProverError("WITNESS_INVALID");
  });
}

const PROTOCOL_VERSION_TAG =
  "0x2afe8a5679df289719eae23ad89b300434b9dfbb8194dad0b50dee97f91a3868";
const SPEND_ARTIFACT_HASH =
  "0xac2082ecb2129c571d2ddeb170f261a0da074491773102fa4f1544e97eb19281";

function publicInputBytes(value: string): Buffer {
  if (value.startsWith("0x") || value.startsWith("0X")) {
    const hex = value.slice(2).padStart(64, "0");
    if (hex.length !== 64) {
      throw new Error("ENCODING_INVALID");
    }
    return Buffer.from(hex, "hex");
  }
  return Buffer.from(BigInt(value).toString(16).padStart(64, "0"), "hex");
}

function fieldInRange(bytes: Buffer) {
  return bytes.compare(BN254_R) < 0;
}

/** Reject a spend public-input vector that is not 29 canonical fields. */
export function checkSpendPublicInputs(inputs: string[]) {
  if (inputs.length !== SPEND_PUBLIC_CAMEL.length) {
    throw new Error("ENCODING_INVALID");
  }
  const fields = inputs.map(publicInputBytes);
  for (const field of fields) {
    if (!fieldInRange(field)) {
      throw new Error("FIELD_OUT_OF_RANGE");
    }
  }
  if (`0x${fields[0].toString("hex")}` !== PROTOCOL_VERSION_TAG) {
    throw new Error("VERSION_UNSUPPORTED");
  }
  const action = Number(BigInt(`0x${fields[16].toString("hex")}`));
  if (action < 1 || action > 5) {
    throw new Error("ENCODING_INVALID");
  }
  if (
    action === 1 &&
    !(fields[7].equals(Buffer.alloc(32)) &&
      fields[12].equals(Buffer.alloc(32)) &&
      fields[13].equals(Buffer.alloc(32)))
  ) {
    throw new Error("ENCODING_INVALID");
  }
}

/** Keccak-256 of the 29 packed 32-byte public inputs. */
export function developmentProofDigest(inputs: string[]) {
  const packed = Buffer.concat(inputs.map(publicInputBytes));
  return toHex(keccak256(packed));
}

/** Development-only verify used until T7.4 supplies ceremony keys. */
export function verifyDevelopmentSpend(inputs: string[], proof: string, artifactHash: string) {
  if (artifactHash.toLowerCase() !== SPEND_ARTIFACT_HASH) {
    throw new ProverError("ARTIFACT_INVALID");
  }
  checkSpendPublicInputs(inputs);
  if (proof.toLowerCase() !== developmentProofDigest(inputs)) {
    throw new ProverError("PROOF_INVALID");
  }
  return true;
}

/** Production pairing is unavailable until the T7.4 ceremony. */
export function verifyProductionSpend() {
  throw new ProverError("KEYS_MISSING");
}

/** Browser/Node proving session with cancel, progress, and secret clearing. */
export function createProverSession() {
  let cancelled = false;
  const secrets: Uint8Array[] = [];
  const progress: string[] = [];

  function checkCancelled() {
    if (cancelled) {
      throw new ProverError("CANCELLED");
    }
  }

  return {
    cancel() {
      cancelled = true;
    },
    retainSecret(secret: Uint8Array) {
      secrets.push(secret);
      return secret;
    },
    clear() {
      for (const secret of secrets) {
        secret.fill(0);
      }
      secrets.length = 0;
    },
    stages() {
      return [...progress];
    },
    async proveSpend(circom: Record<string, unknown>) {
      checkCancelled();
      progress.push("spend");
      const zkeyPath = typeof circom.zkeyPath === "string" ? circom.zkeyPath : "";
      if (!zkeyPath) {
        throw new ProverError("KEYS_MISSING");
      }
      const circuitId = String(circom.circuit_id ?? circom.circuitId ?? "");
      if (circuitId !== "haze-spend-v1" || /equality|rehearsal/i.test(zkeyPath)) {
        throw new ProverError("ARTIFACT_INVALID");
      }
      const exists = await pathExists(zkeyPath);
      if (!exists) {
        throw new ProverError("KEYS_MISSING");
      }
      const wasmPath = typeof circom.wasmPath === "string" ? circom.wasmPath : "";
      if (!wasmPath || !(await pathExists(wasmPath))) {
        throw new ProverError("WITNESS_INVALID");
      }
      return proveOperatorGroth16(circom, zkeyPath, wasmPath);
    },
    async proveDevelopment(publicValue: number): Promise<DevelopmentProof> {
      checkCancelled();
      progress.push("development");
      return {
        profile: "development",
        notForProduction: true,
        publicValue,
        verified: true,
      };
    },
  };
}

export type ProverSession = ReturnType<typeof createProverSession>;

export type WorkerInbound = {
  type: string;
  value?: number;
  circom?: Record<string, unknown>;
};

/** Worker message handler used by the browser proving worker. */
export async function handleProverWorkerMessage(session: ProverSession, message: WorkerInbound) {
  if (message.type === "cancel") {
    session.cancel();
    return { type: "cancelled" } satisfies WorkerOutbound;
  }
  if (message.type === "clear") {
    session.clear();
    return { type: "cleared" } satisfies WorkerOutbound;
  }
  if (message.type === "prove-development") {
    const proof = await session.proveDevelopment(message.value ?? 0);
    return { type: "proof", proof, stages: session.stages() } satisfies WorkerOutbound;
  }
  if (message.type === "prove-spend") {
    return session.proveSpend(message.circom ?? {});
  }
  throw new ProverError("WITNESS_INVALID");
}
