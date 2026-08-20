import { domainField, protocolVersionTag } from "../sdk/typescript/src/domain.ts";
import { intentDigest } from "../sdk/typescript/src/eip712.ts";
import { encodeEnvelope, envelopeHash } from "../sdk/typescript/src/envelope.ts";
import {
  bytes32Limbs,
  fieldFromAddress,
  fieldFromHex,
  fieldFromU128,
  fieldToHex,
} from "../sdk/typescript/src/field.ts";
import {
  APP_TREE,
  BLOCK_TREE,
  BLOCKLIST_LOWER_SENTINEL,
  TREE_DEPTH,
  blocklistUpperSentinel,
  parentNode,
} from "../sdk/typescript/src/merkle.ts";
import {
  encryptionKeyHash,
  noteCommitment,
  notePublicKey,
  nullifier,
} from "../sdk/typescript/src/note.ts";
import { poseidon2Hash } from "../sdk/typescript/src/poseidon2.ts";
import { applicationMember } from "../sdk/typescript/src/policy.ts";

const NOTE_TREE = "haze/avalanche/v1/note-tree-node";
const ZERO = `0x${"00".repeat(32)}`;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const FIXTURE_POOL = "0x1111111111111111111111111111111111111111";
const FIXTURE_USER = "0x2222222222222222222222222222222222222222";
const FIXTURE_USDC = "0x5425890298aed601595a70AB815c96711a31Bc65";
const FIXTURE_APP = `0x${"aa".repeat(32)}`;
const FIXTURE_POOL_VERSION = `0x${"bb".repeat(32)}`;
const FIXTURE_ACTION_REFERENCE = `0x${"01".repeat(32)}`;
const FIXTURE_X25519 = "0x851fe1e88c633c75d58459b39cdd10b0ea81d42ef73d36cc46ea05eb2de45947";
const DEPOSIT = 1;
const WITHDRAW = 3;
const FUJI_CHAIN_ID = 43113;
const AUDIT_SALT = 3n;

export const FIXTURE_DEPOSIT_MEMBERSHIP_ROOT =
  "0x107349b32230536040e2ba6709f3c93c7c424a3c0f1a7c8edadee7e429e21e7b";
export const FIXTURE_DEPOSIT_COMMITMENT =
  "0x12f9ba3a528b60b24a66982d68570b38eb9a93e96d0224fd1a4cc0051fbbe76f";
export const BLOCKLIST_SENTINEL_ROOT =
  "0x2f9120bf4979f6f079577e2eaeb96fd996129dbd24a0855fbd0fe7e30669716d";

function fieldHex(value) {
  if (typeof value === "string") {
    if (/^0x[0-9a-fA-F]{40}$/.test(value)) {
      return fieldToHex(fieldFromAddress(value));
    }
    return fieldToHex(BigInt(value));
  }
  if (typeof value === "bigint") {
    return fieldToHex(value);
  }
  return fieldToHex(BigInt(value));
}

function dec(value) {
  return value.toString();
}

function limbsHex(value) {
  const [hi, lo] = bytes32Limbs(value);
  return [fieldToHex(hi), fieldToHex(lo)];
}

function zeroPath() {
  return Array.from({ length: TREE_DEPTH }, () => ZERO);
}

function zeroHashes(domain) {
  const hashes = [ZERO];
  let zero = ZERO;
  for (let level = 0; level < TREE_DEPTH; level += 1) {
    zero = parentNode(domain, level, zero, zero);
    hashes.push(zero);
  }
  return hashes;
}

export class SparseMerkleTree {
  constructor(domain) {
    this.domain = domain;
    this.leaves = new Map();
  }

  insert(index, leaf) {
    this.leaves.set(Number(index), leaf);
  }

  occupied(level, index) {
    for (const leaf of this.leaves.keys()) {
      if (BigInt(leaf) >> BigInt(level) === index) {
        return true;
      }
    }
    return false;
  }

  node(level, index, zeros) {
    if (level === 0) {
      return this.leaves.get(Number(index)) ?? ZERO;
    }
    if (!this.occupied(level, index)) {
      return zeros[level];
    }
    const left = this.node(level - 1, index * 2n, zeros);
    const right = this.node(level - 1, index * 2n + 1n, zeros);
    return parentNode(this.domain, level - 1, left, right);
  }

  root() {
    return this.node(TREE_DEPTH, 0n, zeroHashes(this.domain));
  }

  path(index) {
    const zeros = zeroHashes(this.domain);
    const siblings = [];
    let cursor = BigInt(index);
    for (let level = 0; level < TREE_DEPTH; level += 1) {
      siblings.push(this.node(level, cursor ^ 1n, zeros));
      cursor >>= 1n;
    }
    return siblings;
  }
}

export function sentinelBlocklistTree() {
  const tree = new SparseMerkleTree(BLOCK_TREE);
  tree.insert(0, BLOCKLIST_LOWER_SENTINEL);
  tree.insert(1, blocklistUpperSentinel());
  return tree;
}

function toHexBytes(bytes) {
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

function dummyRecipientEnvelope(tag) {
  const encap = `0x${tag.toString(16).padStart(2, "0").repeat(32)}`;
  const next = ((tag + 1) & 0xff).toString(16).padStart(2, "0");
  const envelope = {
    purpose: "recipient",
    keyVersion: 0n,
    encapsulatedKey: encap,
    ciphertext: `0x${next.repeat(48)}`,
  };
  return { hash: envelopeHash(envelope), bytes: toHexBytes(encodeEnvelope(envelope)) };
}

function dummyAuditEnvelope() {
  const envelope = {
    purpose: "audit",
    keyVersion: 1n,
    encapsulatedKey: `0x${"33".repeat(32)}`,
    ciphertext: `0x${"44".repeat(64)}`,
  };
  return { hash: envelopeHash(envelope), bytes: toHexBytes(encodeEnvelope(envelope)) };
}

function dummyRecipientHash(tag) {
  return dummyRecipientEnvelope(tag).hash;
}

function dummyAuditHash() {
  return dummyAuditEnvelope().hash;
}

function dummySlot() {
  return {
    enabled: false,
    value: 0,
    secret: ZERO,
    blinding: ZERO,
    x25519: ZERO,
    xHi: ZERO,
    xLo: ZERO,
    npk: ZERO,
    enc: ZERO,
    commitment: ZERO,
    nullifier: ZERO,
    leafIndex: 0,
    noteSiblings: zeroPath(),
    memberIndex: 0,
    memberSiblings: zeroPath(),
    blockLowerIndex: 0,
    blockLowerLeaf: ZERO,
    blockUpperLeaf: ZERO,
    blockLowerSiblings: zeroPath(),
    blockUpperSiblings: zeroPath(),
  };
}

function enabledSlot(spec, bindings) {
  const secret = fieldHex(spec.secret);
  const blinding = fieldHex(spec.blinding);
  const x25519 = spec.x25519 ?? FIXTURE_X25519;
  const [xHi, xLo] = limbsHex(x25519);
  const npk = notePublicKey(secret);
  const enc = encryptionKeyHash(x25519);
  const commitment = noteCommitment({
    chainId: FUJI_CHAIN_ID,
    pool: bindings.pool,
    poolVersion: bindings.poolVersion,
    applicationId: bindings.applicationId,
    value: spec.value,
    ownerNotePublicKey: npk,
    ownerEncryptionKeyHash: enc,
    blinding,
  });
  const nf = nullifier({
    chainId: FUJI_CHAIN_ID,
    pool: bindings.pool,
    poolVersion: bindings.poolVersion,
    applicationId: bindings.applicationId,
    commitment,
    leafIndex: spec.leafIndex,
    spendingSecret: secret,
  });
  const slot = dummySlot();
  slot.enabled = true;
  slot.value = spec.value;
  slot.secret = secret;
  slot.blinding = blinding;
  slot.x25519 = x25519;
  slot.xHi = xHi;
  slot.xLo = xLo;
  slot.npk = npk;
  slot.enc = enc;
  slot.commitment = commitment;
  slot.nullifier = nf;
  slot.leafIndex = spec.leafIndex;
  return slot;
}

function fillPolicyPaths(slots, applicationId, appTree, blockTree) {
  const lowerSibs = blockTree.path(0);
  const upperSibs = blockTree.path(1);
  const upper = blocklistUpperSentinel();
  for (const slot of slots) {
    if (!slot.enabled) {
      continue;
    }
    const member = applicationMember(applicationId, slot.npk, slot.enc);
    let found;
    for (let index = 0; index < 8; index += 1) {
      const path = appTree.path(index);
      const reconstructed = rootFromAppPath(member, index, path);
      if (reconstructed === appTree.root()) {
        found = { index, path };
        break;
      }
    }
    if (!found) {
      throw Object.assign(new Error("membership path missing"), { code: "ENCODING_INVALID" });
    }
    slot.memberIndex = found.index;
    slot.memberSiblings = found.path;
    slot.blockLowerIndex = 0;
    slot.blockLowerLeaf = BLOCKLIST_LOWER_SENTINEL;
    slot.blockUpperLeaf = upper;
    slot.blockLowerSiblings = lowerSibs;
    slot.blockUpperSiblings = upperSibs;
  }
}

function rootFromAppPath(leaf, index, siblings) {
  let node = leaf;
  let cursor = index;
  for (let level = 0; level < TREE_DEPTH; level += 1) {
    node =
      (cursor & 1) === 0
        ? parentNode(APP_TREE, level, node, siblings[level])
        : parentNode(APP_TREE, level, siblings[level], node);
    cursor >>= 1;
  }
  return node;
}

export function auditDataCommitment(input) {
  if (fieldFromHex(input.auditSalt) === 0n) {
    throw Object.assign(new Error("audit salt must be nonzero"), { code: "FIELD_OUT_OF_RANGE" });
  }
  const [poolHi, poolLo] = bytes32Limbs(input.poolVersion);
  const [appHi, appLo] = bytes32Limbs(input.applicationId);
  const [refHi, refLo] = bytes32Limbs(input.actionReference);
  const [rc0Hi, rc0Lo] = bytes32Limbs(input.recipientCiphertextHashes[0]);
  const [rc1Hi, rc1Lo] = bytes32Limbs(input.recipientCiphertextHashes[1]);
  const fields = [
    fieldFromU128(input.chainId),
    fieldFromAddress(input.pool),
    poolHi,
    poolLo,
    appHi,
    appLo,
    fieldFromU128(input.action),
    fieldFromAddress(input.authorizedUser),
    fieldFromAddress(input.usdc),
    fieldFromU128(input.publicAmount),
    fieldFromAddress(input.publicRecipient),
    fieldFromU128(input.applicationPolicyVersion),
    fieldFromU128(input.hazePolicyVersion),
    refHi,
    refLo,
    fieldFromU128(input.inputEnabled[0]),
    fieldFromU128(input.inputEnabled[1]),
    fieldFromU128(input.inputValues[0]),
    fieldFromU128(input.inputValues[1]),
    fieldFromHex(input.inputNotePublicKeys[0]),
    fieldFromHex(input.inputNotePublicKeys[1]),
    fieldFromHex(input.inputEncryptionKeyHashes[0]),
    fieldFromHex(input.inputEncryptionKeyHashes[1]),
    fieldFromHex(input.inputNullifiers[0]),
    fieldFromHex(input.inputNullifiers[1]),
    fieldFromU128(input.outputEnabled[0]),
    fieldFromU128(input.outputEnabled[1]),
    fieldFromU128(input.outputValues[0]),
    fieldFromU128(input.outputValues[1]),
    fieldFromHex(input.outputNotePublicKeys[0]),
    fieldFromHex(input.outputNotePublicKeys[1]),
    fieldFromHex(input.outputEncryptionKeyHashes[0]),
    fieldFromHex(input.outputEncryptionKeyHashes[1]),
    fieldFromHex(input.outputCommitments[0]),
    fieldFromHex(input.outputCommitments[1]),
    rc0Hi,
    rc0Lo,
    rc1Hi,
    rc1Lo,
    fieldFromHex(input.auditSalt),
  ];
  return fieldToHex(poseidon2Hash(domainField("haze/avalanche/v1/audit-data"), fields));
}

function pairDec(a, b) {
  return [dec(a), dec(b)];
}

function pairHex(a, b) {
  return [a, b];
}

function pairPath(a, b) {
  return [a, b];
}

function buildCase(input) {
  const action = input.action;
  const bindings = {
    pool: input.pool,
    user: input.user,
    usdc: input.usdc ?? FIXTURE_USDC,
    applicationId: input.applicationId,
    poolVersion: input.poolVersion,
    actionReference: input.actionReference ?? FIXTURE_ACTION_REFERENCE,
  };
  const publicAmount = input.publicAmount;
  const publicRecipient = input.publicRecipient ?? ZERO_ADDRESS;

  const inSlots = [dummySlot(), dummySlot()];
  const outSlots = [dummySlot(), dummySlot()];
  (input.inputs ?? []).forEach((spec, index) => {
    if (spec) {
      inSlots[index] = enabledSlot(spec, bindings);
    }
  });
  (input.outputs ?? []).forEach((spec, index) => {
    if (spec) {
      outSlots[index] = enabledSlot(spec, bindings);
    }
  });

  const noteTree = new SparseMerkleTree(NOTE_TREE);
  if (action !== DEPOSIT) {
    const extras = Array.isArray(input.treeLeaves) ? input.treeLeaves : [];
    if (extras.length > 0) {
      for (const leaf of extras) {
        noteTree.insert(leaf.leafIndex, leaf.commitment);
      }
    } else {
      for (const slot of inSlots) {
        if (slot.enabled) {
          noteTree.insert(slot.leafIndex, slot.commitment);
        }
      }
    }
    for (const slot of inSlots) {
      if (slot.enabled) {
        slot.noteSiblings = noteTree.path(slot.leafIndex);
      }
    }
  }

  const appTree = new SparseMerkleTree(APP_TREE);
  let nextMember = 0;
  const seen = new Set();
  for (const slot of [...inSlots, ...outSlots]) {
    if (!slot.enabled) {
      continue;
    }
    const key = `${slot.npk}:${slot.enc}`;
    if (seen.has(key)) {
      continue;
    }
    appTree.insert(nextMember, applicationMember(bindings.applicationId, slot.npk, slot.enc));
    seen.add(key);
    nextMember += 1;
  }
  const blockTree = sentinelBlocklistTree();
  fillPolicyPaths(inSlots, bindings.applicationId, appTree, blockTree);
  fillPolicyPaths(outSlots, bindings.applicationId, appTree, blockTree);

  const screen = action === DEPOSIT || action === WITHDRAW;
  const screened = action === WITHDRAW ? publicRecipient : action === DEPOSIT ? bindings.user : ZERO_ADDRESS;
  let addressLowerIndex = 0;
  let addressLowerLeaf = ZERO;
  let addressUpperLeaf = ZERO;
  let addressLowerSibs = zeroPath();
  let addressUpperSibs = zeroPath();
  if (screen) {
    addressLowerLeaf = BLOCKLIST_LOWER_SENTINEL;
    addressUpperLeaf = blocklistUpperSentinel();
    addressLowerSibs = blockTree.path(0);
    addressUpperSibs = blockTree.path(1);
    void screened;
  }

  const recipient0 = outSlots[0].enabled ? dummyRecipientEnvelope(0x11) : { hash: ZERO, bytes: "0x" };
  const recipient1 = outSlots[1].enabled ? dummyRecipientEnvelope(0x21) : { hash: ZERO, bytes: "0x" };
  const auditEnvelope = dummyAuditEnvelope();
  const rc0 = recipient0.hash;
  const rc1 = recipient1.hash;
  const auditCt = auditEnvelope.hash;
  const [rc0Hi, rc0Lo] = limbsHex(rc0);
  const [rc1Hi, rc1Lo] = limbsHex(rc1);
  const [auditCtHi, auditCtLo] = limbsHex(auditCt);
  const [appHi, appLo] = limbsHex(bindings.applicationId);
  const [poolHi, poolLo] = limbsHex(bindings.poolVersion);
  const [refHi, refLo] = limbsHex(bindings.actionReference);

  const noteTreeRoot = action === DEPOSIT ? ZERO : noteTree.root();
  const nf0 = inSlots[0].enabled ? inSlots[0].nullifier : ZERO;
  const nf1 = inSlots[1].enabled ? inSlots[1].nullifier : ZERO;
  const cm0 = outSlots[0].enabled ? outSlots[0].commitment : ZERO;
  const cm1 = outSlots[1].enabled ? outSlots[1].commitment : ZERO;

  const auditSalt = fieldHex(AUDIT_SALT);
  const auditCommitment = auditDataCommitment({
    chainId: FUJI_CHAIN_ID,
    pool: bindings.pool,
    poolVersion: bindings.poolVersion,
    applicationId: bindings.applicationId,
    action,
    authorizedUser: bindings.user,
    usdc: bindings.usdc,
    publicAmount,
    publicRecipient,
    applicationPolicyVersion: 1,
    hazePolicyVersion: 1,
    actionReference: bindings.actionReference,
    inputEnabled: [inSlots[0].enabled ? 1 : 0, inSlots[1].enabled ? 1 : 0],
    inputValues: [inSlots[0].value, inSlots[1].value],
    inputNotePublicKeys: [inSlots[0].npk, inSlots[1].npk],
    inputEncryptionKeyHashes: [inSlots[0].enc, inSlots[1].enc],
    inputNullifiers: [nf0, nf1],
    outputEnabled: [outSlots[0].enabled ? 1 : 0, outSlots[1].enabled ? 1 : 0],
    outputValues: [outSlots[0].value, outSlots[1].value],
    outputNotePublicKeys: [outSlots[0].npk, outSlots[1].npk],
    outputEncryptionKeyHashes: [outSlots[0].enc, outSlots[1].enc],
    outputCommitments: [cm0, cm1],
    recipientCiphertextHashes: [rc0, rc1],
    auditSalt,
  });

  const intentHash = intentDigest(
    {
      applicationId: bindings.applicationId,
      user: bindings.user,
      pool: bindings.pool,
      poolVersion: bindings.poolVersion,
      action,
      noteTreeRoot,
      applicationPolicyVersion: 1,
      hazePolicyVersion: 1,
      applicationMembershipRoot: appTree.root(),
      hazeBlocklistRoot: blockTree.root(),
      inputNullifier0: nf0,
      inputNullifier1: nf1,
      outputCommitment0: cm0,
      outputCommitment1: cm1,
      publicAmount,
      publicRecipient,
      recipientCiphertextHash0: rc0,
      recipientCiphertextHash1: rc1,
      auditDataCommitment: auditCommitment,
      auditCiphertextHash: auditCt,
      tokenIn: ZERO_ADDRESS,
      amountIn: ZERO,
      minUsdcOut: 0,
      routeHash: ZERO,
      deadline: 0,
    },
    FUJI_CHAIN_ID,
  );
  const [intentHi, intentLo] = limbsHex(intentHash);

  const circom = {
    protocolVersionTag: fieldHex(protocolVersionTag()),
    chainId: dec(FUJI_CHAIN_ID),
    poolAddress: fieldHex(bindings.pool),
    poolVersionHi: poolHi,
    poolVersionLo: poolLo,
    applicationIdHi: appHi,
    applicationIdLo: appLo,
    noteTreeRoot,
    applicationPolicyVersion: dec(1),
    hazePolicyVersion: dec(1),
    applicationMembershipRoot: appTree.root(),
    hazeBlocklistRoot: blockTree.root(),
    inputNullifier0: nf0,
    inputNullifier1: nf1,
    outputCommitment0: cm0,
    outputCommitment1: cm1,
    action: dec(action),
    publicAmount: dec(publicAmount),
    publicRecipient: fieldHex(publicRecipient),
    authorizedUser: fieldHex(bindings.user),
    intentHashHi: intentHi,
    intentHashLo: intentLo,
    recipientCiphertextHash0Hi: rc0Hi,
    recipientCiphertextHash0Lo: rc0Lo,
    recipientCiphertextHash1Hi: rc1Hi,
    recipientCiphertextHash1Lo: rc1Lo,
    auditDataCommitment: auditCommitment,
    auditCiphertextHashHi: auditCtHi,
    auditCiphertextHashLo: auditCtLo,
    usdcAddress: fieldHex(bindings.usdc),
    actionReferenceHi: refHi,
    actionReferenceLo: refLo,
    auditSalt,
    inValue: pairDec(inSlots[0].value, inSlots[1].value),
    inSpendingSecret: pairHex(inSlots[0].secret, inSlots[1].secret),
    inBlinding: pairHex(inSlots[0].blinding, inSlots[1].blinding),
    inX25519Hi: pairHex(inSlots[0].xHi, inSlots[1].xHi),
    inX25519Lo: pairHex(inSlots[0].xLo, inSlots[1].xLo),
    inLeafIndex: pairDec(inSlots[0].leafIndex, inSlots[1].leafIndex),
    inNoteSiblings: pairPath(inSlots[0].noteSiblings, inSlots[1].noteSiblings),
    inAppMemberIndex: pairDec(inSlots[0].memberIndex, inSlots[1].memberIndex),
    inAppMemberSiblings: pairPath(inSlots[0].memberSiblings, inSlots[1].memberSiblings),
    inBlockLowerIndex: pairDec(inSlots[0].blockLowerIndex, inSlots[1].blockLowerIndex),
    inBlockLowerLeaf: pairHex(inSlots[0].blockLowerLeaf, inSlots[1].blockLowerLeaf),
    inBlockUpperLeaf: pairHex(inSlots[0].blockUpperLeaf, inSlots[1].blockUpperLeaf),
    inBlockLowerSiblings: pairPath(inSlots[0].blockLowerSiblings, inSlots[1].blockLowerSiblings),
    inBlockUpperSiblings: pairPath(inSlots[0].blockUpperSiblings, inSlots[1].blockUpperSiblings),
    outValue: pairDec(outSlots[0].value, outSlots[1].value),
    outSpendingSecret: pairHex(outSlots[0].secret, outSlots[1].secret),
    outBlinding: pairHex(outSlots[0].blinding, outSlots[1].blinding),
    outX25519Hi: pairHex(outSlots[0].xHi, outSlots[1].xHi),
    outX25519Lo: pairHex(outSlots[0].xLo, outSlots[1].xLo),
    outAppMemberIndex: pairDec(outSlots[0].memberIndex, outSlots[1].memberIndex),
    outAppMemberSiblings: pairPath(outSlots[0].memberSiblings, outSlots[1].memberSiblings),
    outBlockLowerIndex: pairDec(outSlots[0].blockLowerIndex, outSlots[1].blockLowerIndex),
    outBlockLowerLeaf: pairHex(outSlots[0].blockLowerLeaf, outSlots[1].blockLowerLeaf),
    outBlockUpperLeaf: pairHex(outSlots[0].blockUpperLeaf, outSlots[1].blockUpperLeaf),
    outBlockLowerSiblings: pairPath(outSlots[0].blockLowerSiblings, outSlots[1].blockLowerSiblings),
    outBlockUpperSiblings: pairPath(outSlots[0].blockUpperSiblings, outSlots[1].blockUpperSiblings),
    addressLowerIndex: dec(addressLowerIndex),
    addressLowerLeaf,
    addressUpperLeaf,
    addressLowerSiblings: addressLowerSibs,
    addressUpperSiblings: addressUpperSibs,
  };

  const primary = action === DEPOSIT ? outSlots[0] : inSlots[0];
  return {
    circom,
    note: {
      value: primary.value,
      secret: primary.secret,
      blinding: primary.blinding,
      x25519: primary.x25519,
      npk: primary.npk,
      enc: primary.enc,
      commitment: primary.commitment,
      nullifier: primary.nullifier,
      leafIndex: primary.leafIndex,
    },
    membershipRoot: circom.applicationMembershipRoot,
    hazeBlocklistRoot: circom.hazeBlocklistRoot,
    noteTreeRoot: circom.noteTreeRoot,
    envelopes: {
      recipientCiphertext0: recipient0.bytes,
      recipientCiphertext1: recipient1.bytes,
      auditCiphertext: auditEnvelope.bytes,
      recipientCiphertextHash0: rc0,
      recipientCiphertextHash1: rc1,
      auditCiphertextHash: auditCt,
    },
  };
}

export function buildFixtureDepositWitness() {
  return buildCase({
    action: DEPOSIT,
    pool: FIXTURE_POOL,
    user: FIXTURE_USER,
    applicationId: FIXTURE_APP,
    poolVersion: FIXTURE_POOL_VERSION,
    publicAmount: 1_000_000,
    publicRecipient: ZERO_ADDRESS,
    outputs: [{ value: 1_000_000, secret: 1, blinding: 2, leafIndex: 0 }],
  });
}

export function buildLiveDepositWitness(input) {
  return buildCase({
    action: DEPOSIT,
    pool: input.pool,
    user: input.user,
    applicationId: input.applicationId,
    poolVersion: input.poolVersion,
    publicAmount: input.publicAmount ?? 1_000_000,
    publicRecipient: ZERO_ADDRESS,
    outputs: [
      {
        value: input.value ?? 1_000_000,
        secret: input.secret ?? 1,
        blinding: input.blinding ?? 2,
        leafIndex: input.leafIndex ?? 0,
        x25519: input.x25519,
      },
    ],
  });
}

export function buildLiveWithdrawWitness(input) {
  const note = input.note;
  return buildCase({
    action: WITHDRAW,
    pool: input.pool,
    user: input.user,
    applicationId: input.applicationId,
    poolVersion: input.poolVersion,
    publicAmount: input.publicAmount ?? note.value,
    publicRecipient: input.publicRecipient ?? input.user,
    inputs: [
      {
        value: note.value,
        secret: note.secret,
        blinding: note.blinding,
        leafIndex: note.leafIndex,
        x25519: note.x25519,
      },
    ],
    treeLeaves: input.treeLeaves,
  });
}
