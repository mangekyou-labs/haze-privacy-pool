pragma circom 2.2.2;

include "../poseidon2/domains.circom";
include "../poseidon2/poseidon2_sponge.circom";
include "bits.circom";
include "compare.circom";

template MerkleParent() {
    signal output out;
    signal input domain;
    signal input level;
    signal input left;
    signal input right;

    component h = Poseidon2Sponge(3);
    h.domain <== domain;
    h.in[0] <== level;
    h.in[1] <== left;
    h.in[2] <== right;
    out <== h.out;
}

template MerklePath(depth) {
    signal output out;
    signal input domain;
    signal input leaf;
    signal input indexBits[depth];
    signal input siblings[depth];

    signal nodes[depth + 1];
    signal mux[depth];
    signal left[depth];
    signal right[depth];
    nodes[0] <== leaf;

    component parents[depth];
    for (var i = 0; i < depth; i++) {
        indexBits[i] * (indexBits[i] - 1) === 0;
        mux[i] <== (nodes[i] - siblings[i]) * indexBits[i];
        left[i] <== nodes[i] - mux[i];
        right[i] <== siblings[i] + mux[i];
        parents[i] = MerkleParent();
        parents[i].domain <== domain;
        parents[i].level <== i;
        parents[i].left <== left[i];
        parents[i].right <== right[i];
        nodes[i + 1] <== parents[i].out;
    }
    out <== nodes[depth];
}

// Adjacent sorted-blocklist non-membership. When enabled=0 the comparison
// and sentinel checks are skipped; Merkle paths still run (dummy zeros).
template NonMembership(depth) {
    signal output root;
    signal input domain;
    signal input queried;
    signal input enabled;
    signal input lowerLeaf;
    signal input upperLeaf;
    signal input lowerIndex;
    signal input lowerSiblings[depth];
    signal input upperSiblings[depth];

    enabled * (enabled - 1) === 0;
    (1 - enabled) * lowerLeaf === 0;
    (1 - enabled) * upperLeaf === 0;
    (1 - enabled) * lowerIndex === 0;

    component queriedZero = IsZero();
    queriedZero.in <== queried;
    enabled * queriedZero.out === 0;

    component queriedSentinel = IsEqual();
    queriedSentinel.a <== queried;
    queriedSentinel.b <== BN254_R_MINUS_1();
    enabled * queriedSentinel.out === 0;

    component lowerLt = FieldLessThan();
    lowerLt.a <== lowerLeaf;
    lowerLt.b <== queried;
    enabled * (1 - lowerLt.out) === 0;

    component upperLt = FieldLessThan();
    upperLt.a <== queried;
    upperLt.b <== upperLeaf;
    enabled * (1 - upperLt.out) === 0;

    component lowerBits = Num2Bits(depth);
    lowerBits.in <== lowerIndex;
    signal upperIndex;
    upperIndex <== lowerIndex + 1;
    component upperBits = Num2Bits(depth);
    upperBits.in <== upperIndex;

    component lowerPath = MerklePath(depth);
    component upperPath = MerklePath(depth);
    lowerPath.domain <== domain;
    upperPath.domain <== domain;
    lowerPath.leaf <== lowerLeaf;
    upperPath.leaf <== upperLeaf;
    for (var i = 0; i < depth; i++) {
        (1 - enabled) * lowerSiblings[i] === 0;
        (1 - enabled) * upperSiblings[i] === 0;
        lowerPath.indexBits[i] <== lowerBits.out[i];
        upperPath.indexBits[i] <== upperBits.out[i];
        lowerPath.siblings[i] <== lowerSiblings[i];
        upperPath.siblings[i] <== upperSiblings[i];
    }
    lowerPath.out === upperPath.out;
    root <== lowerPath.out;
}
