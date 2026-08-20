pragma circom 2.2.2;

include "../poseidon2/poseidon2_sponge.circom";
include "note.circom";

template AuditDataCommitment() {
    signal output out;
    signal input domain;
    signal input in[40];

    component nz = NonZero();
    nz.in <== in[39];

    component h = Poseidon2Sponge(40);
    h.domain <== domain;
    for (var i = 0; i < 40; i++) {
        h.in[i] <== in[i];
    }
    out <== h.out;
}
