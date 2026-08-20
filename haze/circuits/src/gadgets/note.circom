pragma circom 2.2.2;

include "../poseidon2/poseidon2_sponge.circom";

template NonZero() {
    signal input in;
    signal inv;
    inv <-- in == 0 ? 0 : 1 / in;
    in * inv === 1;
}

template NotePublicKey() {
    signal output out;
    signal input domain;
    signal input spendingSecret;

    component nz = NonZero();
    nz.in <== spendingSecret;

    component h = Poseidon2Sponge(1);
    h.domain <== domain;
    h.in[0] <== spendingSecret;
    out <== h.out;
}

template NoteCommitment() {
    signal output out;
    signal input domain;
    signal input poolDomain;
    signal input applicationIdHi;
    signal input applicationIdLo;
    signal input value;
    signal input ownerNotePublicKey;
    signal input ownerEncryptionKeyHash;
    signal input blinding;

    component nz = NonZero();
    nz.in <== blinding;

    component h = Poseidon2Sponge(7);
    h.domain <== domain;
    h.in[0] <== poolDomain;
    h.in[1] <== applicationIdHi;
    h.in[2] <== applicationIdLo;
    h.in[3] <== value;
    h.in[4] <== ownerNotePublicKey;
    h.in[5] <== ownerEncryptionKeyHash;
    h.in[6] <== blinding;
    out <== h.out;
}

template EncryptionKeyHash() {
    signal output out;
    signal input domain;
    signal input x25519Hi;
    signal input x25519Lo;

    component h = Poseidon2Sponge(2);
    h.domain <== domain;
    h.in[0] <== x25519Hi;
    h.in[1] <== x25519Lo;
    out <== h.out;
}

template Nullifier() {
    signal output out;
    signal input domain;
    signal input poolDomain;
    signal input applicationIdHi;
    signal input applicationIdLo;
    signal input commitment;
    signal input leafIndex;
    signal input spendingSecret;

    component nz = NonZero();
    nz.in <== spendingSecret;

    component h = Poseidon2Sponge(6);
    h.domain <== domain;
    h.in[0] <== poolDomain;
    h.in[1] <== applicationIdHi;
    h.in[2] <== applicationIdLo;
    h.in[3] <== commitment;
    h.in[4] <== leafIndex;
    h.in[5] <== spendingSecret;
    out <== h.out;
}
