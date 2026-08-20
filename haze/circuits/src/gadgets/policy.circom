pragma circom 2.2.2;

include "../poseidon2/poseidon2_sponge.circom";

template GlobalBlockedNote() {
    signal output out;
    signal input domain;
    signal input chainId;
    signal input applicationIdHi;
    signal input applicationIdLo;
    signal input notePublicKey;
    signal input encryptionKeyHash;

    component h = Poseidon2Sponge(5);
    h.domain <== domain;
    h.in[0] <== chainId;
    h.in[1] <== applicationIdHi;
    h.in[2] <== applicationIdLo;
    h.in[3] <== notePublicKey;
    h.in[4] <== encryptionKeyHash;
    out <== h.out;
}

template GlobalBlockedAddress() {
    signal output out;
    signal input domain;
    signal input chainId;
    signal input address;

    component h = Poseidon2Sponge(2);
    h.domain <== domain;
    h.in[0] <== chainId;
    h.in[1] <== address;
    out <== h.out;
}

template ApplicationMember() {
    signal output out;
    signal input domain;
    signal input applicationIdHi;
    signal input applicationIdLo;
    signal input notePublicKey;
    signal input encryptionKeyHash;

    component h = Poseidon2Sponge(4);
    h.domain <== domain;
    h.in[0] <== applicationIdHi;
    h.in[1] <== applicationIdLo;
    h.in[2] <== notePublicKey;
    h.in[3] <== encryptionKeyHash;
    out <== h.out;
}
