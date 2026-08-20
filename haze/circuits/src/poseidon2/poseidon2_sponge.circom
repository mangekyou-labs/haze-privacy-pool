pragma circom 2.2.2;

include "poseidon2_perm.circom";

// Haze v1 width-3 sponge. This is not legacy Poseidon2(n).
// state = [0, 0, domain]; pad10* rate-2; reject a zero digest.
template Poseidon2Sponge(n) {
    signal output out;
    signal input domain;
    signal input in[n];

    assert(n > 0);
    var numBlocks = n % 2 == 0 ? (n \ 2) + 1 : (n + 1) \ 2;

    signal blocks[numBlocks][2];
    for (var i = 0; i < (n \ 2); i++) {
        blocks[i][0] <== in[2 * i];
        blocks[i][1] <== in[2 * i + 1];
    }
    if (n % 2 == 1) {
        blocks[n \ 2][0] <== in[n - 1];
        blocks[n \ 2][1] <== 1;
    } else {
        blocks[n \ 2][0] <== 1;
        blocks[n \ 2][1] <== 0;
    }

    signal state[numBlocks + 1][3];
    state[0][0] <== 0;
    state[0][1] <== 0;
    state[0][2] <== domain;

    component perm[numBlocks];
    for (var i = 0; i < numBlocks; i++) {
        perm[i] = Permutation(3);
        perm[i].inputs[0] <== state[i][0] + blocks[i][0];
        perm[i].inputs[1] <== state[i][1] + blocks[i][1];
        perm[i].inputs[2] <== state[i][2];
        state[i + 1][0] <== perm[i].out[0];
        state[i + 1][1] <== perm[i].out[1];
        state[i + 1][2] <== perm[i].out[2];
    }

    signal inv;
    inv <-- state[numBlocks][0] == 0 ? 0 : 1 / state[numBlocks][0];
    state[numBlocks][0] * inv === 1;
    out <== state[numBlocks][0];
}
