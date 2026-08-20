pragma circom 2.2.2;

include "../src/gadgets/merkle.circom";

component main {public [domain, leaf, indexBits, siblings]} = MerklePath(32);
