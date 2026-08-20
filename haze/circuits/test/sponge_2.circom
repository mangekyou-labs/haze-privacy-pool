pragma circom 2.2.2;

include "../src/poseidon2/poseidon2_sponge.circom";

component main {public [domain, in]} = Poseidon2Sponge(2);
