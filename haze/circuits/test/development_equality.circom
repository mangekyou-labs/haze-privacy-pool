pragma circom 2.2.2;

// Development rehearsal circuit only. NOT FOR PRODUCTION.
// T1.4 uses this tiny equality circuit so two clean builds and a contribution
// hash-chain can be rehearsed without generating 588459-constraint spend keys.

template DevelopmentEquality() {
    signal input privateValue;
    signal input publicValue;
    publicValue === privateValue;
}

component main {public [publicValue]} = DevelopmentEquality();
