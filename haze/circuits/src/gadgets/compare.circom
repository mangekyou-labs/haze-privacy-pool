pragma circom 2.2.2;

include "bits.circom";

template LessThan(n) {
    assert(n <= 128);
    signal input a;
    signal input b;
    signal output out;

    var pow = 1;
    for (var i = 0; i < n; i++) {
        pow = pow + pow;
    }
    component n2b = Num2Bits(n + 1);
    n2b.in <== a + pow - b;
    out <== 1 - n2b.out[n];
}

// Compare two field elements via 128+126-bit limbs (r < 2^254).
template FieldLessThan() {
    signal input a;
    signal input b;
    signal output out;

    component bitsA = Num2Bits(254);
    component bitsB = Num2Bits(254);
    bitsA.in <== a;
    bitsB.in <== b;

    var accALo = 0;
    var accBLo = 0;
    var accAHi = 0;
    var accBHi = 0;
    var e = 1;
    for (var i = 0; i < 128; i++) {
        accALo += bitsA.out[i] * e;
        accBLo += bitsB.out[i] * e;
        e = e + e;
    }
    e = 1;
    for (var i = 0; i < 126; i++) {
        accAHi += bitsA.out[128 + i] * e;
        accBHi += bitsB.out[128 + i] * e;
        e = e + e;
    }

    signal aLo;
    signal aHi;
    signal bLo;
    signal bHi;
    aLo <== accALo;
    aHi <== accAHi;
    bLo <== accBLo;
    bHi <== accBHi;

    component ltHi = LessThan(126);
    component ltLo = LessThan(128);
    component eqHi = IsEqual();
    ltHi.a <== aHi;
    ltHi.b <== bHi;
    ltLo.a <== aLo;
    ltLo.b <== bLo;
    eqHi.a <== aHi;
    eqHi.b <== bHi;
    out <== ltHi.out + eqHi.out * ltLo.out;
}
