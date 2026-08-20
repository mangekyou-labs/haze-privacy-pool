pragma circom 2.2.2;

template Num2Bits(n) {
    signal input in;
    signal output out[n];
    var acc = 0;
    var e = 1;
    for (var i = 0; i < n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] - 1) === 0;
        acc += out[i] * e;
        e = e + e;
    }
    acc === in;
}

template IsZero() {
    signal input in;
    signal output out;
    signal inv;
    inv <-- in != 0 ? 1 / in : 0;
    out <== -in * inv + 1;
    in * out === 0;
}

template IsEqual() {
    signal input a;
    signal input b;
    signal output out;
    component iz = IsZero();
    iz.in <== a - b;
    out <== iz.out;
}

template SlotEnable() {
    signal input value;
    signal output enabled;
    signal inv;
    enabled <-- value == 0 ? 0 : 1;
    enabled * (enabled - 1) === 0;
    (1 - enabled) * value === 0;
    inv <-- value == 0 ? 0 : 1 / value;
    value * inv === enabled;
}

template RangeBits(n) {
    signal input in;
    component bits = Num2Bits(n);
    bits.in <== in;
}
