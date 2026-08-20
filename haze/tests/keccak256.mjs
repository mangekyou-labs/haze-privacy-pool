const RC = [
  1n, 0x8082n, 0x800000000000808an, 0x8000000080008000n, 0x808bn, 0x80000001n, 0x8000000080008081n,
  0x8000000000008009n, 0x8an, 0x88n, 0x80008009n, 0x8000000an, 0x8000808bn, 0x800000000000008bn,
  0x8000000000008089n, 0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n, 0x800an,
  0x800000008000000an, 0x8000000080008081n, 0x8000000000008080n, 0x80000001n, 0x8000000080008008n,
];

function rotl(x, n) {
  return ((x << BigInt(n)) | (x >> BigInt(64 - n))) & 0xffffffffffffffffn;
}

function keccakf(a) {
  const rotc = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];
  const piln = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];
  for (let round = 0; round < 24; round += 1) {
    const c = [];
    for (let i = 0; i < 5; i += 1) {
      c[i] = a[i] ^ a[i + 5] ^ a[i + 10] ^ a[i + 15] ^ a[i + 20];
    }
    for (let i = 0; i < 5; i += 1) {
      const d = c[(i + 4) % 5] ^ rotl(c[(i + 1) % 5], 1);
      for (let j = 0; j < 25; j += 5) {
        a[j + i] ^= d;
      }
    }
    let [x, t] = [1, a[1]];
    for (let i = 0; i < 24; i += 1) {
      const j = piln[i];
      [a[j], x, t] = [rotl(t, rotc[i]), j, a[j]];
    }
    for (let j = 0; j < 25; j += 5) {
      const tmp = a.slice(j, j + 5);
      for (let i = 0; i < 5; i += 1) {
        a[j + i] = tmp[i] ^ (~tmp[(i + 1) % 5] & tmp[(i + 2) % 5]);
      }
    }
    a[0] ^= RC[round];
  }
}

export function keccak256(data) {
  const input = Buffer.from(data);
  const rate = 136;
  const state = Array.from({ length: 25 }, () => 0n);
  const padded = Buffer.concat([input, Buffer.alloc(rate - (input.length % rate))]);
  padded[input.length] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;
  for (let offset = 0; offset < padded.length; offset += rate) {
    for (let i = 0; i < 17; i += 1) {
      let word = 0n;
      for (let b = 0; b < 8; b += 1) {
        word |= BigInt(padded[offset + i * 8 + b]) << BigInt(8 * b);
      }
      state[i] ^= word;
    }
    keccakf(state);
  }
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i += 1) {
    for (let b = 0; b < 8; b += 1) {
      out[i * 8 + b] = Number((state[i] >> BigInt(8 * b)) & 0xffn);
    }
  }
  return out;
}
