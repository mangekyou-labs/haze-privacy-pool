import { SdkError } from "./errors.ts";
import { BN254_R, fieldToHex } from "./field.ts";
import rc3 from "./poseidon2-rc3.json" with { type: "json" };

const RC: bigint[][] = (rc3 as string[][]).map((round) => round.map((value) => BigInt(value)));

function add(left: bigint, right: bigint) {
  const sum = left + right;
  return sum >= BN254_R ? sum - BN254_R : sum;
}

function mul(left: bigint, right: bigint) {
  return (left * right) % BN254_R;
}

function sbox(value: bigint) {
  const squared = mul(value, value);
  return mul(mul(squared, squared), value);
}

function matmulExternal(state: bigint[]) {
  const sum = add(add(state[0], state[1]), state[2]);
  return [add(state[0], sum), add(state[1], sum), add(state[2], sum)];
}

function matmulInternal(state: bigint[]) {
  const sum = add(add(state[0], state[1]), state[2]);
  return [add(state[0], sum), add(state[1], sum), add(add(state[2], state[2]), sum)];
}

/** BN254 Poseidon2 t=3 permutation (Horizen / zkhash parameters). */
export function poseidon2Permute(input: bigint[]) {
  if (input.length !== 3) {
    throw new SdkError("ENCODING_INVALID");
  }
  let state = matmulExternal(input);
  for (let round = 0; round < 4; round += 1) {
    state = [add(state[0], RC[round][0]), add(state[1], RC[round][1]), add(state[2], RC[round][2])];
    state = [sbox(state[0]), sbox(state[1]), sbox(state[2])];
    state = matmulExternal(state);
  }
  for (let round = 4; round < 60; round += 1) {
    state[0] = sbox(add(state[0], RC[round][0]));
    state = matmulInternal(state);
  }
  for (let round = 60; round < 64; round += 1) {
    state = [add(state[0], RC[round][0]), add(state[1], RC[round][1]), add(state[2], RC[round][2])];
    state = [sbox(state[0]), sbox(state[1]), sbox(state[2])];
    state = matmulExternal(state);
  }
  return state;
}

/** Width-3 pad10* sponge used by Haze note/nullifier hashes. */
export function poseidon2Hash(domain: bigint, fields: bigint[]): bigint {
  let state = [0n, 0n, domain];
  let index = 0;
  while (index + 1 < fields.length) {
    state[0] = add(state[0], fields[index]);
    state[1] = add(state[1], fields[index + 1]);
    state = poseidon2Permute(state);
    index += 2;
  }
  if (index < fields.length) {
    state[0] = add(state[0], fields[index]);
    state[1] = add(state[1], 1n);
    state = poseidon2Permute(state);
  } else {
    state[0] = add(state[0], 1n);
    state = poseidon2Permute(state);
  }
  if (state[0] === 0n) {
    throw new SdkError("FIELD_OUT_OF_RANGE");
  }
  return state[0];
}

export function poseidon2HashHex(domain: bigint, fields: bigint[]): string {
  return fieldToHex(poseidon2Hash(domain, fields));
}
