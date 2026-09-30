export type BrowserAuditFacts = {
  chainId: number; pool: string; poolVersion: string; applicationId: string; action: number;
  authorizedUser: string; usdc: string; publicAmount: number; publicRecipient: string;
  applicationPolicyVersion: number; hazePolicyVersion: number; actionReference: string;
  inputEnabled: number[]; inputValues: number[]; inputNotePublicKeys: string[];
  inputEncryptionKeyHashes: string[]; inputNullifiers: string[]; outputEnabled: number[];
  outputValues: number[]; outputNotePublicKeys: string[]; outputEncryptionKeyHashes: string[];
  outputCommitments: string[]; recipientCiphertextHashes: string[]; auditSalt: string;
};

function concat(...parts: Uint8Array[]) {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
}

function uint(major: number, input: number | bigint): Uint8Array {
  const value = BigInt(input);
  if (value < 24n) return Uint8Array.of((major << 5) | Number(value));
  const sizes = [[0x100n, 24, 1], [0x1_0000n, 25, 2], [0x1_0000_0000n, 26, 4]] as const;
  const selected = sizes.find(([limit]) => value < limit) ?? [1n << 65n, 27, 8] as const;
  const bytes = new Uint8Array(selected[2]); let cursor = value;
  for (let index = bytes.length - 1; index >= 0; index -= 1) { bytes[index] = Number(cursor & 255n); cursor >>= 8n; }
  if (cursor !== 0n) throw new Error("ENCODING_INVALID");
  return concat(Uint8Array.of((major << 5) | selected[1]), bytes);
}

function hex(value: string) {
  const raw = value.replace(/^0x/, "");
  if (raw.length % 2 || !/^[0-9a-f]*$/i.test(raw)) throw new Error("ENCODING_INVALID");
  return Uint8Array.from(raw.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));
}
const bstr = (value: Uint8Array) => concat(uint(2, value.length), value);
const array = (values: Uint8Array[]) => concat(uint(4, values.length), ...values);
const map = (values: Uint8Array[]) => concat(uint(5, values.length / 2), ...values);
const key = (value: number) => uint(0, value);
const numberPair = (values: number[]) => array(values.map((value) => uint(0, value)));
const hexArray = (values: string[]) => array(values.map((value) => bstr(hex(value))));

/** RFC 8949 deterministic encoding of the frozen Haze v1 audit record. */
export function encodeBrowserAuditRecord(facts: BrowserAuditFacts, caseTag: Uint8Array) {
  if (BigInt(facts.auditSalt) === 0n) throw new Error("FIELD_OUT_OF_RANGE");
  const values = [
    uint(0, facts.chainId), bstr(hex(facts.pool)), bstr(hex(facts.poolVersion)), bstr(hex(facts.applicationId)),
    uint(0, facts.action), bstr(hex(facts.authorizedUser)), bstr(hex(facts.usdc)), uint(0, facts.publicAmount),
    bstr(hex(facts.publicRecipient)), uint(0, facts.applicationPolicyVersion), uint(0, facts.hazePolicyVersion),
    bstr(hex(facts.actionReference)), numberPair(facts.inputEnabled), numberPair(facts.inputValues),
    hexArray(facts.inputNotePublicKeys), hexArray(facts.inputEncryptionKeyHashes), hexArray(facts.inputNullifiers),
    numberPair(facts.outputEnabled), numberPair(facts.outputValues), hexArray(facts.outputNotePublicKeys),
    hexArray(facts.outputEncryptionKeyHashes), hexArray(facts.outputCommitments), hexArray(facts.recipientCiphertextHashes),
    bstr(hex(facts.auditSalt)),
  ];
  const factEntries = values.flatMap((value, index) => [key(index + 1), value]);
  return map([key(1), map(factEntries), key(2), map([key(1), bstr(caseTag)])]);
}
