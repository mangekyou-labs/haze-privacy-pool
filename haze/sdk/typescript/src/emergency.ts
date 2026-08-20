import { keccak256 } from "./keccak.ts";

/** Emergency-exit action rejected on normal pool paths. */
export const EMERGENCY_EXIT_ACTION = 5 as const;

/** Seven-day cooldown between request and execute. */
export const EMERGENCY_EXIT_COOLDOWN = 7 * 24 * 60 * 60;

/** ABI type string bound into `request_id`. */
export const EMERGENCY_EXIT_REQUEST_TYPE =
  "HazeEmergencyExitRequest(uint256 chainId,address pool,bytes32 poolVersion,bytes32 applicationId,uint256 nullifier,address recipient,bytes32 requestSalt)" as const;

/** Emergency public inputs in frozen circuit order. */
export const EMERGENCY_PUBLIC_CAMEL = [
  "protocolVersionTag",
  "chainId",
  "poolAddress",
  "poolVersionHi",
  "poolVersionLo",
  "applicationIdHi",
  "applicationIdLo",
  "noteTreeRoot",
  "hazePolicyVersion",
  "hazeBlocklistRoot",
  "inputNullifier",
  "action",
  "publicAmount",
  "publicRecipient",
  "requester",
  "requestIdHi",
  "requestIdLo",
  "auditDataCommitment",
  "auditCiphertextHashHi",
  "auditCiphertextHashLo",
] as const;

export type EmergencyExitRequest = {
  chainId: number | bigint;
  pool: string;
  poolVersion: string;
  applicationId: string;
  nullifier: string;
  recipient: string;
  requestSalt: string;
};

function hexToBuf(value: string): Buffer {
  return Buffer.from(value.replace(/^0x/i, ""), "hex");
}

function toHex(bytes: Uint8Array): string {
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

function addressWord(address: string): Buffer {
  const out = Buffer.alloc(32);
  hexToBuf(address).copy(out, 32 - 20);
  return out;
}

function word(value: number | bigint | string): Buffer {
  const out = Buffer.alloc(32);
  const hex =
    typeof value === "string"
      ? value.replace(/^0x/i, "").padStart(64, "0")
      : BigInt(value).toString(16).padStart(64, "0");
  Buffer.from(hex, "hex").copy(out);
  return out;
}

/** `keccak256(abi.encode(typeHash, chainId, pool, poolVersion, applicationId, nullifier, recipient, requestSalt))`. */
export function emergencyExitRequestId(fields: EmergencyExitRequest): string {
  const encoded = Buffer.concat([
    Buffer.from(keccak256(Buffer.from(EMERGENCY_EXIT_REQUEST_TYPE))),
    word(fields.chainId),
    addressWord(fields.pool),
    word(fields.poolVersion),
    word(fields.applicationId),
    word(fields.nullifier),
    addressWord(fields.recipient),
    word(fields.requestSalt),
  ]);
  return toHex(keccak256(encoded));
}
