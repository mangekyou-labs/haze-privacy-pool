import { type NextRequest, NextResponse } from "next/server.js";
import { FUJI_V2 } from "../../../../../../../../sdk/typescript/src/fuji-v2-defaults.ts";
import { secp256k1 } from "@noble/curves/secp256k1";
import { functionSelector, toHex, hexToBuf } from "../../../../../../../../sdk/typescript/src/abi.ts";
import { encodeMembershipRootUpdate } from "../../../../../../../../sdk/typescript/src/browser-fuji-contracts.ts";
import { keccak256 } from "../../../../../../../../sdk/typescript/src/keccak.ts";
import { parentNode, APP_TREE, TREE_DEPTH } from "../../../../../../../../sdk/typescript/src/merkle.ts";
import { applicationMember } from "../../../../../../../../sdk/typescript/src/policy.ts";
import { DEFAULT_APPLICATION_ID, validateOrigin } from "../../_lib.ts";

const APPLICATION_REGISTRY = process.env.NEXT_PUBLIC_HAZE_APPLICATION_REGISTRY || FUJI_V2.applicationRegistry;
const FUJI_RPC = process.env.HAZE_FUJI_RPC || process.env.NEXT_PUBLIC_HAZE_FUJI_RPC || "https://api.avax-test.network/ext/bc/C/rpc";
const CHAIN_ID = 43113;

class SparseMerkleTree {
  domain: string;
  leaves: Map<number, string>;
  constructor(domain: string) {
    this.domain = domain;
    this.leaves = new Map();
  }
  insert(index: number, leaf: string) {
    this.leaves.set(index, leaf);
  }
  node(level: number, index: bigint, zeros: string[]): string {
    if (level === 0) {
      return this.leaves.get(Number(index)) ?? "0x" + "00".repeat(32);
    }
    let occupied = false;
    for (const leaf of this.leaves.keys()) {
      if (BigInt(leaf) >> BigInt(level) === index) {
        occupied = true;
        break;
      }
    }
    if (!occupied) return zeros[level];
    const left = this.node(level - 1, index * 2n, zeros);
    const right = this.node(level - 1, index * 2n + 1n, zeros);
    return parentNode(this.domain, level - 1, left, right);
  }
  root(): string {
    const zeros = ["0x" + "00".repeat(32)];
    let z = "0x" + "00".repeat(32);
    for (let level = 0; level < TREE_DEPTH; level += 1) {
      z = parentNode(this.domain, level, z, z);
      zeros.push(z);
    }
    return this.node(TREE_DEPTH, 0n, zeros);
  }
}
function rlpEncodeItem(item: unknown): Uint8Array {
  if (typeof item === "string") {
    if (item.startsWith("0x")) {
      const clean = item.slice(2);
      if (clean.length === 0) return Uint8Array.of(0x80);
      const buf = Uint8Array.from(clean.match(/../g) || [], (b) => Number.parseInt(b, 16));
      return rlpEncodeBytes(buf);
    }
    return rlpEncodeBytes(new TextEncoder().encode(item));
  }
  if (typeof item === "number" || typeof item === "bigint") {
    const n = BigInt(item);
    if (n === 0n) return Uint8Array.of(0x80);
    let hex = n.toString(16);
    if (hex.length % 2 !== 0) hex = "0" + hex;
    const buf = Uint8Array.from(hex.match(/../g) || [], (b) => Number.parseInt(b, 16));
    return rlpEncodeBytes(buf);
  }
  if (item instanceof Uint8Array) {
    return rlpEncodeBytes(item);
  }
  if (Array.isArray(item)) {
    const encodedItems = item.map(rlpEncodeItem);
    const totalLen = encodedItems.reduce((sum, b) => sum + b.length, 0);
    const prefix = rlpLengthPrefix(totalLen, 0xc0, 0xf7);
    const out = new Uint8Array(prefix.length + totalLen);
    out.set(prefix, 0);
    let offset = prefix.length;
    for (const b of encodedItems) {
      out.set(b, offset);
      offset += b.length;
    }
    return out;
  }
  throw new Error("unsupported type");
}

function rlpEncodeBytes(buf: Uint8Array): Uint8Array {
  if (buf.length === 1 && buf[0] < 0x80) {
    return buf;
  }
  const prefix = rlpLengthPrefix(buf.length, 0x80, 0xb7);
  const out = new Uint8Array(prefix.length + buf.length);
  out.set(prefix, 0);
  out.set(buf, prefix.length);
  return out;
}

function rlpLengthPrefix(len: number, shortOffset: number, longOffset: number): Uint8Array {
  if (len < 56) {
    return Uint8Array.of(shortOffset + len);
  }
  let hex = len.toString(16);
  if (hex.length % 2 !== 0) hex = "0" + hex;
  const lenBytes = Uint8Array.from(hex.match(/../g) || [], (b) => Number.parseInt(b, 16));
  return Uint8Array.from([longOffset + lenBytes.length, ...lenBytes]);
}

async function rpcCall(method: string, params: unknown[] = []): Promise<unknown> {
  const res = await fetch(FUJI_RPC, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  if (!res.ok) {
    throw new Error(`RPC_HTTP_ERROR: ${res.status}`);
  }
  const json = await res.json();
  if (json.error) {
    throw new Error(`RPC_ERROR: ${json.error.message || JSON.stringify(json.error)}`);
  }
  return json.result;
}

function parseApplicationRecord(raw: string): { membershipRoot: string; membershipVersion: bigint } {
  const values = raw.replace(/^0x/, "").match(/.{64}/g) ?? [];
  const start = BigInt(`0x${values[0] ?? "0"}`) === 32n ? 1 : 0;
  return {
    membershipRoot: `0x${values[start + 4] ?? "00".repeat(32)}`,
    membershipVersion: BigInt(`0x${values[start + 5] ?? "0"}`),
  };
}

export async function POST(req: NextRequest | Request) {
  if (req instanceof Request && "headers" in req) {
    if (!validateOrigin(req as NextRequest)) {
      return NextResponse.json(
        { code: "FORBIDDEN", error: "CSRF_ORIGIN_INVALID", message: "Origin validation failed" },
        { status: 403 },
      );
    }
  }

  try {
    const rawKey = process.env.HAZE_FUJI_POLICY_AUTHORITY_KEY;
    if (!rawKey || !/^(?:0x)?[0-9a-fA-F]{64}$/.test(rawKey.trim())) {
      return NextResponse.json(
        {
          code: "UNAVAILABLE",
          error: "MEMBERSHIP_RELAYER_UNAVAILABLE",
          message: "Fuji policy authority relayer key is not configured on this host",
        },
        { status: 503 },
      );
    }

    const body = await req.json().catch(() => ({}));
    const applicationId = String(body.applicationId || DEFAULT_APPLICATION_ID);
    const rawRoot = body.membershipRoot;
    const membershipLeaves = Array.isArray(body.membershipLeaves) ? body.membershipLeaves : undefined;

    if (
      !applicationId ||
      typeof applicationId !== "string" ||
      !/^0x[0-9a-fA-F]{64}$/.test(applicationId)
    ) {
      return NextResponse.json(
        {
          code: "ENCODING_INVALID",
          error: "ENCODING_INVALID",
          message: "applicationId must be a valid 32-byte hex string",
        },
        { status: 400 },
      );
    }

    let targetRoot: string;

    if (membershipLeaves && membershipLeaves.length > 0) {
      const tree = new SparseMerkleTree(APP_TREE);
      let nextMember = 0;
      const seen = new Set<string>();
      for (const leaf of membershipLeaves) {
        if (!leaf || typeof leaf !== "object") continue;
        const npk = String(leaf.npk || "");
        const enc = String(leaf.enc || "");
        if (!/^0x[0-9a-fA-F]{64}$/i.test(npk) || !/^0x[0-9a-fA-F]{64}$/i.test(enc)) {
          return NextResponse.json(
            {
              code: "ENCODING_INVALID",
              error: "ENCODING_INVALID",
              message: "Membership leaf components must be valid 32-byte hex strings",
            },
            { status: 400 },
          );
        }
        const key = `${npk.toLowerCase()}:${enc.toLowerCase()}`;
        if (!seen.has(key)) {
          seen.add(key);
          try {
            tree.insert(nextMember, applicationMember(applicationId, npk, enc));
            nextMember += 1;
          } catch {
            return NextResponse.json(
              {
                code: "ENCODING_INVALID",
                error: "ENCODING_INVALID",
                message: "Membership leaf components must be valid BN254 field elements",
              },
              { status: 400 },
            );
          }
        }
      }
      const canonicalRoot = tree.root();
      if (rawRoot && typeof rawRoot === "string") {
        if (rawRoot.toLowerCase() !== canonicalRoot.toLowerCase()) {
          return NextResponse.json(
            {
              code: "INVALID_MEMBERSHIP_ROOT",
              error: "INVALID_MEMBERSHIP_ROOT",
              message: "Provided membership root does not match canonical root derived from member facts",
            },
            { status: 400 },
          );
        }
      }
      targetRoot = canonicalRoot;
    } else {
      if (
        !rawRoot ||
        typeof rawRoot !== "string" ||
        !/^0x[0-9a-fA-F]{64}$/.test(rawRoot)
      ) {
        return NextResponse.json(
          {
            code: "ENCODING_INVALID",
            error: "ENCODING_INVALID",
            message: "membershipRoot must be a valid 32-byte hex string",
          },
          { status: 400 },
        );
      }
      targetRoot = rawRoot;
    }
    const privKeyHex = rawKey.trim().replace(/^0x/, "");
    const privKeyBytes = Uint8Array.from(privKeyHex.match(/../g) || [], (b) => Number.parseInt(b, 16));
    const pubKey = secp256k1.getPublicKey(privKeyBytes, false);
    const senderAddress = toHex(keccak256(pubKey.subarray(1)).subarray(12));

    // Read current state from ApplicationRegistry
    const appData = `${functionSelector("getApplication(bytes32)")}${applicationId.slice(2)}`;
    let currentRaw = (await rpcCall("eth_call", [{ to: APPLICATION_REGISTRY, data: appData }, "latest"])) as string;
    let current = parseApplicationRecord(currentRaw);
    const beforeVersion = current.membershipVersion;

    if (current.membershipRoot.toLowerCase() === targetRoot.toLowerCase()) {
      return NextResponse.json({
        ok: true,
        membershipVersion: Number(current.membershipVersion),
        membershipRoot: current.membershipRoot,
      });
    }

    // Build and sign transaction
    const nonceHex = (await rpcCall("eth_getTransactionCount", [senderAddress, "pending"])) as string;
    const nonce = Number.parseInt(nonceHex, 16);
    const gasPriceHex = (await rpcCall("eth_gasPrice", [])) as string;
    const gasPrice = BigInt(gasPriceHex || "0x5d21dba00"); // default ~25 nAVAX
    const maxPriorityFeePerGas = 1500000000n; // 1.5 nAVAX
    const maxFeePerGas = gasPrice > 25000000000n ? gasPrice * 2n : 35000000000n;
    const gasLimit = 120000n;
    const txData = encodeMembershipRootUpdate(applicationId, targetRoot);

    const txFields = [
      CHAIN_ID,
      nonce,
      maxPriorityFeePerGas,
      maxFeePerGas,
      gasLimit,
      APPLICATION_REGISTRY,
      0n,
      txData,
      [],
    ];

    const rlp = rlpEncodeItem(txFields);
    const payloadToSign = new Uint8Array(1 + rlp.length);
    payloadToSign[0] = 0x02;
    payloadToSign.set(rlp, 1);
    const digest = keccak256(payloadToSign);

    const sig = secp256k1.sign(digest, privKeyBytes, { prehash: false });
    const signedFields = [
      ...txFields,
      sig.recovery,
      sig.r,
      sig.s,
    ];
    const signedRlp = rlpEncodeItem(signedFields);
    const rawTx = new Uint8Array(1 + signedRlp.length);
    rawTx[0] = 0x02;
    rawTx.set(signedRlp, 1);
    const rawTxHex = toHex(rawTx);

    const txHash = (await rpcCall("eth_sendRawTransaction", [rawTxHex])) as string;

    // Poll for receipt
    for (let attempt = 0; attempt < 30; attempt += 1) {
      const receipt = (await rpcCall("eth_getTransactionReceipt", [txHash])) as { status?: string } | null;
      if (receipt) {
        if (receipt.status !== "0x1") {
          throw new Error("RELAYER_TRANSACTION_REVERTED");
        }
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }

    // Read updated record with replica sync polling
    for (let poll = 0; poll < 15; poll += 1) {
      currentRaw = (await rpcCall("eth_call", [{ to: APPLICATION_REGISTRY, data: appData }, "latest"])) as string;
      current = parseApplicationRecord(currentRaw);
      if (current.membershipVersion > beforeVersion && current.membershipRoot.toLowerCase() === targetRoot.toLowerCase()) {
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }

    const finalVersion = current.membershipVersion > beforeVersion ? current.membershipVersion : beforeVersion + 1n;

    return NextResponse.json({
      ok: true,
      membershipVersion: Number(finalVersion),
      membershipRoot: targetRoot,
      hash: txHash,
    });
  } catch (error) {
    return NextResponse.json(
      {
        code: "MEMBERSHIP_UPDATE_FAILED",
        error: error instanceof Error ? error.message : "MEMBERSHIP_UPDATE_FAILED",
      },
      { status: 500 },
    );
  }
}
