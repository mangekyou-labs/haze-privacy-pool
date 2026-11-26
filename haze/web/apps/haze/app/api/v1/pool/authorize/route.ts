import { type NextRequest, NextResponse } from "next/server.js";
import { FUJI_V2 } from "../../../../../../../../sdk/typescript/src/fuji-v2-defaults.ts";
import { secp256k1 } from "@noble/curves/secp256k1";
import { hexToBuf } from "../../../../../../../../sdk/typescript/src/abi.ts";
import {
  authorizationDigest,
  intentStructHash,
  type ApplicationAuthorizationFields,
  type HazeIntentFields,
} from "../../../../../../../../sdk/typescript/src/eip712.ts";
import {
  introspectSession,
  isFixtureMode,
  keccak256,
  requireRole,
  validateOrigin,
} from "../../_lib.ts";

const DEFAULT_SIGNER = "0xeD37FD0d6F0f69236E7472B36796e133D20EcC32";
const CHAIN_ID = 43113;

function getGatekeeperKey(): string | null {
  const key =
    process.env.HAZE_FUJI_GATEKEEPER_KEY ||
    process.env.HAZE_FUJI_POLICY_AUTHORITY_KEY ||
    process.env.PRIVATE_KEY;
  if (!key) return null;
  const clean = key.replace(/^0x/i, "");
  return clean.length === 64 ? clean : null;
}

export async function POST(req: NextRequest) {
  if (!validateOrigin(req)) {
    return NextResponse.json(
      { code: "FORBIDDEN", error: "CSRF_ORIGIN_INVALID", message: "Origin validation failed" },
      { status: 403 },
    );
  }


  try {
    const body = await req.json().catch(() => ({}));
    const intent = (body.intent || body) as Record<string, unknown>;
    const rawBody = body as Record<string, unknown>;

    if (!intent || typeof intent !== "object" || Object.keys(intent).length === 0) {
      return NextResponse.json(
        { code: "ENCODING_INVALID", error: "ENCODING_INVALID", message: "Intent object required" },
        { status: 400 },
      );
    }

    const keyHex = getGatekeeperKey();
    const isFixture = isFixtureMode();

    if (!keyHex && !isFixture) {
      return NextResponse.json(
        { code: "UNAVAILABLE", error: "UNAVAILABLE", message: "Gatekeeper backend unavailable on this host" },
        { status: 503 },
      );
    }

    let calculatedIntentHash: string;
    if (typeof rawBody.intentHash === "string" && rawBody.intentHash.length > 0) {
      calculatedIntentHash = rawBody.intentHash;
    } else if (typeof intent.intentHash === "string" && intent.intentHash.length > 0) {
      calculatedIntentHash = intent.intentHash;
    } else {
      const safeIntent: HazeIntentFields = {
        applicationId: String(intent.applicationId || rawBody.applicationId || `0x${"00".repeat(30)}0a11`),
        user: String(intent.user || rawBody.wallet || rawBody.user || DEFAULT_SIGNER),
        pool: String(intent.pool || rawBody.pool || (process.env.NEXT_PUBLIC_HAZE_POOL || FUJI_V2.pool)),
        poolVersion: String(intent.poolVersion || rawBody.poolVersion || `0x${"00".repeat(30)}b001`),
        action: Number(intent.action ?? rawBody.action ?? 1),
        noteTreeRoot: String(intent.noteTreeRoot || `0x${"00".repeat(32)}`),
        applicationPolicyVersion: Number(intent.applicationPolicyVersion ?? 1),
        hazePolicyVersion: Number(intent.hazePolicyVersion ?? 1),
        applicationMembershipRoot: String(intent.applicationMembershipRoot || `0x${"00".repeat(32)}`),
        hazeBlocklistRoot: String(intent.hazeBlocklistRoot || `0x${"00".repeat(32)}`),
        inputNullifier0: String(intent.inputNullifier0 || `0x${"00".repeat(32)}`),
        inputNullifier1: String(intent.inputNullifier1 || `0x${"00".repeat(32)}`),
        outputCommitment0: String(intent.outputCommitment0 || `0x${"00".repeat(32)}`),
        outputCommitment1: String(intent.outputCommitment1 || `0x${"00".repeat(32)}`),
        publicAmount: Number(intent.publicAmount ?? 0),
        publicRecipient: String(intent.publicRecipient || "0x0000000000000000000000000000000000000000"),
        recipientCiphertextHash0: String(intent.recipientCiphertextHash0 || `0x${"00".repeat(32)}`),
        recipientCiphertextHash1: String(intent.recipientCiphertextHash1 || `0x${"00".repeat(32)}`),
        auditDataCommitment: String(intent.auditDataCommitment || `0x${"00".repeat(32)}`),
        auditCiphertextHash: String(intent.auditCiphertextHash || `0x${"00".repeat(32)}`),
        tokenIn: String(intent.tokenIn || "0x0000000000000000000000000000000000000000"),
        amountIn: String(intent.amountIn || `0x${"00".repeat(32)}`),
        minUsdcOut: Number(intent.minUsdcOut ?? 0),
        routeHash: String(intent.routeHash || `0x${"00".repeat(32)}`),
        deadline: Number(intent.deadline ?? 0),
      };
      try {
        calculatedIntentHash = intentStructHash(safeIntent);
      } catch {
        calculatedIntentHash = `0x${"00".repeat(32)}`;
      }
    }

    const clientAuth = body.authorization as Partial<ApplicationAuthorizationFields> | undefined;
    const now = Math.floor(Date.now() / 1000);
    const validAfter = typeof clientAuth?.validAfter === "number" ? Math.min(clientAuth.validAfter, now - 60) : now - 300;
    const validUntil = typeof clientAuth?.validUntil === "number" ? clientAuth.validUntil : now + 3600;
    const nonce = String(
      clientAuth?.nonce ||
      rawBody.nonce ||
      rawBody.actionReference ||
      `0x${Buffer.from(keccak256(Buffer.from(JSON.stringify(intent) + Date.now()))).toString("hex")}`
    );

    const authorization: ApplicationAuthorizationFields = {
      applicationId: String(intent.applicationId || rawBody.applicationId || `0x${"00".repeat(30)}0a11`),
      user: String(intent.user || rawBody.wallet || rawBody.user || DEFAULT_SIGNER),
      pool: String(intent.pool || rawBody.pool || (process.env.NEXT_PUBLIC_HAZE_POOL || FUJI_V2.pool)),
      poolVersion: String(intent.poolVersion || rawBody.poolVersion || `0x${"00".repeat(30)}b001`),
      action: Number(intent.action ?? rawBody.action ?? 1),
      intentHash: calculatedIntentHash,
      applicationPolicyVersion: Number(intent.applicationPolicyVersion ?? rawBody.applicationPolicyVersion ?? 1),
      hazePolicyVersion: Number(intent.hazePolicyVersion ?? rawBody.hazePolicyVersion ?? 1),
      auditDataCommitment: String(intent.auditDataCommitment || rawBody.auditDataCommitment || `0x${"00".repeat(32)}`),
      auditCiphertextHash: String(intent.auditCiphertextHash || rawBody.auditCiphertextHash || `0x${"00".repeat(32)}`),
      nonce,
      validAfter,
      validUntil,
    };

    let signature: string;
    let signer: string;

    if (keyHex) {
      const digestHex = authorizationDigest(authorization, CHAIN_ID);
      const sig = secp256k1.sign(hexToBuf(digestHex), Buffer.from(keyHex, "hex"));
      const r = sig.r.toString(16).padStart(64, "0");
      const s = sig.s.toString(16).padStart(64, "0");
      const v = (sig.recovery + 27).toString(16).padStart(2, "0");
      signature = `0x${r}${s}${v}`;
      signer = DEFAULT_SIGNER;
    } else {
      signer = DEFAULT_SIGNER;
      signature = `0x${"11".repeat(65)}`;
    }

    return NextResponse.json({
      signature,
      intent,
      authorization: {
        ...authorization,
        signer,
        signature,
      },
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Gatekeeper authorization failed";
    return NextResponse.json(
      { code: "AUTHORIZATION_DENIED", error: "AUTHORIZATION_DENIED", message: msg },
      { status: 403 },
    );
  }
}
