import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  AUTH_TYPE,
  EIP712_DOMAIN_TYPE,
  INTENT_TYPE,
  KEY_TYPE,
  POOL_DOMAIN_NAME,
  POOL_DOMAIN_VERSION,
  authorizationDigest,
  authorizationStructHash,
  eip712TypeHashes,
  intentDigest,
  intentStructHash,
  poolDomainSeparator,
} from "../sdk/typescript/src/eip712.ts";
import {
  SdkError,
  GATEKEEPER_ERROR_CODES,
  PROTOCOL_ERROR_CODES,
  CONTRACT_ERROR_CODES,
  parseContractError,
  parseGatekeeperError,
} from "../sdk/typescript/src/errors.ts";
import {
  FUJI_COMPATIBILITY,
  checkCompatibility,
} from "../sdk/typescript/src/versions.ts";
import { hashManifest, parseManifest } from "../sdk/typescript/src/manifest.ts";
import {
  assertBoundChain,
  createMemoryTransport,
} from "../sdk/typescript/src/transport.ts";
import {
  EMERGENCY_SELECTORS,
  POOL_SELECTORS,
  ROUTER_SELECTORS,
  bindHazePool,
  functionSelector,
} from "../sdk/typescript/src/bindings.ts";
import {
  createStaticQuoteAdapter,
  createUnavailableQuoteAdapter,
} from "../sdk/typescript/src/quote.ts";
import { createGatekeeperClient } from "../sdk/typescript/src/gatekeeper.ts";
import { routeHash } from "../sdk/typescript/src/router.ts";
import { HAZE_CHAIN_FAMILY, HAZE_PRODUCT_ID } from "../sdk/typescript/src/index.ts";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PROTOCOL = join(HAZE_ROOT, "circuits/vectors/v1/haze-protocol-v1.json");
const VERIFIER = join(HAZE_ROOT, "circuits/vectors/v1/haze-verifier-v1.json");

function loadProtocol() {
  return JSON.parse(readFileSync(PROTOCOL, "utf8"));
}

function named(vectors, name) {
  return vectors.positive.find((vector) => vector.name === name);
}

test("TypeScript EIP-712 types consume the committed protocol vectors", () => {
  const file = loadProtocol();
  const types = named(file, "eip712_type_hashes");
  const hashes = eip712TypeHashes();
  assert.equal(POOL_DOMAIN_NAME, "Haze Avalanche Compliant Pool");
  assert.equal(POOL_DOMAIN_VERSION, "1");
  assert.equal(hashes.domain, types.domain);
  assert.equal(hashes.intent, types.intent);
  assert.equal(hashes.authorization, types.authorization);
  assert.equal(hashes.keyDerivation, types.key_derivation);
  assert.match(EIP712_DOMAIN_TYPE, /^EIP712Domain\(/);
  assert.match(INTENT_TYPE, /^HazeIntent\(/);
  assert.match(AUTH_TYPE, /^ApplicationAuthorization\(/);
  assert.match(KEY_TYPE, /^HazeKeyDerivation\(/);

  const domain = named(file, "eip712_domain_separator_fuji");
  assert.equal(
    poolDomainSeparator({
      chainId: domain.chain_id,
      verifyingContract: domain.verifying_contract,
    }),
    domain.hash,
  );

  const intent = named(file, "haze_intent_deposit");
  assert.equal(intentStructHash(intent.fields), intent.struct_hash);
  assert.equal(intentDigest(intent.fields, domain.chain_id), intent.digest);

  const auth = named(file, "application_authorization");
  assert.equal(authorizationStructHash(auth.fields), auth.struct_hash);
  assert.equal(authorizationDigest(auth.fields, domain.chain_id), auth.digest);
});

test("EIP-712 validation rejects incompatible encodings and domains", () => {
  const intent = named(loadProtocol(), "haze_intent_deposit").fields;
  assert.throws(() => intentStructHash({ ...intent, deadline: 2 ** 48 }), (error) => {
    assert.equal(error instanceof SdkError, true);
    assert.equal(error.code, "FIELD_OUT_OF_RANGE");
    return true;
  });
  assert.throws(() => intentStructHash({ ...intent, tokenIn: "0x1111111111111111111111111111111111111111" }), (error) => {
    assert.equal(error.code, "ENCODING_INVALID");
    return true;
  });
  assert.throws(
    () =>
      intentStructHash({
        ...intent,
        noteTreeRoot: "0x0000000000000000000000000000000000000000000000000000000000000001",
      }),
    (error) => {
      assert.equal(error.code, "ENCODING_INVALID");
      return true;
    },
  );
  assert.throws(
    () =>
      poolDomainSeparator({
        chainId: 43113,
        verifyingContract: "0x1111111111111111111111111111111111111111",
        name: "Haze Shielded Account",
      }),
    (error) => {
      assert.equal(error.code, "DOMAIN_MISMATCH");
      return true;
    },
  );
});

test("version checks reject incompatible chain, contract, manifest, circuit, and API versions", () => {
  const verifier = JSON.parse(readFileSync(VERIFIER, "utf8"));
  const file = loadProtocol();
  assert.equal(FUJI_COMPATIBILITY.productId, HAZE_PRODUCT_ID);
  assert.equal(FUJI_COMPATIBILITY.chainFamily, HAZE_CHAIN_FAMILY);
  assert.equal(FUJI_COMPATIBILITY.chainId, file.primitives.fuji_chain_id);
  assert.equal(FUJI_COMPATIBILITY.schemaVersion, file.schema_version);
  assert.equal(FUJI_COMPATIBILITY.circuitArtifactHash, verifier.artifactHash);
  assert.equal(FUJI_COMPATIBILITY.protocolVersionTag, verifier.protocolVersionTag);

  const ok = {
    productId: HAZE_PRODUCT_ID,
    chainFamily: HAZE_CHAIN_FAMILY,
    chainId: 43113,
    schemaVersion: 1,
    apiVersion: 1,
    contractDomainVersion: "1",
    protocolVersionTag: verifier.protocolVersionTag,
    circuitArtifactHash: verifier.artifactHash,
    manifestVersion: 1,
  };
  assert.deepEqual(checkCompatibility(ok), { ok: true });

  const mismatch = (patch, code) => {
    assert.throws(() => checkCompatibility({ ...ok, ...patch }), (error) => {
      assert.equal(error instanceof SdkError, true);
      assert.equal(error.code, code);
      return true;
    });
  };
  mismatch({ chainId: file.primitives.c_chain_id }, "CHAIN_MISMATCH");
  mismatch({ schemaVersion: 2 }, "VERSION_UNSUPPORTED");
  mismatch({ apiVersion: 2 }, "VERSION_UNSUPPORTED");
  mismatch({ contractDomainVersion: "2" }, "VERSION_UNSUPPORTED");
  mismatch({ productId: "stellar-private-payments" }, "VERSION_UNSUPPORTED");
  mismatch({ circuitArtifactHash: `0x${"11".repeat(32)}` }, "VERSION_UNSUPPORTED");
  mismatch({ protocolVersionTag: `0x${"22".repeat(32)}` }, "VERSION_UNSUPPORTED");
  mismatch({ manifestVersion: 9 }, "VERSION_UNSUPPORTED");
});

test("SDK error taxonomy maps contract and gatekeeper failures", () => {
  for (const code of [
    "ENCODING_INVALID",
    "FIELD_OUT_OF_RANGE",
    "VERSION_UNSUPPORTED",
    "DOMAIN_MISMATCH",
    "CHAIN_MISMATCH",
    "APPLICATION_MISMATCH",
    "POOL_VERSION_MISMATCH",
    "CIPHERTEXT_INVALID",
  ]) {
    assert.equal(PROTOCOL_ERROR_CODES.includes(code), true);
  }
  for (const code of [
    "AUTH_WINDOW",
    "PAUSED",
    "UNAUTHORIZED",
    "REENTRANCY",
    "TIMELOCK",
    "POLICY_INVALID",
    "NULLIFIER_USED",
    "ROOT_UNKNOWN",
    "STATUS_INVALID",
    "KEYS_MISSING",
  ]) {
    assert.equal(CONTRACT_ERROR_CODES.includes(code), true);
  }
  for (const code of [
    "USER_INELIGIBLE",
    "POLICY_STALE",
    "TOKEN_NOT_ALLOWED",
    "LIMIT_EXCEEDED",
    "AUTHORIZATION_EXPIRED",
  ]) {
    assert.equal(GATEKEEPER_ERROR_CODES.includes(code), true);
  }
  assert.equal(parseContractError("execution reverted: AUTH_WINDOW"), "AUTH_WINDOW");
  assert.equal(parseContractError("PAUSED"), "PAUSED");
  assert.equal(parseGatekeeperError({ code: "USER_INELIGIBLE" }), "USER_INELIGIBLE");
  assert.throws(() => parseGatekeeperError({ code: "mystery" }), (error) => {
    assert.equal(error.code, "ENCODING_INVALID");
    return true;
  });
});

test("application manifest hashing rejects version drift and secret fields", () => {
  const manifest = {
    schemaVersion: 1,
    productId: HAZE_PRODUCT_ID,
    applicationId: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    organizationName: "Example App",
    gatekeeperEndpoint: "/v1",
    portalEndpoint: "/portal",
    auditorPolicy: { fields: ["amount", "counterparty"] },
    kmsKeyRefs: ["app-audit"],
    auditKeys: [{ version: 1, publicKey: `0x${"33".repeat(32)}` }],
    sourceTokens: [{ token: "0x5425890298aed601595a70ab815c96711a31bc65", decimals: 6 }],
    manifestVersion: 1,
  };
  const digest = hashManifest(manifest);
  assert.match(digest, /^0x[0-9a-f]{64}$/);
  assert.equal(hashManifest(manifest), digest);
  const parsed = parseManifest(manifest, digest);
  assert.equal(parsed.manifestVersion, 1);
  assert.throws(() => parseManifest({ ...manifest, manifestVersion: 2 }, digest), (error) => {
    assert.equal(error.code, "VERSION_UNSUPPORTED");
    return true;
  });
  assert.throws(() => parseManifest({ ...manifest, privateKey: "0x01" }, digest), (error) => {
    assert.equal(error.code, "ENCODING_INVALID");
    return true;
  });
  assert.throws(() => parseManifest(manifest, `0x${"00".repeat(32)}`), (error) => {
    assert.equal(error.code, "ENCODING_INVALID");
    return true;
  });
});

test("quote adapter returns a provider-neutral quote and fails closed", async () => {
  const adapter = "0x3333333333333333333333333333333333333333";
  const data = "0xaabb";
  const quotes = createStaticQuoteAdapter({
    usdcOut: "1000000",
    adapter,
    data,
    gasEstimate: 180000,
  });
  const request = {
    tokenIn: "0x5425890298aed601595a70ab815c96711a31bc65",
    amountIn: "0x00000000000000000000000000000000000000000000000000000000000f4240",
    minUsdcOut: "900000",
    deadline: 2_000_000_000,
  };
  const quote = await quotes.quote(request);
  assert.equal(quote.tokenIn, request.tokenIn);
  assert.equal(quote.usdcOut, "1000000");
  assert.equal(quote.minUsdcOut, request.minUsdcOut);
  assert.equal(quote.adapter, adapter);
  assert.equal(quote.routeHash, routeHash(adapter, data));
  assert.match(quote.calldataHash, /^0x[0-9a-f]{64}$/);
  assert.equal(quote.expiry, request.deadline);
  assert.equal("vendorRoute" in quote, false);
  await assert.rejects(() => quotes.quote({ ...request, minUsdcOut: "2000000" }), (error) => {
    assert.equal(error.code, "QUOTE_STALE");
    return true;
  });
  await assert.rejects(() => createUnavailableQuoteAdapter().quote(request), (error) => {
    assert.equal(error.code, "UNAVAILABLE");
    return true;
  });
});

test("gatekeeper client uses versioned routes and typed denials", async () => {
  const calls = [];
  const authorization = named(loadProtocol(), "application_authorization").fields;
  const client = createGatekeeperClient({
    endpoint: "/v1",
    apiVersion: 1,
    fetch: async (url, init) => {
      calls.push({ url, init });
      if (url === "/v1/authorizations") {
        return {
          ok: false,
          status: 403,
          headers: { get: (name) => (name.toLowerCase() === "haze-api-version" ? "1" : null) },
          json: async () => ({ code: "USER_INELIGIBLE" }),
          text: async () => "USER_INELIGIBLE",
        };
      }
      return {
        ok: true,
        status: 200,
        headers: { get: (name) => (name.toLowerCase() === "haze-api-version" ? "1" : null) },
        json: async () => ({
          schemaVersion: 1,
          productId: HAZE_PRODUCT_ID,
          applicationId: authorization.applicationId,
          organizationName: "Example App",
          gatekeeperEndpoint: "/v1",
          portalEndpoint: "/portal",
          auditorPolicy: { fields: ["amount"] },
          kmsKeyRefs: ["app-audit"],
          auditKeys: [{ version: 1, publicKey: `0x${"33".repeat(32)}` }],
          sourceTokens: [],
          manifestVersion: 1,
        }),
        text: async () => "",
      };
    },
  });
  await assert.rejects(
    () =>
      client.requestAuthorization({
        applicationId: authorization.applicationId,
        session: "app-session",
        intent: named(loadProtocol(), "haze_intent_deposit").fields,
      }),
    (error) => {
      assert.equal(error.code, "USER_INELIGIBLE");
      return true;
    },
  );
  assert.equal(calls[0].url, "/v1/authorizations");
  assert.equal(calls[0].init.method, "POST");
  assert.equal(calls[0].init.headers["haze-api-version"], "1");

  const manifest = await client.fetchManifest(authorization.applicationId);
  assert.equal(calls[1].url, `/v1/applications/${authorization.applicationId}/manifest`);
  assert.equal(manifest.productId, HAZE_PRODUCT_ID);

  const wrongVersion = createGatekeeperClient({
    endpoint: "/v1",
    apiVersion: 1,
    fetch: async () => ({
      ok: true,
      status: 200,
      headers: { get: () => "2" },
      json: async () => ({}),
      text: async () => "",
    }),
  });
  await assert.rejects(() => wrongVersion.fetchManifest(authorization.applicationId), (error) => {
    assert.equal(error.code, "VERSION_UNSUPPORTED");
    return true;
  });
});

test("provider-neutral transport and contract bindings read views by selector", async () => {
  const pool = "0x1111111111111111111111111111111111111111";
  const version = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  const artifact = JSON.parse(readFileSync(VERIFIER, "utf8")).artifactHash;
  assert.equal(
    functionSelector(
      "deposit(((bytes32,address,address,bytes32,uint8,uint256,uint64,uint64,uint256,uint256,uint256,uint256,uint256,uint256,uint64,address,bytes32,bytes32,uint256,bytes32,address,uint256,uint64,bytes32,uint48),(bytes32,address,address,bytes32,uint8,bytes32,uint64,uint64,uint256,bytes32,bytes32,uint48,uint48),bytes,bytes,bytes,bytes,bytes))",
    ),
    POOL_SELECTORS.deposit,
  );
  assert.equal(
    functionSelector("requestEmergencyExit(bytes32)"),
    EMERGENCY_SELECTORS.requestEmergencyExit,
  );
  assert.equal(
    functionSelector(
      "swapAndShield(((bytes32,address,address,bytes32,uint8,uint256,uint64,uint64,uint256,uint256,uint256,uint256,uint256,uint256,uint64,address,bytes32,bytes32,uint256,bytes32,address,uint256,uint64,bytes32,uint48),(bytes32,address,address,bytes32,uint8,bytes32,uint64,uint64,uint256,bytes32,bytes32,uint48,uint48),bytes,bytes,bytes,bytes,bytes),(address,bytes,bytes32))",
    ),
    ROUTER_SELECTORS.swapAndShield,
  );

  const transport = createMemoryTransport({
    chainId: 43113,
    views: {
      [pool.toLowerCase()]: {
        [POOL_SELECTORS.poolVersion]: version,
        [POOL_SELECTORS.spendArtifactHash]: artifact,
      },
    },
  });
  assert.equal(await transport.chainId(), 43113);
  await assertBoundChain(transport, 43113);
  await assert.rejects(() => assertBoundChain(transport, 43114), (error) => {
    assert.equal(error.code, "CHAIN_MISMATCH");
    return true;
  });

  const binding = bindHazePool(transport, pool);
  assert.equal(await binding.poolVersion(), version);
  assert.equal(await binding.spendArtifactHash(), artifact);
  assert.match(binding.encodeView("poolVersion()"), /^0x[0-9a-f]{8}$/);
});
