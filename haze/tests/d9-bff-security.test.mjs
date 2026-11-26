import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { NextRequest } from "next/server.js";
import { PRODUCTION_URL } from "../dev/production-origin.mjs";

process.env.HAZE_FIXTURE_MODE = "true";
process.env.NODE_ENV = "test";

import { POST as challengeHandler } from "../web/apps/haze/app/api/v1/auth/challenge/route.ts";
import { POST as verifyHandler } from "../web/apps/haze/app/api/v1/auth/verify/route.ts";
import { GET as sessionHandler } from "../web/apps/haze/app/api/v1/auth/session/route.ts";
import { POST as logoutHandler } from "../web/apps/haze/app/api/v1/auth/logout/route.ts";
import { GET as healthHandler } from "../web/apps/haze/app/api/v1/health/route.ts";
import { POST as quoteHandler } from "../web/apps/haze/app/api/v1/pool/quote/route.ts";
import { POST as authorizeHandler } from "../web/apps/haze/app/api/v1/pool/authorize/route.ts";
import { GET as historyHandler } from "../web/apps/haze/app/api/v1/pool/history/route.ts";
import { GET as adminApplicationsHandler } from "../web/apps/haze/app/api/v1/admin/applications/route.ts";
import { GET as govProposalsHandler, POST as govCreateProposalHandler } from "../web/apps/haze/app/api/v1/governance/proposals/route.ts";
import {
  createChallengeBFF,
  DEFAULT_APPLICATION_ID,
  FUJI_SESSION_COOKIE,
  verifyChallengeBFF,
} from "../web/apps/haze/app/api/v1/_lib.ts";

const TEST_WALLET = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";
const OTHER_WALLET = "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc";

test("D9 deployment: Keycloak image imports the committed Haze realm", () => {
  const dockerfile = readFileSync(new URL("../dev/keycloak/Dockerfile", import.meta.url), "utf8");
  const realm = JSON.parse(
    readFileSync(new URL("../dev/keycloak/realm-export.json", import.meta.url), "utf8"),
  );

  assert.equal(realm.realm, "haze-fuji");
  assert.match(
    dockerfile,
    /COPY\s+haze\/dev\/keycloak\/realm-export\.json\s+\/opt\/keycloak\/data\/import\/realm-export\.json/,
  );
  assert.match(dockerfile, /--import-realm/);

  // SO-06: Restrict Keycloak realm to exact production origin
  const client = realm.clients[0];
  assert.deepEqual(client.redirectUris, [`${PRODUCTION_URL}/*`]);
  assert.deepEqual(client.webOrigins, [PRODUCTION_URL]);
  assert.equal(client.attributes?.["post.logout.redirect.uris"], `${PRODUCTION_URL}/*`);
});

function makeReq(url, method = "GET", body = null, headers = {}, cookie = null) {
  const allHeaders = new Headers(headers);
  if (!allHeaders.has("host")) allHeaders.set("host", "localhost:3000");
  if (!allHeaders.has("origin")) allHeaders.set("origin", "http://localhost:3000");
  if (cookie) {
    allHeaders.set("cookie", `${FUJI_SESSION_COOKIE}=${cookie}`);
  }
  if (body) {
    if (!allHeaders.has("content-type")) allHeaders.set("content-type", "application/json");
    return new NextRequest(url, {
      method,
      headers: allHeaders,
      body: typeof body === "string" ? body : JSON.stringify(body),
    });
  }
  return new NextRequest(url, {
    method,
    headers: allHeaders,
  });
}

test("D9 BFF: POST /api/v1/auth/challenge issues canonical challenge and rejects bad inputs", async () => {
  // Valid challenge request
  const validReq = makeReq("http://localhost:3000/api/v1/auth/challenge", "POST", {
    wallet: TEST_WALLET,
    applicationId: DEFAULT_APPLICATION_ID,
    role: "pool-user",
  });
  const res = await challengeHandler(validReq);
  assert.equal(res.status, 200);
  const data = await res.json();
  assert.ok(data.challengeId);
  assert.ok(data.nonce);
  assert.ok(data.message.includes(TEST_WALLET));
  assert.equal(data.chainId, 43113);

  // Invalid wallet format
  const badReq = makeReq("http://localhost:3000/api/v1/auth/challenge", "POST", {
    wallet: "not-a-wallet",
    role: "pool-user",
  });
  const badRes = await challengeHandler(badReq);
  assert.equal(badRes.status, 400);

  // CSRF Origin mismatch
  const csrfReq = makeReq(
    "http://localhost:3000/api/v1/auth/challenge",
    "POST",
    { wallet: TEST_WALLET, role: "pool-user" },
    { origin: "http://malicious-site.example.com", host: "localhost:3000" },
  );
  const csrfRes = await challengeHandler(csrfReq);
  assert.equal(csrfRes.status, 403);
});

test("D9 BFF: POST /api/v1/auth/verify sets HttpOnly SameSite=Strict cookie and strips token from JSON", async () => {
  const ch = await createChallengeBFF(TEST_WALLET, DEFAULT_APPLICATION_ID, "pool-user");

  const req = makeReq("http://localhost:3000/api/v1/auth/verify", "POST", {
    challengeId: ch.challengeId,
    message: ch.message,
    signature: `0x${"11".repeat(65)}`,
  });

  const res = await verifyHandler(req);
  assert.equal(res.status, 200);
  const data = await res.json();

  // Token is NOT exposed in JSON body
  assert.equal(data.token, undefined);
  assert.equal(data.authenticated, true);
  assert.equal(data.wallet.toLowerCase(), TEST_WALLET.toLowerCase());
  assert.equal(data.role, "pool-user");

  // Cookie is set with secure attributes
  const setCookie = res.headers.get("set-cookie") || "";
  assert.ok(setCookie.includes(`${FUJI_SESSION_COOKIE}=`));
  assert.ok(setCookie.toLowerCase().includes("httponly"));
  assert.ok(setCookie.toLowerCase().includes("samesite=strict"));
  assert.ok(setCookie.toLowerCase().includes("path=/"));
});

test("D9 BFF: GET /api/v1/auth/session introspects cookie and POST /api/v1/auth/logout revokes session", async () => {
  const ch = await createChallengeBFF(TEST_WALLET, DEFAULT_APPLICATION_ID, "pool-user");
  const { token } = await verifyChallengeBFF(ch.challengeId, ch.message, `0x${"11".repeat(65)}`);

  // Unauthenticated check
  const unauthReq = makeReq("http://localhost:3000/api/v1/auth/session");
  const unauthRes = await sessionHandler(unauthReq);
  assert.equal(unauthRes.status, 200);
  const unauthData = await unauthRes.json();
  assert.equal(unauthData.authenticated, false);

  // Authenticated check with cookie
  const authReq = makeReq("http://localhost:3000/api/v1/auth/session", "GET", null, {}, token);
  const authRes = await sessionHandler(authReq);
  assert.equal(authRes.status, 200);
  const authData = await authRes.json();
  assert.equal(authData.authenticated, true);
  assert.equal(authData.wallet.toLowerCase(), TEST_WALLET.toLowerCase());
  assert.equal(authData.role, "pool-user");
  assert.equal(authData.token, undefined); // Token never in JSON

  // Logout
  const logoutReq = makeReq("http://localhost:3000/api/v1/auth/logout", "POST", {}, {}, token);
  const logoutRes = await logoutHandler(logoutReq);
  assert.equal(logoutRes.status, 200);
  const logoutData = await logoutRes.json();
  assert.equal(logoutData.ok, true);

  // Cookie cleared
  const clearedCookie = logoutRes.headers.get("set-cookie") || "";
  assert.ok(clearedCookie.includes("Max-Age=0"));

  // Subsequent session check returns unauthenticated
  const postLogoutReq = makeReq("http://localhost:3000/api/v1/auth/session", "GET", null, {}, token);
  const postLogoutRes = await sessionHandler(postLogoutReq);
  const postLogoutData = await postLogoutRes.json();
  assert.equal(postLogoutData.authenticated, false);
});

test("D9 BFF: GET /api/v1/health returns sanitized service readiness", async () => {
  const res = await healthHandler();
  assert.equal(res.status, 200);
  const data = await res.json();
  assert.equal(data.status, "ready");
  assert.equal(data.chainId, 43113);
  assert.equal(data.circuitVersion, "spend-v1");
  assert.equal(data.schemaVersion, 6);
  assert.equal(data.database, undefined); // No database details exposed
  assert.equal(data.keycloak, undefined);
});

test("D9 BFF Route Policy: Public /pool/quote accessible without session", async () => {
  process.env.HAZE_FUJI_PILOT_TOKEN = "0x15cF58144EF33af1e14b5208015d11F9143E27b9";
  process.env.HAZE_FUJI_PILOT_VENUE = "0x25cF58144EF33af1e14b5208015d11F9143E27b9";
  const req = makeReq("http://localhost:3000/api/v1/pool/quote", "POST", {
    tokenIn: "0x15cF58144EF33af1e14b5208015d11F9143E27b9",
    amountIn: "1000000",
  });
  const res = await quoteHandler(req);
  assert.equal(res.status, 200);
  const data = await res.json();
  assert.equal(data.amountOut, "1000000");
  assert.equal(data.rate, "1:1");
});

test("D9 BFF Route Policy: pool-user history route enforces pool-user role and reject unauthenticated callers", async () => {
  // 1. Unauthenticated -> 401
  const unauthReq = makeReq(`http://localhost:3000/api/v1/pool/history?wallet=${TEST_WALLET}`, "GET");
  const unauthRes = await historyHandler(unauthReq);
  assert.equal(unauthRes.status, 401);

  // 2. Authenticated pool-user -> 200
  const ch = await createChallengeBFF(TEST_WALLET, DEFAULT_APPLICATION_ID, "pool-user");
  const { token } = await verifyChallengeBFF(ch.challengeId, ch.message, `0x${"11".repeat(65)}`);

  const authReq = makeReq(`http://localhost:3000/api/v1/pool/history?wallet=${TEST_WALLET}`, "GET", null, {}, token);
  const authRes = await historyHandler(authReq);
  assert.equal(authRes.status, 200);
});

test("D9 BFF Route Policy: pool authorize route enforces origin validation and signs intent", async () => {
  // 1. Invalid origin -> 403
  const badOriginReq = new Request("http://localhost:3000/api/v1/pool/authorize", {
    method: "POST",
    headers: { "Content-Type": "application/json", origin: "http://malicious.site" },
    body: JSON.stringify({
      wallet: TEST_WALLET,
      applicationId: DEFAULT_APPLICATION_ID,
      action: 1,
      intentHash: `0x${"00".repeat(32)}`,
    }),
  });
  const badOriginRes = await authorizeHandler(badOriginReq);
  assert.equal(badOriginRes.status, 403);

  // 2. Valid origin -> 200
  const validReq = makeReq("http://localhost:3000/api/v1/pool/authorize", "POST", {
    wallet: TEST_WALLET,
    applicationId: DEFAULT_APPLICATION_ID,
    action: 1,
    intentHash: `0x${"00".repeat(32)}`,
  });
  const validRes = await authorizeHandler(validReq);
  assert.equal(validRes.status, 200);
  const validData = await validRes.json();
  assert.ok(validData.signature);
});

test("D9 BFF Route Policy: admin routes require application-admin role and strictly reject super-auditor", async () => {
  // 1. Unauthenticated -> 401
  const unauthReq = makeReq("http://localhost:3000/api/v1/admin/applications");
  const unauthRes = await adminApplicationsHandler(unauthReq);
  assert.equal(unauthRes.status, 401);

  // 2. pool-user -> 403
  const userCh = await createChallengeBFF(TEST_WALLET, DEFAULT_APPLICATION_ID, "pool-user");
  const { token: userToken } = await verifyChallengeBFF(userCh.challengeId, userCh.message, `0x${"11".repeat(65)}`);
  const userReq = makeReq("http://localhost:3000/api/v1/admin/applications", "GET", null, {}, userToken);
  const userRes = await adminApplicationsHandler(userReq);
  assert.equal(userRes.status, 403);

  // 3. super-auditor -> 403 Forbidden (Strict isolation: super-auditor does NOT inherit admin)
  const superCh = await createChallengeBFF(TEST_WALLET, DEFAULT_APPLICATION_ID, "super-auditor");
  const { token: superToken } = await verifyChallengeBFF(superCh.challengeId, superCh.message, `0x${"11".repeat(65)}`);
  const superReq = makeReq("http://localhost:3000/api/v1/admin/applications", "GET", null, {}, superToken);
  const superRes = await adminApplicationsHandler(superReq);
  assert.equal(superRes.status, 403);

  // 4. application-admin -> 200
  const adminCh = await createChallengeBFF(TEST_WALLET, DEFAULT_APPLICATION_ID, "application-admin");
  const { token: adminToken } = await verifyChallengeBFF(adminCh.challengeId, adminCh.message, `0x${"11".repeat(65)}`);
  const adminReq = makeReq("http://localhost:3000/api/v1/admin/applications", "GET", null, {}, adminToken);
  const adminRes = await adminApplicationsHandler(adminReq);
  assert.equal(adminRes.status, 200);
});

test("D9 BFF Route Policy: governance routes require governance-operator role", async () => {
  // 1. Unauthenticated -> 401
  const unauthReq = makeReq("http://localhost:3000/api/v1/governance/proposals");
  const unauthRes = await govProposalsHandler(unauthReq);
  assert.equal(unauthRes.status, 401);

  // 2. application-admin -> 403
  const adminCh = await createChallengeBFF(TEST_WALLET, DEFAULT_APPLICATION_ID, "application-admin");
  const { token: adminToken } = await verifyChallengeBFF(adminCh.challengeId, adminCh.message, `0x${"11".repeat(65)}`);
  const adminReq = makeReq("http://localhost:3000/api/v1/governance/proposals", "GET", null, {}, adminToken);
  const adminRes = await govProposalsHandler(adminReq);
  assert.equal(adminRes.status, 403);

  // 3. governance-operator -> 200
  const govCh = await createChallengeBFF(TEST_WALLET, DEFAULT_APPLICATION_ID, "governance-operator");
  const { token: govToken } = await verifyChallengeBFF(govCh.challengeId, govCh.message, `0x${"11".repeat(65)}`);
  const govReq = makeReq("http://localhost:3000/api/v1/governance/proposals", "GET", null, {}, govToken);
  const govRes = await govProposalsHandler(govReq);
  assert.equal(govRes.status, 200);
});

test("D9 BFF: Wallet ownership check prevents cross-wallet data inspection in pool routes", async () => {
  const userCh = await createChallengeBFF(TEST_WALLET, DEFAULT_APPLICATION_ID, "pool-user");
  const { token: userToken } = await verifyChallengeBFF(userCh.challengeId, userCh.message, `0x${"11".repeat(65)}`);

  // Querying own wallet -> 200
  const ownReq = makeReq(`http://localhost:3000/api/v1/pool/history?wallet=${TEST_WALLET}`, "GET", null, {}, userToken);
  const ownRes = await historyHandler(ownReq);
  assert.equal(ownRes.status, 200);

  // Querying different wallet -> 403 Forbidden
  const otherReq = makeReq(`http://localhost:3000/api/v1/pool/history?wallet=${OTHER_WALLET}`, "GET", null, {}, userToken);
  const otherRes = await historyHandler(otherReq);
  assert.equal(otherRes.status, 403);
});

test("D9 BFF: Rejects legacy cookies and query tokens", async () => {
  const userCh = await createChallengeBFF(TEST_WALLET, DEFAULT_APPLICATION_ID, "pool-user");
  const { token } = await verifyChallengeBFF(userCh.challengeId, userCh.message, `0x${"11".repeat(65)}`);

  // Legacy cookie haze_session is ignored -> 401
  const legacyReq = makeReq("http://localhost:3000/api/v1/admin/applications", "GET", null, {
    cookie: `haze_session=${token}`,
  });
  const legacyRes = await adminApplicationsHandler(legacyReq);
  assert.equal(legacyRes.status, 401);

  // Query parameter ?token=... is ignored -> 401
  const queryReq = makeReq(`http://localhost:3000/api/v1/admin/applications?token=${token}`, "GET");
  const queryRes = await adminApplicationsHandler(queryReq);
  assert.equal(queryRes.status, 401);
});

test("D9 BFF: auth dependency failures map to 503 instead of 401", async () => {
  const previousOrigin = process.env.HAZE_AUTH_ORIGIN;
  const previousFetch = globalThis.fetch;
  process.env.HAZE_AUTH_ORIGIN = "http://auth-unavailable.test";
  globalThis.fetch = async () => new Response(null, { status: 503 });

  try {
    const protectedReq = makeReq(
      "http://localhost:3000/api/v1/admin/applications",
      "GET",
      null,
      {},
      "opaque-session-token",
    );
    const protectedRes = await adminApplicationsHandler(protectedReq);
    assert.equal(protectedRes.status, 503);

    const sessionReq = makeReq(
      "http://localhost:3000/api/v1/auth/session",
      "GET",
      null,
      {},
      "opaque-session-token",
    );
    const sessionRes = await sessionHandler(sessionReq);
    assert.equal(sessionRes.status, 503);
  } finally {
    globalThis.fetch = previousFetch;
    if (previousOrigin === undefined) delete process.env.HAZE_AUTH_ORIGIN;
    else process.env.HAZE_AUTH_ORIGIN = previousOrigin;
  }
});

test("D9 BFF: logout does not claim revocation when the auth dependency is unavailable", async () => {
  const previousOrigin = process.env.HAZE_AUTH_ORIGIN;
  const previousFetch = globalThis.fetch;
  process.env.HAZE_AUTH_ORIGIN = "http://auth-unavailable.test";
  globalThis.fetch = async () => new Response(null, { status: 503 });

  try {
    const req = makeReq(
      "http://localhost:3000/api/v1/auth/logout",
      "POST",
      null,
      {},
      "opaque-session-token",
    );
    const res = await logoutHandler(req);
    assert.equal(res.status, 503);
    assert.deepEqual(await res.json(), {
      code: "UNAVAILABLE",
      error: "UNAVAILABLE",
      message: "Authentication service unavailable",
    });
  } finally {
    globalThis.fetch = previousFetch;
    if (previousOrigin === undefined) delete process.env.HAZE_AUTH_ORIGIN;
    else process.env.HAZE_AUTH_ORIGIN = previousOrigin;
  }
});
