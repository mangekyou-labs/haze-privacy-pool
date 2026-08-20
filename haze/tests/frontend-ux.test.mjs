import assert from "node:assert/strict";
import test from "node:test";
import {
  HAZE_APP_KIND as DEX_KIND,
  authorizeApi as authorizeDexApi,
  authorizeRoute as authorizeDexRoute,
  copyFor as dexCopyFor,
  designSystem as dexDesign,
  layoutFor as dexLayout,
  lintPrivacyCopy as lintDexCopy,
  navFor as dexNav,
  primitive as dexPrimitive,
  threatModel as dexThreat,
} from "../apps/privacy-pool-dex/src/index.ts";
import {
  HAZE_APP_KIND as PORTAL_KIND,
  authorizeApi as authorizePortalApi,
  authorizeRoute as authorizePortalRoute,
  copyFor as portalCopyFor,
  designSystem as portalDesign,
  layoutFor as portalLayout,
  lintPrivacyCopy as lintPortalCopy,
  navFor as portalNav,
  primitive as portalPrimitive,
  threatModel as portalThreat,
} from "../apps/compliance-portal/src/index.ts";

const APP_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const APP_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

const poolUser = { role: "pool-user", applicationId: APP_A };
const adminA = { role: "application-admin", applicationId: APP_A };
const auditorA = { role: "application-auditor", applicationId: APP_A };
const superAuditor = { role: "super-auditor", applicationId: APP_A };
const anonymous = { role: null };

test("Privacy Pool DEX and Compliance Portal remain independently deployable products", () => {
  assert.equal(DEX_KIND, "privacy-pool-dex");
  assert.equal(PORTAL_KIND, "compliance-portal");
  assert.notEqual(DEX_KIND, PORTAL_KIND);
  assert.equal(dexDesign.productName, "Haze");
  assert.equal(portalDesign.productName, "Haze");
  assert.equal(dexDesign.language, "alpine-volcanic");
  assert.notEqual(dexDesign.language, "stellar");
});

test("ordinary pool users cannot load portal routes or portal APIs", () => {
  for (const path of ["/admin", "/audit", "/governance"]) {
    const decision = authorizeDexRoute(poolUser, path);
    assert.equal(decision.ok, false);
    assert.equal(decision.code, "FORBIDDEN");
  }
  assert.equal(authorizePortalRoute(poolUser, "/admin").ok, false);
  assert.equal(authorizePortalRoute(poolUser, "/audit").ok, false);
  assert.equal(authorizePortalRoute(poolUser, "/governance").ok, false);
  assert.equal(authorizePortalApi(poolUser, "GET", "/v1/disclosures/query").ok, false);
  assert.equal(authorizePortalApi(poolUser, "GET", "/v1/cases").ok, false);
  assert.equal(authorizeDexApi(poolUser, "POST", "/v1/authorizations").ok, true);
});

test("hiding a navigation item is never treated as authorization", () => {
  const labels = portalNav(poolUser).map((item) => item.path);
  assert.equal(labels.includes("/admin"), false);
  const hidden = authorizePortalRoute(poolUser, "/admin");
  assert.equal(hidden.ok, false);
  assert.equal(hidden.code, "FORBIDDEN");
  assert.notEqual(hidden.code, "NOT_FOUND");
});

test("an application auditor cannot load governance or other-application data", () => {
  assert.equal(authorizePortalRoute(auditorA, "/governance").ok, false);
  assert.equal(authorizePortalApi(auditorA, "POST", "/v1/governance/schedule").ok, false);
  assert.equal(
    authorizePortalRoute(auditorA, "/audit", { applicationId: APP_B }).ok,
    false,
  );
  assert.equal(
    authorizePortalApi(auditorA, "GET", "/v1/disclosures/query", { applicationId: APP_B }).code,
    "APPLICATION_MISMATCH",
  );
  assert.equal(authorizePortalRoute(auditorA, "/audit", { applicationId: APP_A }).ok, true);
});

test("an application administrator cannot reach other-application or custody controls", () => {
  assert.equal(authorizePortalRoute(adminA, "/admin", { applicationId: APP_A }).ok, true);
  assert.equal(authorizePortalRoute(adminA, "/admin", { applicationId: APP_B }).ok, false);
  assert.equal(authorizePortalRoute(adminA, "/governance").ok, false);
  assert.equal(authorizePortalApi(adminA, "POST", "/v1/pool/deposit").ok, false);
});

test("a super-auditor has no note-custody authority", () => {
  assert.equal(authorizePortalRoute(superAuditor, "/governance").ok, true);
  assert.equal(authorizePortalApi(superAuditor, "POST", "/v1/pool/deposit").ok, false);
  assert.equal(authorizePortalApi(superAuditor, "POST", "/v1/pool/transact").ok, false);
  assert.equal(authorizeDexApi(superAuditor, "POST", "/v1/authorizations").ok, false);
});

test("anonymous sessions are denied on authenticated surfaces", () => {
  assert.equal(authorizeDexRoute(anonymous, "/shield").ok, false);
  assert.equal(authorizePortalRoute(anonymous, "/admin").ok, false);
  assert.equal(authorizeDexRoute(poolUser, "/shield").ok, true);
});

test("privacy copy never labels public facts as private", () => {
  const publicFacts = [
    "source-token-swap",
    "deposit-amount",
    "withdrawal-amount",
    "application-affiliation",
    "gas",
    "wallet-address",
    "version-migration",
  ];
  for (const fact of publicFacts) {
    const dex = dexCopyFor(fact);
    const portal = portalCopyFor(fact);
    assert.equal(dex.visibility, "public");
    assert.equal(portal.visibility, "public");
    assert.doesNotMatch(dex.label, /private/i);
    assert.doesNotMatch(portal.warning, /private/i);
  }
  assert.equal(dexCopyFor("shielded-note-amount").visibility, "private");
  assert.deepEqual(
    lintDexCopy("This private swap keeps your deposit amount private across applications."),
    [
      "source-token-swap",
      "deposit-amount",
      "cross-application-anonymity",
    ],
  );
  assert.deepEqual(lintPortalCopy("Private application affiliation"), ["application-affiliation"]);
});

test("design tokens are a Haze language and meet WCAG 2.1 AA contrast", () => {
  for (const system of [dexDesign, portalDesign]) {
    assert.equal(system.productName, "Haze");
    assert.match(system.fontSans, /IBM Plex Sans/);
    assert.match(system.fontMono, /IBM Plex Mono/);
    assert.ok(system.contrast.body >= 4.5);
    assert.ok(system.contrast.large >= 3);
    assert.ok(system.contrast.primary >= 4.5);
    assert.equal(system.tokens.primary.toLowerCase() === "#fdbe2c", false);
    assert.equal(system.tokens.primary.toLowerCase() === "#3f8aff", false);
    assert.equal(system.tokens.background.toLowerCase() === "#000000", false);
    assert.doesNotMatch(JSON.stringify(system), /stellar|soroban|freighter|manrope/i);
  }
  assert.deepEqual(dexDesign.tokens, portalDesign.tokens);
});

test("shared primitives expose accessible names, roles, and keyboard contracts", () => {
  for (const primitive of [dexPrimitive, portalPrimitive]) {
    const button = primitive("button");
    const field = primitive("text-field");
    const alert = primitive("alert");
    const status = primitive("status");
    assert.equal(button.role, "button");
    assert.ok(button.name);
    assert.equal(button.tabIndex, 0);
    assert.equal(button.focusRestore, true);
    assert.equal(field.role, "textbox");
    assert.ok(field.labelledBy);
    assert.equal(alert.role, "alert");
    assert.equal(status.ariaLive, "polite");
    assert.equal(status.reducedMotion, true);
  }
});

test("layouts collapse on mobile and keep independent product shells", () => {
  assert.equal(dexLayout(390).mode, "stack");
  assert.equal(portalLayout(390).mode, "stack");
  assert.equal(dexLayout(800).mode, "split");
  assert.equal(portalLayout(1280).mode, "workspace");
  assert.deepEqual(
    dexNav(poolUser).map((item) => item.path).sort(),
    ["/emergency-exit", "/history", "/migrate", "/send", "/shield", "/swap", "/withdraw"].sort(),
  );
  assert.ok(dexNav(poolUser).every((item) => !item.path.startsWith("/admin")));
  assert.ok(portalNav(adminA).some((item) => item.path === "/admin"));
  assert.ok(portalNav(auditorA).every((item) => item.path !== "/governance"));
});

test("frontend architecture treats nav hiding as non-authoritative and forbids secret logs", () => {
  for (const model of [dexThreat, portalThreat]) {
    assert.equal(model.navIsAuthorization, false);
    assert.equal(model.logWitnesses, false);
    assert.equal(model.logPlaintextNotes, false);
    assert.equal(model.independentDeployment, true);
    assert.equal(model.csp.defaultSrc, "'self'");
    assert.equal(model.csp.connectSrc, "'self'");
  }
});
