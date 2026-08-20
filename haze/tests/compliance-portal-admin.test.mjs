import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { HAZE_PRODUCT_ID } from "../sdk/typescript/src/identity.ts";
import { hashManifest } from "../sdk/typescript/src/manifest.ts";
import { SdkError } from "../sdk/typescript/src/errors.ts";
import {
  authorizeApi,
  createAdminWorkspace,
  renderAdminHtml,
} from "../apps/compliance-portal/src/index.ts";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const APP_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const APP_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

const adminA = { role: "application-admin", applicationId: APP_A };
const auditorA = { role: "application-auditor", applicationId: APP_A };
const poolUser = { role: "pool-user", applicationId: APP_A };
const superAuditor = { role: "super-auditor", applicationId: APP_A };

function fixtureManifest(applicationId = APP_A) {
  return {
    schemaVersion: 1,
    productId: HAZE_PRODUCT_ID,
    applicationId,
    organizationName: "Haze Test Org",
    gatekeeperEndpoint: "https://gk.example/v1",
    portalEndpoint: "https://portal.example",
    auditorPolicy: { fields: ["commitment"] },
    kmsKeyRefs: ["kms:aws:alias/haze-app-a"],
    auditKeys: [{ version: 1, publicKey: `0x${"11".repeat(32)}` }],
    sourceTokens: [{ token: "0x0000000000000000000000000000000000000001", decimals: 6 }],
    manifestVersion: 1,
  };
}

function memoryServices() {
  const cases = [];
  const grants = [];
  const reports = [
    { applicationId: APP_A, txHash: "0xaaa1", kind: "deposit" },
    { applicationId: APP_B, txHash: "0xbbb1", kind: "deposit" },
  ];
  let nextCase = 1;
  let nextGrant = 1;
  return {
    auditAuth: {
      async createCase({ title, reason }) {
        const record = { caseId: `case-${nextCase++}`, title, reason, applicationId: APP_A };
        cases.push(record);
        return record;
      },
      async listCases() {
        return [...cases];
      },
      async delegate({ auditor, expiresAt, capabilities }) {
        const grant = {
          grantId: `grant-${nextGrant++}`,
          auditor,
          expiresAt,
          capabilities,
          applicationId: APP_A,
          revoked: false,
        };
        grants.push(grant);
        return grant;
      },
      async revoke({ grantId }) {
        const grant = grants.find((item) => item.grantId === grantId);
        if (!grant) {
          throw new SdkError("NOT_FOUND");
        }
        grant.revoked = true;
        return grant;
      },
    },
    disclosure: {
      async export({ caseId, fields, applicationId }) {
        return {
          caseId,
          fields,
          applicationId,
          rows: [{ commitment: "0xcc" }],
        };
      },
    },
    indexer: {
      async queryApplication({ applicationId }) {
        return reports.filter((item) => item.applicationId === applicationId);
      },
    },
    health: {
      async kms() {
        return { status: "ok", refs: ["kms:aws:alias/haze-app-a"] };
      },
      async gatekeeper() {
        return { status: "ok", signer: "0x1111111111111111111111111111111111111111" };
      },
    },
  };
}

function createWorkspace() {
  return createAdminWorkspace({
    applicationId: APP_A,
    ...memoryServices(),
  });
}

test("only an application administrator can open the administration workspace", () => {
  const workspace = createWorkspace();
  assert.equal(workspace.signIn(poolUser).ok, false);
  assert.equal(workspace.signIn(auditorA).ok, false);
  assert.equal(workspace.signIn(superAuditor).ok, false);
  assert.equal(workspace.signIn(adminA).ok, true);
  assert.equal(workspace.navigate("/admin").ok, true);
  assert.equal(workspace.navigate("/governance").ok, false);
  assert.equal(workspace.screen().path, "/admin");
});

test("admin APIs stay isolated from other applications and custody routes", () => {
  assert.equal(authorizeApi(adminA, "POST", "/v1/manifests").ok, true);
  assert.equal(authorizeApi(adminA, "POST", "/v1/delegations").ok, true);
  assert.equal(authorizeApi(adminA, "POST", "/v1/cases").ok, true);
  assert.equal(authorizeApi(adminA, "GET", "/v1/reports/application").ok, true);
  assert.equal(authorizeApi(adminA, "POST", "/v1/disclosures/export").ok, true);
  assert.equal(
    authorizeApi(adminA, "POST", "/v1/manifests", { applicationId: APP_B }).code,
    "APPLICATION_MISMATCH",
  );
  assert.equal(authorizeApi(adminA, "POST", "/v1/pool/deposit").ok, false);
  assert.equal(authorizeApi(adminA, "POST", "/v1/governance/schedule").ok, false);
  assert.equal(authorizeApi(auditorA, "POST", "/v1/delegations").ok, false);
  assert.equal(authorizeApi(poolUser, "POST", "/v1/cases").ok, false);
});

test("registering a manifest pins the hash, rejects secrets, and records KMS health", async () => {
  const workspace = createWorkspace();
  workspace.signIn(adminA);
  const manifest = fixtureManifest();
  const hash = hashManifest(manifest);
  const registered = await workspace.registerManifest(manifest, hash);
  assert.equal(registered.applicationId, APP_A);
  assert.equal(registered.hash, hash);
  assert.equal(workspace.status().manifestHash, hash);
  const kms = await workspace.registerKms(["kms:aws:alias/haze-app-a"]);
  assert.equal(kms.status, "ok");
  assert.equal(workspace.status().kmsHealth, "ok");
  const signer = await workspace.gatekeeperSigner();
  assert.match(signer.signer, /^0x/);
  await assert.rejects(
    () => workspace.registerManifest({ ...manifest, privateKey: "0xdead" }, hash),
    (error) => error instanceof SdkError && error.code === "ENCODING_INVALID",
  );
});

test("other-application data cannot be registered or reported", async () => {
  const workspace = createWorkspace();
  workspace.signIn(adminA);
  const foreign = fixtureManifest(APP_B);
  await assert.rejects(
    () => workspace.registerManifest(foreign, hashManifest(foreign)),
    (error) => error instanceof SdkError && error.code === "APPLICATION_MISMATCH",
  );
  const reports = await workspace.transactionReports();
  assert.equal(reports.every((item) => item.applicationId === APP_A), true);
  assert.equal(reports.some((item) => item.applicationId === APP_B), false);
});

test("administrator delegates an auditor, opens a case, exports scoped records, and revokes", async () => {
  const workspace = createWorkspace();
  workspace.signIn(adminA);
  const grant = await workspace.delegateAuditor({
    auditor: "0x2222222222222222222222222222222222222222",
    expiresAt: 1_800_000_000,
    capabilities: ["query", "export"],
  });
  assert.equal(grant.revoked, false);
  const opened = await workspace.createCase({ title: "SAR-1", reason: "policy review" });
  assert.match(opened.caseId, /^case-/);
  const listed = await workspace.listCases();
  assert.equal(listed.length, 1);
  const exported = await workspace.exportDisclosure({
    caseId: opened.caseId,
    fields: ["commitment"],
  });
  assert.deepEqual(exported.fields, ["commitment"]);
  assert.equal(exported.applicationId, APP_A);
  const revoked = await workspace.revokeAccess({ grantId: grant.grantId });
  assert.equal(revoked.revoked, true);
  assert.equal(workspace.status().grants.find((item) => item.grantId === grant.grantId).revoked, true);
});

test("non-admin sessions cannot run administration mutations", async () => {
  const workspace = createWorkspace();
  workspace.signIn(auditorA);
  await assert.rejects(
    () =>
      workspace.delegateAuditor({
        auditor: "0x22",
        expiresAt: 1,
        capabilities: ["query"],
      }),
    (error) => error instanceof SdkError && error.code === "UNAUTHORIZED",
  );
});

test("admin HTML uses alpine-volcanic tokens and accessible workspace structure", () => {
  const workspace = createWorkspace();
  workspace.signIn(adminA);
  const desktop = renderAdminHtml(workspace.screen(1080));
  const mobile = renderAdminHtml(workspace.screen(390));
  assert.match(desktop, /IBM Plex Sans/);
  assert.match(desktop, /#16130f/);
  assert.match(desktop, /Skip to content/);
  assert.match(desktop, /id="haze-main"/);
  assert.match(desktop, /data-layout="workspace"/);
  assert.match(mobile, /data-layout="stack"/);
  assert.doesNotMatch(desktop, /stellar|soroban|freighter/i);
  mkdirSync(join(HAZE_ROOT, "apps/compliance-portal/public"), { recursive: true });
  writeFileSync(join(HAZE_ROOT, "apps/compliance-portal/public/admin.html"), desktop);
  writeFileSync(join(HAZE_ROOT, "apps/compliance-portal/public/admin-mobile.html"), mobile);
});
