import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { SdkError } from "../sdk/typescript/src/errors.ts";
import {
  authorizeApi,
  createAuditWorkspace,
  renderAuditHtml,
} from "../apps/compliance-portal/src/index.ts";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const APP_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const APP_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const AUDITOR = "0x2222222222222222222222222222222222222222";

const auditorA = { role: "application-auditor", applicationId: APP_A };
const adminA = { role: "application-admin", applicationId: APP_A };
const poolUser = { role: "pool-user", applicationId: APP_A };
const superAuditor = { role: "super-auditor", applicationId: APP_A };

function memoryServices() {
  const assigned = [
    {
      caseId: "case-1",
      title: "SAR-1",
      applicationId: APP_A,
      fields: ["commitment"],
      expiresAt: 1_900_000_000,
      revoked: false,
    },
    {
      caseId: "case-foreign",
      title: "other-app",
      applicationId: APP_B,
      fields: ["commitment"],
      expiresAt: 1_900_000_000,
      revoked: false,
    },
  ];
  const records = [
    { caseId: "case-1", applicationId: APP_A, commitment: "0xcc", plaintext: "secret" },
  ];
  const log = [];
  return {
    auditAuth: {
      async challenge({ address }) {
        return { nonce: "siwe-nonce", address };
      },
      async token({ address, signature, nonce }) {
        if (!signature || nonce !== "siwe-nonce") {
          throw new SdkError("UNAUTHORIZED");
        }
        return { token: "audience-cases", address };
      },
      async listAssigned() {
        return assigned.filter((item) => item.applicationId === APP_A);
      },
    },
    disclosure: {
      async query({ caseId, fields, applicationId, grant }) {
        if (grant?.revoked) {
          throw new SdkError("UNAUTHORIZED");
        }
        if (grant && grant.expiresAt <= 1_000) {
          throw new SdkError("AUTHORIZATION_EXPIRED");
        }
        if (applicationId !== APP_A) {
          throw new SdkError("APPLICATION_MISMATCH");
        }
        const extra = fields.find((field) => !grant.fields.includes(field));
        if (extra) {
          throw new SdkError("UNAUTHORIZED");
        }
        const hit = records.find((item) => item.caseId === caseId);
        if (!hit) {
          throw new SdkError("UNAUTHORIZED");
        }
        const row = { caseId, applicationId };
        for (const field of fields) {
          row[field] = hit[field];
        }
        log.push({ action: "query", caseId, allowed: true });
        return { rows: [row] };
      },
      async export({ caseId, fields, applicationId, grant }) {
        const queried = await this.query({ caseId, fields, applicationId, grant });
        log.push({ action: "export", caseId, allowed: true });
        return { caseId, fields, applicationId, rows: queried.rows };
      },
      async accessLog() {
        return [...log];
      },
    },
  };
}

function createWorkspace() {
  return createAuditWorkspace({
    applicationId: APP_A,
    auditor: AUDITOR,
    ...memoryServices(),
  });
}

test("only an application auditor can open the investigation workspace", async () => {
  const workspace = createWorkspace();
  assert.equal(workspace.signIn(poolUser).ok, false);
  assert.equal(workspace.signIn(adminA).ok, false);
  assert.equal(workspace.signIn(superAuditor).ok, false);
  const challenge = await workspace.startSiwe(AUDITOR);
  assert.equal(challenge.nonce, "siwe-nonce");
  const bound = await workspace.completeSiwe({
    address: AUDITOR,
    signature: "0xsig",
    nonce: challenge.nonce,
  });
  assert.equal(bound.token, "audience-cases");
  assert.equal(workspace.signIn(auditorA).ok, true);
  assert.equal(workspace.navigate("/audit").ok, true);
  assert.equal(workspace.navigate("/admin").ok, false);
  assert.equal(workspace.navigate("/governance").ok, false);
  assert.equal(workspace.screen().path, "/audit");
});

test("auditor APIs stay isolated from other applications, admin mutations, and custody", () => {
  assert.equal(authorizeApi(auditorA, "GET", "/v1/disclosures/query").ok, true);
  assert.equal(authorizeApi(auditorA, "POST", "/v1/disclosures/export").ok, true);
  assert.equal(authorizeApi(auditorA, "GET", "/v1/cases").ok, true);
  assert.equal(authorizeApi(auditorA, "GET", "/v1/access-log").ok, true);
  assert.equal(
    authorizeApi(auditorA, "GET", "/v1/disclosures/query", { applicationId: APP_B }).code,
    "APPLICATION_MISMATCH",
  );
  assert.equal(authorizeApi(auditorA, "POST", "/v1/delegations").ok, false);
  assert.equal(authorizeApi(auditorA, "POST", "/v1/cases").ok, false);
  assert.equal(authorizeApi(auditorA, "POST", "/v1/governance/schedule").ok, false);
  assert.equal(authorizeApi(auditorA, "POST", "/v1/pool/deposit").ok, false);
  assert.equal(authorizeApi(adminA, "GET", "/v1/disclosures/query").ok, false);
});

test("auditor sees assigned cases and cannot query unassigned or foreign cases", async () => {
  const workspace = createWorkspace();
  workspace.signIn(auditorA);
  const cases = await workspace.assignedCases();
  assert.deepEqual(
    cases.map((item) => item.caseId),
    ["case-1"],
  );
  await assert.rejects(
    () => workspace.search({ caseId: "case-missing", fields: ["commitment"] }),
    (error) => error instanceof SdkError && error.code === "UNAUTHORIZED",
  );
  await assert.rejects(
    () => workspace.search({ caseId: "case-foreign", fields: ["commitment"] }),
    (error) => error instanceof SdkError && error.code === "UNAUTHORIZED",
  );
});

test("field-limited search and export hide ungranted columns", async () => {
  const workspace = createWorkspace();
  workspace.signIn(auditorA);
  const detail = await workspace.search({ caseId: "case-1", fields: ["commitment"] });
  assert.equal(detail.rows[0].commitment, "0xcc");
  assert.equal(detail.rows[0].plaintext, undefined);
  await assert.rejects(
    () => workspace.search({ caseId: "case-1", fields: ["commitment", "plaintext"] }),
    (error) => error instanceof SdkError && error.code === "UNAUTHORIZED",
  );
  const exported = await workspace.exportDisclosure({
    caseId: "case-1",
    fields: ["commitment"],
  });
  assert.deepEqual(exported.fields, ["commitment"]);
  assert.equal(exported.applicationId, APP_A);
});

test("expired or revoked grants surface in the workspace and fail closed", async () => {
  const workspace = createAuditWorkspace({
    applicationId: APP_A,
    auditor: AUDITOR,
    ...memoryServices(),
    clock: () => 2_000_000_000,
    grantOverride: { expiresAt: 1_000, revoked: true },
  });
  workspace.signIn(auditorA);
  const status = workspace.status();
  assert.equal(status.expired, true);
  assert.equal(status.revoked, true);
  await assert.rejects(
    () => workspace.search({ caseId: "case-1", fields: ["commitment"] }),
    (error) =>
      error instanceof SdkError &&
      (error.code === "UNAUTHORIZED" || error.code === "AUTHORIZATION_EXPIRED"),
  );
});

test("personal access history records allowed queries and denied field overreach", async () => {
  const workspace = createWorkspace();
  workspace.signIn(auditorA);
  await workspace.search({ caseId: "case-1", fields: ["commitment"] });
  await workspace.search({ caseId: "case-1", fields: ["plaintext"] }).catch(() => undefined);
  const history = await workspace.accessHistory();
  assert.ok(history.some((item) => item.action === "query" && item.allowed === true));
  assert.ok(history.some((item) => item.allowed === false));
});

test("audit HTML uses alpine-volcanic tokens and accessible investigation structure", () => {
  const workspace = createWorkspace();
  workspace.signIn(auditorA);
  const desktop = renderAuditHtml(workspace.screen(1080));
  const mobile = renderAuditHtml(workspace.screen(390));
  assert.match(desktop, /IBM Plex Sans/);
  assert.match(desktop, /#16130f/);
  assert.match(desktop, /Skip to content/);
  assert.match(desktop, /id="haze-main"/);
  assert.match(desktop, /data-layout="workspace"/);
  assert.match(mobile, /data-layout="stack"/);
  assert.doesNotMatch(desktop, /stellar|soroban|freighter/i);
  mkdirSync(join(HAZE_ROOT, "apps/compliance-portal/public"), { recursive: true });
  writeFileSync(join(HAZE_ROOT, "apps/compliance-portal/public/audit.html"), desktop);
  writeFileSync(join(HAZE_ROOT, "apps/compliance-portal/public/audit-mobile.html"), mobile);
});
