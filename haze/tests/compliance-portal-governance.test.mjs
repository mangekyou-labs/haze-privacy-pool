import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { SdkError } from "../sdk/typescript/src/errors.ts";
import {
  authorizeApi,
  createGovernanceWorkspace,
  renderGovernanceHtml,
} from "../apps/compliance-portal/src/index.ts";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const APP_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const APP_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

const superAuditor = { role: "super-auditor", applicationId: APP_A };
const adminA = { role: "application-admin", applicationId: APP_A };
const auditorA = { role: "application-auditor", applicationId: APP_A };
const poolUser = { role: "pool-user", applicationId: APP_A };

const REGISTRY = "0x1111111111111111111111111111111111111111";
const TIMELOCK = "0x2222222222222222222222222222222222222222";
const DELAY = 86_400;

function memoryServices() {
  const schedules = [];
  return {
    registry: {
      address: REGISTRY,
      timelock: TIMELOCK,
      delay: DELAY,
      async schedule(tx) {
        const item = { ...tx, executed: false };
        schedules.push(item);
        return item;
      },
      async execute(id) {
        const item = schedules.find((entry) => entry.id === id);
        if (!item) {
          throw new SdkError("UNAUTHORIZED");
        }
        item.executed = true;
        return item;
      },
      async list() {
        return [...schedules];
      },
    },
    status: {
      async snapshot() {
        return {
          suspended: [APP_A],
          emergency: { paused: false, exitOpen: true },
          versions: {
            pool: "1.0.0",
            artifactHash: "0x" + "ab".repeat(32),
            provenance: "development",
          },
          ceremony: { transcriptHash: "0x" + "cd".repeat(32), production: false },
        };
      },
    },
  };
}

function createWorkspace(clock = () => 1_000) {
  return createGovernanceWorkspace({
    applicationId: APP_A,
    clock,
    ...memoryServices(),
  });
}

test("only a super-auditor can open the governance workspace", () => {
  const workspace = createWorkspace();
  assert.equal(workspace.signIn(poolUser).ok, false);
  assert.equal(workspace.signIn(adminA).ok, false);
  assert.equal(workspace.signIn(auditorA).ok, false);
  assert.equal(workspace.signIn(superAuditor).ok, true);
  assert.equal(workspace.navigate("/governance").ok, true);
  assert.equal(workspace.navigate("/admin").ok, false);
  assert.equal(workspace.navigate("/audit").ok, false);
  assert.equal(workspace.screen().path, "/governance");
});

test("governance APIs stay isolated from custody, admin mutations, and other applications", () => {
  assert.equal(authorizeApi(superAuditor, "POST", "/v1/governance/schedule").ok, true);
  assert.equal(authorizeApi(superAuditor, "POST", "/v1/governance/execute").ok, true);
  assert.equal(authorizeApi(superAuditor, "GET", "/v1/governance/status").ok, true);
  assert.equal(authorizeApi(superAuditor, "POST", "/v1/governance/super-auditor").ok, true);
  assert.equal(authorizeApi(superAuditor, "POST", "/v1/pool/deposit").ok, false);
  assert.equal(authorizeApi(superAuditor, "POST", "/v1/pool/transact").ok, false);
  assert.equal(authorizeApi(superAuditor, "POST", "/v1/delegations").ok, false);
  assert.equal(authorizeApi(adminA, "POST", "/v1/governance/schedule").ok, false);
  assert.equal(
    authorizeApi(superAuditor, "POST", "/v1/governance/schedule", { applicationId: APP_B }).code,
    "APPLICATION_MISMATCH",
  );
});

test("preview shows exact on-chain targets and unsigned execute is TIMELOCK", async () => {
  const workspace = createWorkspace();
  workspace.signIn(superAuditor);
  const preview = await workspace.previewSchedule({
    kind: "policy-root",
    target: REGISTRY,
    calldata: "0xdead",
    eta: 1_000 + DELAY,
  });
  assert.equal(preview.target, REGISTRY);
  assert.equal(preview.timelock, TIMELOCK);
  assert.equal(preview.delay, DELAY);
  assert.equal(preview.kind, "policy-root");
  await assert.rejects(
    () => workspace.execute({ id: "missing" }),
    (error) => error instanceof SdkError && error.code === "TIMELOCK",
  );
});

test("schedule then early execute is TIMELOCK; execute after delay activates", async () => {
  let now = 1_000;
  const workspace = createWorkspace(() => now);
  workspace.signIn(superAuditor);
  await workspace.previewSchedule({
    kind: "application-suspend",
    target: REGISTRY,
    calldata: "0xbeef",
    eta: 1_000 + DELAY,
  });
  const scheduled = await workspace.schedule();
  assert.equal(scheduled.executed, false);
  await assert.rejects(
    () => workspace.execute({ id: scheduled.id }),
    (error) => error instanceof SdkError && error.code === "TIMELOCK",
  );
  now = 1_000 + DELAY;
  const executed = await workspace.execute({ id: scheduled.id });
  assert.equal(executed.executed, true);
});

test("status exposes suspensions, emergency, versions, ceremony, and super-auditor grant without custody", async () => {
  const workspace = createWorkspace();
  workspace.signIn(superAuditor);
  const snap = await workspace.protocolStatus();
  assert.deepEqual(snap.suspended, [APP_A]);
  assert.equal(snap.emergency.exitOpen, true);
  assert.match(snap.versions.artifactHash, /^0x/);
  assert.equal(snap.ceremony.production, false);
  const grant = await workspace.grantSuperAuditor({
    wallet: "0x3333333333333333333333333333333333333333",
  });
  assert.equal(grant.custody, false);
  assert.equal(authorizeApi(superAuditor, "POST", "/v1/pool/deposit").ok, false);
});

test("non-super-auditor sessions cannot schedule governance", async () => {
  const workspace = createWorkspace();
  workspace.signIn(adminA);
  await assert.rejects(
    () =>
      workspace.previewSchedule({
        kind: "policy-root",
        target: REGISTRY,
        calldata: "0x00",
        eta: 2_000,
      }),
    (error) => error instanceof SdkError && error.code === "UNAUTHORIZED",
  );
});

test("governance HTML uses alpine-volcanic tokens and accessible workspace structure", () => {
  const workspace = createWorkspace();
  workspace.signIn(superAuditor);
  const desktop = renderGovernanceHtml(workspace.screen(1080));
  const mobile = renderGovernanceHtml(workspace.screen(390));
  assert.match(desktop, /IBM Plex Sans/);
  assert.match(desktop, /#16130f/);
  assert.match(desktop, /Skip to content/);
  assert.match(desktop, /id="haze-main"/);
  assert.match(desktop, /data-layout="workspace"/);
  assert.match(mobile, /data-layout="stack"/);
  assert.doesNotMatch(desktop, /stellar|soroban|freighter/i);
  mkdirSync(join(HAZE_ROOT, "apps/compliance-portal/public"), { recursive: true });
  writeFileSync(join(HAZE_ROOT, "apps/compliance-portal/public/governance.html"), desktop);
  writeFileSync(join(HAZE_ROOT, "apps/compliance-portal/public/governance-mobile.html"), mobile);
});
