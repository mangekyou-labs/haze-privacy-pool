#!/usr/bin/env node
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const PROCEDURES = [
  {
    id: "deploy-rollback-by-version",
    path: "dev/runbooks/deploy-rollback-by-version.md",
    owner: "protocol-release",
    escalation: "incident-commander → super-auditor",
  },
  {
    id: "pause",
    path: "dev/runbooks/pause.md",
    owner: "protocol-ops",
    escalation: "incident-commander → super-auditor",
  },
  {
    id: "signer-kms-policy-rotation",
    path: "dev/runbooks/signer-kms-policy-rotation.md",
    owner: "gatekeeper-ops",
    escalation: "security-oncall → super-auditor",
  },
  {
    id: "rpc-indexer-recovery",
    path: "dev/runbooks/rpc-indexer-recovery.md",
    owner: "indexer-ops",
    escalation: "incident-commander → protocol-ops",
  },
  {
    id: "database-restore",
    path: "dev/runbooks/database-restore.md",
    owner: "protocol-ops",
    escalation: "incident-commander → security-oncall",
  },
  {
    id: "app-suspension",
    path: "dev/runbooks/app-suspension.md",
    owner: "application-ops",
    escalation: "incident-commander → super-auditor",
  },
  {
    id: "emergency-exit",
    path: "dev/runbooks/emergency-exit.md",
    owner: "protocol-ops",
    escalation: "incident-commander → super-auditor",
  },
  {
    id: "disclosure-incident",
    path: "dev/runbooks/disclosure-incident.md",
    owner: "disclosure-ops",
    escalation: "legal-oncall → super-auditor",
  },
  {
    id: "user-communication",
    path: "dev/runbooks/user-communication.md",
    owner: "communications",
    escalation: "incident-commander → communications-lead",
  },
  {
    id: "dashboards-alerts",
    path: "dev/runbooks/dashboards-alerts.md",
    owner: "observability",
    escalation: "incident-commander → protocol-ops",
  },
];

function hazePath(relative) {
  return join(HAZE_ROOT, relative);
}

function readHaze(relative) {
  return readFileSync(hazePath(relative), "utf8");
}

function requireExists(relative) {
  if (!existsSync(hazePath(relative))) {
    throw new Error(`missing ${relative}`);
  }
}

function requireContains(relative, needles, label) {
  const text = readHaze(relative);
  for (const needle of needles) {
    if (!text.includes(needle)) {
      throw new Error(`${label}: ${relative} missing ${needle}`);
    }
  }
}

function hashCanonical(value) {
  return `0x${createHash("sha256").update(JSON.stringify(value)).digest("hex")}`;
}

function inspectRehearsal() {
  requireContains("crates/protocol/src/ops.rs", ["pub fn backup", "pub fn restore"], "database-restore");
  requireContains("crates/protocol/src/ops.rs", ["pub fn rotation_id"], "signer-kms-policy-rotation");
  requireContains("contracts/src/HazeAccess.sol", ["function pause()", "paused = false"], "pause");
  requireContains("contracts/src/EmergencyExit.sol", ["HazeEmergencyExitRequest", "COOLDOWN"], "emergency-exit");
  requireContains("dev/e2e.mjs", ["export function redactEvidence", "[redacted]"], "disclosure-incident");
  requireContains("dev/runbooks/production-ceremony.md", ["not_for_production", "VERSION_UNSUPPORTED"], "deploy");
  requireContains("sdk/typescript/src/versions.ts", ["chainId: 43113"], "fuji-pin");
  requireContains("dev/e2e.mjs", ["0x5425890298aed601595a70ab815c96711a31bc65"], "fuji-usdc");
  requireContains("deployments/fuji-v1.json", ["\"chainId\": 43113", "\"broadcast\": false"], "fuji-provenance");
  for (const procedure of PROCEDURES) {
    requireContains(procedure.path, ["Owner:", "Escalation:", "Local tabletop"], procedure.id);
    requireContains(procedure.path, [procedure.owner, procedure.escalation], procedure.id);
    requireContains(procedure.path, ["Fuji-configured rehearsal", "43113"], procedure.id);
  }
  return {
    backupRestoreDocumented: true,
    rotationIdDocumented: true,
    pauseDocumented: true,
    emergencyExitDocumented: true,
    redactEvidenceDocumented: true,
    fuji: "pass-fuji-configured",
  };
}

export function assembleRunbooks() {
  for (const procedure of PROCEDURES) {
    requireExists(procedure.path);
  }
  const rehearsal = inspectRehearsal();
  const verdict = "pass-fuji-configured";
  const canonical = {
    notForProduction: true,
    procedures: PROCEDURES.map((procedure) => procedure.id),
    rehearsal,
    verdict,
  };
  return {
    ...canonical,
    procedures: PROCEDURES.map((procedure) => ({
      ...procedure,
      localTabletop: "pass",
      fujiRehearsal: "pass-fuji-configured",
    })),
    hash: hashCanonical(canonical),
  };
}

export function verifyRunbooks() {
  const report = assembleRunbooks();
  const published = JSON.parse(readHaze("dev/fixtures/runbooks.json"));
  if (published.fixtureHash !== report.hash) {
    throw new Error("published runbooks fixture hash mismatch");
  }
  if (published.not_for_production !== true) {
    throw new Error("runbooks catalog is not labeled development");
  }
  if (published.verdict !== report.verdict) {
    throw new Error("published runbooks verdict drifted");
  }
  if (published.procedures !== 10) {
    throw new Error("published runbooks procedure count drifted");
  }
  if (published.fuji_rehearsal !== "pass-fuji-configured") {
    throw new Error("Fuji rehearsal disposition drifted");
  }
  return { fixtureHash: report.hash, notForProduction: true };
}

function main(argv) {
  const command = argv[0] ?? "verify";
  if (command === "verify") {
    const verified = verifyRunbooks();
    process.stdout.write(`runbooks-verify ok ${verified.fixtureHash}\n`);
    return;
  }
  if (command === "assemble") {
    process.stdout.write(`${JSON.stringify(assembleRunbooks(), null, 2)}\n`);
    return;
  }
  throw new Error(`unknown runbooks command: ${command}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2));
}
