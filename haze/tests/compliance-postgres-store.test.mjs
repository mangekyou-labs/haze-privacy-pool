import assert from "node:assert/strict";
import test from "node:test";

import {
  FUJI_CHAIN_ID,
  LIVE_APP_ID,
  LIVE_POSEIDON_POOL,
  REQUIRED_CONFIRMATIONS,
  DEDICATED_AUDITOR,
} from "../sdk/typescript/src/compliance-service.ts";
import { CompliancePostgresStore } from "../web/apps/haze/lib/compliance-postgres-store.ts";

/** Minimal in-memory Postgres mock: resolves rows/params and records SQL. */
function mockPool() {
  const tables = new Map();
  const sql = [];
  const pool = {
    tables,
    sql,
    async query(text, params = []) {
      sql.push(text);
      if (/insert into haze_compliance_cases/i.test(text)) {
        // params order for the honest insert:
        //  1 case_id, 2 title, 3 chain_id, 4 pool, 5 application_id, 6 transaction_hash,
        //  7 log_index, 8 block_number, 9 block_hash, 10 status, 11 confirmations,
        //  12 required_confirmations, 13 assigned_auditor, 14 amount, 15 asset,
        //  16 event_timestamp, 17 policy_version, 18 witness_data, 19 granted, 20 denied
        const row = {
          case_id: params[0], title: params[1], chain_id: params[2],
          pool: params[3], application_id: params[4], transaction_hash: params[5],
          log_index: params[6], block_number: params[7], block_hash: params[8],
          status: params[9], confirmations: params[10], required_confirmations: params[11],
          assigned_auditor: params[12], amount: params[13], asset: params[14],
          event_timestamp: params[15], policy_version: params[16], witness_data: params[17],
          granted_fields: params[18], denied_fields: params[19],
          created_at: new Date(), updated_at: new Date(),
        };
        if (!tables.has("haze_compliance_cases")) tables.set("haze_compliance_cases", []);
        tables.get("haze_compliance_cases").push(row);
        return { rows: [] };
      }
      if (/select \* from haze_compliance_cases where case_id/i.test(text)) {
        const rows = (tables.get("haze_compliance_cases") ?? []).filter((r) => r.case_id === params[0]);
        return { rows };
      }
      if (/select status from haze_compliance_cases/i.test(text)) {
        const rows = (tables.get("haze_compliance_cases") ?? []).filter((r) => r.case_id === params[0]);
        return { rows: rows.map((r) => ({ status: r.status })) };
      }
      if (/update haze_compliance_cases/i.test(text)) {
        const rows = (tables.get("haze_compliance_cases") ?? []).filter((r) => r.case_id === params[1]);
        rows.forEach((r) => { r.status = params[0]; });
        return { rows };
      }
      return { rows: [] };
    },
  };
  return pool;
}

test("postgres store case identity survives a round trip (no fabricated block 0 / confirmation sentinel)", async () => {
  const pool = mockPool();
  const store = new CompliancePostgresStore(pool);
  const txHash = "0x" + "88".repeat(32);
  const blockNumber = 42;
  const logIndex = 3;

  await store.upsertWithdrawalCase({
    chainId: FUJI_CHAIN_ID,
    pool: LIVE_POSEIDON_POOL,
    applicationId: LIVE_APP_ID,
    transactionHash: txHash,
    logIndex,
    blockNumber,
    currentBlockNumber: blockNumber + 5,
  });

  const caseItem = await store.getCaseById(`case-fuji-${txHash.slice(2, 10)}-${logIndex}`);
  assert.ok(caseItem);
  assert.equal(caseItem.chainId, FUJI_CHAIN_ID);
  assert.equal(caseItem.pool, LIVE_POSEIDON_POOL.toLowerCase());
  assert.equal(caseItem.logIndex, logIndex);
  assert.equal(caseItem.blockNumber, blockNumber);
  assert.equal(caseItem.confirmationCount, 6);
  assert.equal(caseItem.assignedAuditor, DEDICATED_AUDITOR.toLowerCase());
});

test("postgres store disclosure uses stored amount, not hardcoded 1.000000 USDC", async () => {
  const pool = mockPool();
  const store = new CompliancePostgresStore(pool);
  const txHash = "0x" + "99".repeat(32);
  const blockNumber = 100;

  const caseItem = await store.upsertWithdrawalCase({
    chainId: FUJI_CHAIN_ID,
    pool: LIVE_POSEIDON_POOL,
    applicationId: LIVE_APP_ID,
    transactionHash: txHash,
    logIndex: 0,
    blockNumber,
    currentBlockNumber: blockNumber + 15,
    witnessData: { auditRecord: { facts: { publicAmount: 3_000_000, timestamp: 1724000000, applicationPolicyVersion: 1 } } },
  });
  assert.equal(caseItem.caseState, "ready");

  const disclosure = await store.discloseCase(caseItem.caseId, DEDICATED_AUDITOR);
  assert.equal(disclosure.fields.amount, "3.00 USDC");
  assert.notEqual(disclosure.fields.amount, "1.000000 USDC");
});
