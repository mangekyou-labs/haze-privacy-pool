import assert from "node:assert/strict";
import test from "node:test";
import { POST } from "../web/apps/haze/app/api/v1/pool/membership-root/route.ts";
import { unionMembershipLeaves } from "../sdk/typescript/src/fuji-membership-store.ts";
import {
  SparseMerkleTree,
  buildLiveDepositWitness,
  buildLiveTransferWitness,
} from "../dev/operator-circuit-witness.mjs";
import { applicationMember } from "../sdk/typescript/src/policy.ts";
import { APP_TREE } from "../sdk/typescript/src/merkle.ts";

const LIVE_POOL = "0x3333333333333333333333333333333333333333";
const LIVE_OPERATOR = "0xeD37fd0d6f0f69236e7472b36796e133d20ecc32";
const LIVE_APP = `0x${(0xa11n).toString(16).padStart(64, "0")}`;
const LIVE_POOL_VERSION = `0x${(0xb001n).toString(16).padStart(64, "0")}`;

function canonicalMembershipRoot(applicationId, leaves) {
  const tree = new SparseMerkleTree(APP_TREE);
  let next = 0;
  const seen = new Set();
  for (const leaf of leaves) {
    if (!leaf?.npk || !leaf?.enc) continue;
    const key = `${String(leaf.npk).toLowerCase()}:${String(leaf.enc).toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    tree.insert(next, applicationMember(applicationId, leaf.npk, leaf.enc));
    next += 1;
  }
  return tree.root();
}

function jsonRequest(body, headers = {}) {
  return new Request("http://localhost:3010/api/v1/pool/membership-root", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      origin: "http://localhost:3010",
      host: "localhost:3010",
      ...headers,
    },
    body: JSON.stringify(body),
  });
}

test("membership-root route returns 503 when policy authority key is missing", async () => {
  const origKey = process.env.HAZE_FUJI_POLICY_AUTHORITY_KEY;
  try {
    delete process.env.HAZE_FUJI_POLICY_AUTHORITY_KEY;
    const req = jsonRequest({
      applicationId: `0x${"00".repeat(30)}0a11`,
      membershipRoot: `0x${"12".repeat(32)}`,
    });
    const res = await POST(req);
    assert.equal(res.status, 503);
    const data = await res.json();
    assert.equal(data.error, "MEMBERSHIP_RELAYER_UNAVAILABLE");
  } finally {
    if (origKey) process.env.HAZE_FUJI_POLICY_AUTHORITY_KEY = origKey;
  }
});

test("membership-root route returns 400 on invalid parameters", async () => {
  const origKey = process.env.HAZE_FUJI_POLICY_AUTHORITY_KEY;
  try {
    process.env.HAZE_FUJI_POLICY_AUTHORITY_KEY = "0x" + "11".repeat(32);
    const badApp = jsonRequest({
      applicationId: "invalid",
      membershipRoot: `0x${"12".repeat(32)}`,
    });
    const res1 = await POST(badApp);
    assert.equal(res1.status, 400);

    const badRoot = jsonRequest({
      applicationId: `0x${"00".repeat(30)}0a11`,
      membershipRoot: "not-hex",
    });
    const res2 = await POST(badRoot);
    assert.equal(res2.status, 400);
  } finally {
    if (origKey) process.env.HAZE_FUJI_POLICY_AUTHORITY_KEY = origKey;
    else delete process.env.HAZE_FUJI_POLICY_AUTHORITY_KEY;
  }
});

test("membership-root route returns 403 on CSRF origin mismatch", async () => {
  const req = new Request("http://localhost:3010/api/v1/pool/membership-root", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      origin: "https://evil.com",
      host: "localhost:3010",
    },
    body: JSON.stringify({
      applicationId: `0x${"00".repeat(30)}0a11`,
      membershipRoot: `0x${"12".repeat(32)}`,
    }),
  });
  const res = await POST(req);
  assert.equal(res.status, 403);
  const data = await res.json();
  assert.equal(data.error, "CSRF_ORIGIN_INVALID");
});

test("membership-root route accepts valid membership leaves", async () => {
  const origKey = process.env.HAZE_FUJI_POLICY_AUTHORITY_KEY;
  try {
    process.env.HAZE_FUJI_POLICY_AUTHORITY_KEY = "0x" + "11".repeat(32);
    const req = jsonRequest({
      applicationId: `0x${"00".repeat(30)}0a11`,
      membershipLeaves: [
        {
          npk: `0x${"01".repeat(32)}`,
          enc: `0x${"02".repeat(32)}`,
        },
      ],
    });
    const res = await POST(req);
    // Either 200 (if root matches or transaction succeeds) or network response, but not 400 ENCODING_INVALID
    assert.notEqual(res.status, 400);
  } finally {
    if (origKey) process.env.HAZE_FUJI_POLICY_AUTHORITY_KEY = origKey;
    else delete process.env.HAZE_FUJI_POLICY_AUTHORITY_KEY;
  }
});

test("membership-root route rejects root mismatch when membership leaves are provided", async () => {
  const origKey = process.env.HAZE_FUJI_POLICY_AUTHORITY_KEY;
  try {
    process.env.HAZE_FUJI_POLICY_AUTHORITY_KEY = "0x" + "11".repeat(32);
    const mismatched = jsonRequest({
      applicationId: `0x${"00".repeat(30)}0a11`,
      membershipRoot: `0x${"12".repeat(32)}`,
      membershipLeaves: [
        {
          npk: `0x${"01".repeat(32)}`,
          enc: `0x${"02".repeat(32)}`,
        },
      ],
    });
    const res = await POST(mismatched);
    assert.equal(res.status, 400);
    const data = await res.json();
    assert.equal(data.error, "INVALID_MEMBERSHIP_ROOT");
  } finally {
    if (origKey) process.env.HAZE_FUJI_POLICY_AUTHORITY_KEY = origKey;
    else delete process.env.HAZE_FUJI_POLICY_AUTHORITY_KEY;
  }
});

test("unionMembershipLeaves preserves stored then in then out order and drops duplicates", () => {
  const stored = [
    { npk: `0x${"11".repeat(32)}`, enc: `0x${"12".repeat(32)}` },
    { npk: `0x${"13".repeat(32)}`, enc: `0x${"14".repeat(32)}` },
  ];
  const inSlots = [
    { npk: `0x${"11".repeat(32)}`, enc: `0x${"12".repeat(32)}` },
    { npk: `0x${"15".repeat(32)}`, enc: `0x${"16".repeat(32)}` },
  ];
  const outSlots = [
    { npk: `0x${"17".repeat(32)}`, enc: `0x${"18".repeat(32)}` },
    { npk: `0x${"15".repeat(32)}`, enc: `0x${"16".repeat(32)}` },
  ];
  const union = unionMembershipLeaves(stored, inSlots, outSlots);
  assert.deepEqual(
    union.map((leaf) => leaf.npk),
    [`0x${"11".repeat(32)}`, `0x${"13".repeat(32)}`, `0x${"15".repeat(32)}`, `0x${"17".repeat(32)}`],
  );
});

test("unionMembershipLeaves skips duplicate npk:enc case-insensitively", () => {
  const union = unionMembershipLeaves(
    [{ npk: `0x${"AA".repeat(32)}`, enc: `0x${"BB".repeat(32)}` }],
    [{ npk: `0x${"aa".repeat(32)}`, enc: `0x${"bb".repeat(32)}` }],
    [],
  );
  assert.equal(union.length, 1);
});

test("membership-root rejects stored-only leaves against a Send witness root that includes recipient and change", async () => {
  const origKey = process.env.HAZE_FUJI_POLICY_AUTHORITY_KEY;
  try {
    process.env.HAZE_FUJI_POLICY_AUTHORITY_KEY = "0x" + "11".repeat(32);
    const stored = [{ npk: `0x${"18".repeat(32)}`, enc: `0x${"19".repeat(32)}` }];
    const deposit = buildLiveDepositWitness({
      pool: LIVE_POOL,
      user: LIVE_OPERATOR,
      applicationId: LIVE_APP,
      poolVersion: LIVE_POOL_VERSION,
      value: 1_000_000,
    });
    const transfer = buildLiveTransferWitness({
      pool: LIVE_POOL,
      user: LIVE_OPERATOR,
      applicationId: LIVE_APP,
      poolVersion: LIVE_POOL_VERSION,
      note: deposit.note,
      sendAmount: 400_000,
      recipientX25519: `0x${"22".repeat(32)}`,
      recipientSecret: `0x${"14".repeat(32)}`,
      recipientBlinding: `0x${"15".repeat(32)}`,
      changeSecret: `0x${"16".repeat(32)}`,
      changeBlinding: `0x${"17".repeat(32)}`,
      changeX25519: deposit.note.x25519,
      membershipLeaves: stored,
    });
    const union = unionMembershipLeaves(
      stored,
      [{ npk: deposit.note.npk, enc: deposit.note.enc }],
      [transfer.recipientNote, transfer.note],
    );
    assert.equal(transfer.circom.applicationMembershipRoot, canonicalMembershipRoot(LIVE_APP, union));
    const storedOnly = jsonRequest({
      applicationId: LIVE_APP,
      membershipRoot: transfer.circom.applicationMembershipRoot,
      membershipLeaves: stored,
    });
    const res = await POST(storedOnly);
    assert.equal(res.status, 400);
    const data = await res.json();
    assert.equal(data.error, "INVALID_MEMBERSHIP_ROOT");
  } finally {
    if (origKey) process.env.HAZE_FUJI_POLICY_AUTHORITY_KEY = origKey;
    else delete process.env.HAZE_FUJI_POLICY_AUTHORITY_KEY;
  }
});
