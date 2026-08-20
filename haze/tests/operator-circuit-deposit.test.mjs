import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  assertCommittedFujiUntouched,
  detectPoolNoteTree,
  isPlaceholderPolicyRoot,
  planLiveCircuitDeposit,
} from "../dev/operator-circuit-deposit.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const POOL = join(HAZE_ROOT, "contracts/src/HazePool.sol");
const FUJI = join(HAZE_ROOT, "deployments/fuji-v1.json");
const LIVE = join(HAZE_ROOT, "deployments/fuji-v1.live.json");

test("live HazePool still hashes keccak parents, not Poseidon2 note-tree-node", () => {
  const source = readFileSync(POOL, "utf8");
  assert.equal(detectPoolNoteTree(source), "keccak");
  assert.match(source, /keccak parents reduced mod r/);
  assert.doesNotMatch(source, /haze\/avalanche\/v1\/note-tree-node/);
});

test("live sidecar records the Poseidon pool and keeps the keccak set in previous", () => {
  const live = JSON.parse(readFileSync(LIVE, "utf8"));
  assert.equal(live.chainId, 43113);
  assert.equal(live.noteTree, "poseidon2");
  assert.equal(live.addresses.HazePool, "0x00BEB0A5D709d0F093952fD374Dbbf3d0d21d550");
  assert.equal(live.addresses.HazePoolPoseidon, "0x00BEB0A5D709d0F093952fD374Dbbf3d0d21d550");
  assert.equal(
    live.membershipRoot,
    "0x15d312c3937a289d3fd541c50355ac3a2122c88498db924c011ac0a619f352c4",
  );
  assert.equal(
    live.hazeBlocklistRoot,
    "0x2f9120bf4979f6f079577e2eaeb96fd996129dbd24a0855fbd0fe7e30669716d",
  );
  assert.equal(isPlaceholderPolicyRoot(live.membershipRoot), false);
  assert.equal(isPlaceholderPolicyRoot(live.hazeBlocklistRoot), false);
  assert.equal(isPlaceholderPolicyRoot("0x11"), true);
  assert.equal(isPlaceholderPolicyRoot("0x44"), true);
  const previous = live.transactions.previous ?? {};
  const older = live.transactions.previousTransactions?.previous ?? {};
  assert.equal(older.HazePool ?? previous.HazePool, "0x97bB30637DD7A71997F905Cd142cF89d2887ADb8");
  assert.notEqual(live.addresses.HazePool, "0x97bB30637DD7A71997F905Cd142cF89d2887ADb8");
});

test("circuit-valid live deposit planner refuses the keccak pool", () => {
  assert.throws(() => planLiveCircuitDeposit(), (error) => {
    assert.equal(error.code, "NOTE_TREE_MISMATCH");
    return true;
  });
});

test("circuit-valid live deposit planner refuses placeholder policy roots on a Poseidon pool", () => {
  const poseidonPool = [
    "contract HazePoolPoseidon {",
    "    // haze/avalanche/v1/note-tree-node",
    "    function _hashPair(uint256 left, uint256 right) internal pure returns (uint256) {",
    "        return poseidon2(left, right);",
    "    }",
    "}",
  ].join("\n");
  assert.throws(
    () =>
      planLiveCircuitDeposit({
        poolSource: poseidonPool,
        membershipRoot: "0x11",
        hazeBlocklistRoot: "0x44",
      }),
    (error) => {
      assert.equal(error.code, "POLICY_INVALID");
      return true;
    },
  );
});

test("circuit-valid live deposit planner refuses production flips and rehearsal zkeys", () => {
  const poseidonPool = "haze/avalanche/v1/note-tree-node poseidon2";
  const realRoots = {
    poolSource: poseidonPool,
    membershipRoot: `0x${"ab".repeat(32)}`,
    hazeBlocklistRoot: `0x${"cd".repeat(32)}`,
  };
  assert.throws(() => planLiveCircuitDeposit({ ...realRoots, spendProve: "production" }), (error) => {
    assert.equal(error.code, "KEYS_MISSING");
    return true;
  });
  assert.throws(
    () => planLiveCircuitDeposit({ ...realRoots, productionCeremonyApproved: true }),
    (error) => {
      assert.equal(error.code, "KEYS_MISSING");
      return true;
    },
  );
  assert.throws(
    () => planLiveCircuitDeposit({ ...realRoots, zkeyPath: "/tmp/rehearsal-ceremony.zkey" }),
    (error) => {
      assert.equal(error.code, "ARTIFACT_INVALID");
      return true;
    },
  );
  assert.throws(() => planLiveCircuitDeposit({ ...realRoots, flipFujiBroadcast: true }), (error) => {
    assert.equal(error.code, "SC-09");
    return true;
  });
  const plan = planLiveCircuitDeposit(realRoots);
  assert.equal(plan.noteTree, "poseidon2");
  assert.equal(plan.action, 1);
  assert.equal(plan.chainId, 43113);
  assert.equal(plan.spendProve, "KEYS_MISSING");
  assert.equal(plan.broadcast, false);
  assert.equal(plan.notForProduction, true);
  const fuji = assertCommittedFujiUntouched(FUJI);
  assert.equal(fuji.broadcast, false);
  assert.equal(fuji.spend_prove, "KEYS_MISSING");
});
