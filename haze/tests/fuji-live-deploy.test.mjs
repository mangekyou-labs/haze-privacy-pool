import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { fujiGate } from "../dev/host.mjs";
import {
  computeCreateAddress,
  parseBroadcastDeposit,
  planLiveFujiDeploy,
  planLiveFujiDeposit,
  planLiveFujiPairingDeploy,
  planLiveFujiPoseidonDeploy,
  recordLiveDeposit,
  writeLiveOverlay,
} from "../dev/fuji-live-deploy.mjs";
import {
  BLOCKLIST_SENTINEL_ROOT,
  buildLiveDepositWitness,
} from "../dev/operator-circuit-witness.mjs";

const HAZE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const FUJI_PACKAGE = join(HAZE_ROOT, "deployments/fuji-v1.json");
const MAINNET_PACKAGE = join(HAZE_ROOT, "deployments/mainnet-v1.json");
const USDC = "0x5425890298aed601595a70AB815c96711a31Bc65";

test("computeCreateAddress matches the canonical Ethereum CREATE vectors", () => {
  const deployer = "0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0";
  assert.equal(
    computeCreateAddress(deployer, 0),
    "0xcd234a471b72ba2f1ccf0a70fcaba648a5eecd8d",
  );
  assert.equal(
    computeCreateAddress(deployer, 1),
    "0x343c43a37d37dff08ae8c4a11544c718abb4fcf8",
  );
});

test("live Fuji plan uses Circle USDC, development prove, and predicted router/exit", () => {
  const plan = planLiveFujiDeploy({
    deployer: "0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0",
    nonce: 10,
  });
  assert.equal(plan.chainId, 43113);
  assert.equal(plan.usdc.toLowerCase(), USDC.toLowerCase());
  assert.equal(plan.notForProduction, true);
  assert.equal(plan.spendProve, "KEYS_MISSING");
  assert.equal(plan.prove, "development-equality");
  assert.equal(plan.minDelaySeconds, 1);
  assert.equal(plan.publicRpc, "https://api.avax-test.network/ext/bc/C/rpc");
  assert.equal(plan.predicted.pool, computeCreateAddress(plan.deployer, 10 + 6));
  assert.equal(plan.predicted.router, computeCreateAddress(plan.deployer, 10 + 7));
  assert.equal(plan.predicted.exit, computeCreateAddress(plan.deployer, 10 + 8));
  assert.deepEqual(
    plan.creates.map((item) => item.name),
    [
      "HazeAccess",
      "ApplicationRegistry",
      "PolicyRegistry",
      "VersionRegistry",
      "DevelopmentEqualityVerifier",
      "HazeSpendVerifier",
      "HazePool",
      "SwapAndShieldRouter",
      "EmergencyExit",
    ],
  );
});

test("live Fuji plan refuses production keys and T7.5 flips", () => {
  assert.throws(() => planLiveFujiDeploy({ inventProductionKeys: true }), (error) => {
    assert.equal(error.code, "KEYS_MISSING");
    return true;
  });
  assert.throws(() => planLiveFujiDeploy({ spendProve: "production" }), (error) => {
    assert.equal(error.code, "KEYS_MISSING");
    return true;
  });
  assert.throws(() => planLiveFujiDeploy({ flipFujiBroadcast: true }), (error) => {
    assert.equal(error.code, "SC-09");
    return true;
  });
  assert.throws(() => planLiveFujiDeploy({ mainnetAuthorized: true }), (error) => {
    assert.equal(error.code, "SC-09");
    return true;
  });
});

test("live overlay writes addresses without flipping committed Fuji or mainnet packages", () => {
  const beforeFuji = readFileSync(FUJI_PACKAGE, "utf8");
  const beforeMainnet = readFileSync(MAINNET_PACKAGE, "utf8");
  const dir = mkdtempSync(join(tmpdir(), "haze-fuji-live-"));
  const overlayPath = join(dir, "fuji-v1.live.json");
  try {
    const overlay = writeLiveOverlay({
      overlayPath,
      addresses: {
        HazePool: "0x1111111111111111111111111111111111111111",
        HazeSpendVerifier: "0x2222222222222222222222222222222222222222",
        SwapAndShieldRouter: "0x3333333333333333333333333333333333333333",
        EmergencyExit: "0x4444444444444444444444444444444444444444",
        HazeAccess: "0x5555555555555555555555555555555555555555",
        ApplicationRegistry: "0x6666666666666666666666666666666666666666",
        PolicyRegistry: "0x7777777777777777777777777777777777777777",
        VersionRegistry: "0x8888888888888888888888888888888888888888",
      },
      transactions: { deploy: `0x${"ab".repeat(32)}` },
    });
    assert.equal(overlay.broadcast, true);
    assert.equal(overlay.spend_prove, "KEYS_MISSING");
    assert.equal(overlay.prove, "development-equality");
    assert.equal(overlay.chainId, 43113);
    assert.equal(overlay.addresses.HazePool, "0x1111111111111111111111111111111111111111");
    assert.equal(existsSync(overlayPath), true);
    assert.equal(readFileSync(FUJI_PACKAGE, "utf8"), beforeFuji);
    assert.equal(readFileSync(MAINNET_PACKAGE, "utf8"), beforeMainnet);
    const fuji = JSON.parse(beforeFuji);
    const mainnet = JSON.parse(beforeMainnet);
    assert.equal(fuji.broadcast, false);
    assert.equal(fuji.spend_prove, "KEYS_MISSING");
    assert.equal(mainnet.broadcast, false);
    assert.notEqual(mainnet.authorized, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("committed fujiGate stays fail-closed after the live planner exists", () => {
  const gate = fujiGate();
  assert.equal(gate.ready, false);
  assert.ok(gate.reasons.includes("broadcast:false"));
  assert.ok(gate.reasons.includes("KEYS_MISSING"));
});

test("pairing Fuji plan is operator-owned Groth16 and does not flip production or fuji-v1", () => {
  const plan = planLiveFujiPairingDeploy({
    deployer: "0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0",
    nonce: 20,
  });
  assert.equal(plan.chainId, 43113);
  assert.equal(plan.notForProduction, true);
  assert.equal(plan.productionCeremonyApproved, false);
  assert.equal(plan.spendProve, "KEYS_MISSING");
  assert.equal(plan.prove, "operator-owned-groth16");
  assert.deepEqual(
    plan.creates.map((item) => item.name),
    [
      "HazeAccess",
      "ApplicationRegistry",
      "PolicyRegistry",
      "VersionRegistry",
      "DevelopmentEqualityVerifier",
      "Groth16Verifier",
      "HazeOperatorGroth16Adapter",
      "HazeSpendVerifierPairing",
      "HazePool",
      "SwapAndShieldRouter",
      "EmergencyExit",
    ],
  );
  assert.equal(plan.predicted.pool, computeCreateAddress(plan.deployer, 20 + 8));
  assert.throws(() => planLiveFujiPairingDeploy({ spendProve: "production" }), (error) => {
    assert.equal(error.code, "KEYS_MISSING");
    return true;
  });
  const fuji = JSON.parse(readFileSync(FUJI_PACKAGE, "utf8"));
  assert.equal(fuji.broadcast, false);
  assert.equal(fuji.spend_prove, "KEYS_MISSING");
});

test("Poseidon Fuji plan uses the pairing set, real policy roots, and does not flip fuji-v1", () => {
  const plan = planLiveFujiPoseidonDeploy({
    deployer: "0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0",
    nonce: 20,
  });
  const witness = buildLiveDepositWitness({
    pool: "0x3333333333333333333333333333333333333333",
    user: "0xeD37fd0d6f0f69236e7472b36796e133d20ecc32",
    applicationId: "0x0000000000000000000000000000000000000000000000000000000000000a11",
    poolVersion: "0x000000000000000000000000000000000000000000000000000000000000b001",
  });
  assert.equal(plan.chainId, 43113);
  assert.equal(plan.noteTree, "poseidon2");
  assert.equal(plan.prove, "operator-owned-groth16");
  assert.equal(plan.spendProve, "KEYS_MISSING");
  assert.equal(plan.notForProduction, true);
  assert.equal(plan.hazeBlocklistRoot, BLOCKLIST_SENTINEL_ROOT);
  assert.equal(plan.membershipRoot, witness.membershipRoot);
  assert.equal(plan.creates.at(-3).name, "HazePoolPoseidon");
  assert.equal(plan.predicted.pool, computeCreateAddress(plan.deployer, 20 + 8));
  assert.throws(() => planLiveFujiPoseidonDeploy({ spendProve: "production" }), (error) => {
    assert.equal(error.code, "KEYS_MISSING");
    return true;
  });
  const fuji = JSON.parse(readFileSync(FUJI_PACKAGE, "utf8"));
  assert.equal(fuji.broadcast, false);
  assert.equal(fuji.spend_prove, "KEYS_MISSING");
});

test("Foundry live scripts pin Fuji and keep production keys missing", () => {
  const deploy = readFileSync(join(HAZE_ROOT, "contracts/script/DeployFujiLive.s.sol"), "utf8");
  const pairing = readFileSync(join(HAZE_ROOT, "contracts/script/DeployFujiPairingLive.s.sol"), "utf8");
  const activate = readFileSync(join(HAZE_ROOT, "contracts/script/ActivateFujiLive.s.sol"), "utf8");
  assert.match(deploy, /block\.chainid == 43113/);
  assert.match(deploy, /0x5425890298aed601595a70AB815c96711a31Bc65/);
  assert.doesNotMatch(deploy, /43114/);
  assert.match(pairing, /block\.chainid == 43113/);
  assert.match(pairing, /HazeSpendVerifierPairing/);
  assert.match(pairing, /Groth16Verifier/);
  assert.doesNotMatch(pairing, /43114/);
  assert.match(activate, /block\.chainid == 43113/);
  const verify = readFileSync(join(HAZE_ROOT, "contracts/script/VerifyFujiPairingLive.s.sol"), "utf8");
  assert.match(verify, /block\.chainid == 43113/);
  assert.match(verify, /HazeOperatorPairingReceipt/);
  assert.match(verify, /production/);
  assert.doesNotMatch(verify, /43114/);
  const poseidon = readFileSync(join(HAZE_ROOT, "contracts/script/DeployFujiPoseidonLive.s.sol"), "utf8");
  assert.match(poseidon, /block\.chainid == 43113/);
  assert.match(poseidon, /HazePoolPoseidon/);
  assert.match(poseidon, /HazeSpendVerifierPairing/);
  assert.match(poseidon, /0x2f9120bf4979f6f079577e2eaeb96fd996129dbd24a0855fbd0fe7e30669716d/i);
  assert.match(poseidon, /0x15d312c3937a289d3fd541c50355ac3a2122c88498db924c011ac0a619f352c4/i);
  assert.doesNotMatch(poseidon, /MEMBER_ROOT = bytes32\(uint256\(0x11\)\)/);
  assert.doesNotMatch(poseidon, /43114/);
});

test("live Fuji deposit plan uses 1 USDC, development digest, and the sidecar pool", () => {
  const plan = planLiveFujiDeposit({
    pool: "0x919b338f189B1e564Af34A26fC002138f308f7dE",
  });
  assert.equal(plan.chainId, 43113);
  assert.equal(plan.usdc.toLowerCase(), USDC.toLowerCase());
  assert.equal(plan.amount, 1_000_000);
  assert.equal(plan.action, 1);
  assert.equal(plan.prove, "development-equality");
  assert.equal(plan.spendProve, "KEYS_MISSING");
  assert.equal(plan.notForProduction, true);
  assert.equal(plan.pool, "0x919b338f189B1e564Af34A26fC002138f308f7dE");
  assert.equal(
    plan.applicationId,
    "0x0000000000000000000000000000000000000000000000000000000000000a11",
  );
  assert.equal(plan.membershipVersion, 1);
  assert.equal(plan.hazePolicyVersion, 1);
});

test("live Fuji deposit plan refuses production keys and T7.5 flips", () => {
  assert.throws(() => planLiveFujiDeposit({ inventProductionKeys: true }), (error) => {
    assert.equal(error.code, "KEYS_MISSING");
    return true;
  });
  assert.throws(() => planLiveFujiDeposit({ spendProve: "production" }), (error) => {
    assert.equal(error.code, "KEYS_MISSING");
    return true;
  });
  assert.throws(() => planLiveFujiDeposit({ flipFujiBroadcast: true }), (error) => {
    assert.equal(error.code, "SC-09");
    return true;
  });
  assert.throws(() => planLiveFujiDeposit({ mainnetAuthorized: true }), (error) => {
    assert.equal(error.code, "SC-09");
    return true;
  });
});

test("recording a live deposit does not flip committed Fuji or mainnet packages", () => {
  const beforeFuji = readFileSync(FUJI_PACKAGE, "utf8");
  const beforeMainnet = readFileSync(MAINNET_PACKAGE, "utf8");
  const dir = mkdtempSync(join(tmpdir(), "haze-fuji-deposit-"));
  const overlayPath = join(dir, "fuji-v1.live.json");
  try {
    writeLiveOverlay({
      overlayPath,
      addresses: {
        HazePool: "0x919b338f189B1e564Af34A26fC002138f308f7dE",
        HazeSpendVerifier: "0x2222222222222222222222222222222222222222",
        SwapAndShieldRouter: "0x3333333333333333333333333333333333333333",
        EmergencyExit: "0x4444444444444444444444444444444444444444",
        HazeAccess: "0x5555555555555555555555555555555555555555",
        ApplicationRegistry: "0x6666666666666666666666666666666666666666",
        PolicyRegistry: "0x7777777777777777777777777777777777777777",
        VersionRegistry: "0x8888888888888888888888888888888888888888",
      },
      transactions: { HazePool: `0x${"ab".repeat(32)}` },
    });
    const overlay = recordLiveDeposit({
      overlayPath,
      depositTx: `0x${"cd".repeat(32)}`,
      approveTx: `0x${"ef".repeat(32)}`,
      amount: 1_000_000,
    });
    assert.equal(overlay.broadcast, true);
    assert.equal(overlay.spend_prove, "KEYS_MISSING");
    assert.equal(overlay.transactions.deposit, `0x${"cd".repeat(32)}`);
    assert.equal(overlay.transactions.approve, `0x${"ef".repeat(32)}`);
    assert.equal(overlay.transactions.depositAmount, 1_000_000);
    assert.equal(readFileSync(FUJI_PACKAGE, "utf8"), beforeFuji);
    assert.equal(readFileSync(MAINNET_PACKAGE, "utf8"), beforeMainnet);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("broadcast parser reads approve and deposit hashes from Foundry run-latest JSON", () => {
  const parsed = parseBroadcastDeposit({
    transactions: [
      { hash: `0x${"11".repeat(32)}`, function: "approve(address,uint256)" },
      { hash: `0x${"22".repeat(32)}`, function: "deposit(((bytes32,address)))" },
    ],
  });
  assert.equal(parsed.approveTx, `0x${"11".repeat(32)}`);
  assert.equal(parsed.depositTx, `0x${"22".repeat(32)}`);
});

test("Foundry deposit script pins Fuji Circle USDC and a development digest deposit", () => {
  const deposit = readFileSync(join(HAZE_ROOT, "contracts/script/DepositFujiLive.s.sol"), "utf8");
  assert.match(deposit, /block\.chainid == 43113/);
  assert.match(deposit, /0x5425890298aed601595a70AB815c96711a31Bc65/);
  assert.match(deposit, /pool\.deposit/);
  assert.match(deposit, /approve/);
  assert.match(deposit, /keccak256\(abi\.encodePacked\(pool\.publicInputs/);
  assert.doesNotMatch(deposit, /43114/);
  assert.doesNotMatch(deposit, /KEYS_MISSING/);
});
