import { functionSelector } from "./abi.ts";
import type { EvmTransport } from "./transport.ts";

export { functionSelector };

const TRANSACT_ARGS =
  "((bytes32,address,address,bytes32,uint8,uint256,uint64,uint64,uint256,uint256,uint256,uint256,uint256,uint256,uint64,address,bytes32,bytes32,uint256,bytes32,address,uint256,uint64,bytes32,uint48),(bytes32,address,address,bytes32,uint8,bytes32,uint64,uint64,uint256,bytes32,bytes32,uint48,uint48),bytes,bytes,bytes,bytes,bytes)";

/** Selectors for `HazePool` entrypoints used by the SDK. */
export const POOL_SELECTORS = {
  deposit: functionSelector(`deposit(${TRANSACT_ARGS})`),
  transact: functionSelector(`transact(${TRANSACT_ARGS})`),
  depositFromRouter: functionSelector(`depositFromRouter(address,${TRANSACT_ARGS})`),
  poolVersion: functionSelector("poolVersion()"),
  spendArtifactHash: functionSelector("SPEND_ARTIFACT_HASH()"),
} as const;

/** Selectors for `SwapAndShieldRouter`. */
export const ROUTER_SELECTORS = {
  swapAndShield: functionSelector(`swapAndShield(${TRANSACT_ARGS},(address,bytes,bytes32))`),
} as const;

/** Selectors for `EmergencyExit`. */
export const EMERGENCY_SELECTORS = {
  requestEmergencyExit: functionSelector("requestEmergencyExit(bytes32)"),
  executeEmergencyExit: functionSelector(
    "executeEmergencyExit((bytes32,uint256,uint64,uint256,uint256,uint64,address,address,bytes32,uint256,bytes32,bytes,bytes))",
  ),
} as const;

/** Read-only pool binding over a provider-neutral transport. */
export function bindHazePool(transport: EvmTransport, address: string) {
  return {
    address,
    async poolVersion() {
      return transport.call({ to: address, data: POOL_SELECTORS.poolVersion });
    },
    async spendArtifactHash() {
      return transport.call({ to: address, data: POOL_SELECTORS.spendArtifactHash });
    },
    encodeView(signature: string) {
      return functionSelector(signature);
    },
  };
}
