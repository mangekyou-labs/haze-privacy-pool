/** Pool authorization domain name matching `HazePool`. */
export const POOL_DOMAIN_NAME = "Haze Avalanche Compliant Pool" as const;

/** Pool authorization domain version matching `HazePool`. */
export const POOL_DOMAIN_VERSION = "1" as const;

/** v1 action codes accepted by the pool (emergency exit is rejected here). */
export const PoolAction = {
  Deposit: 1,
  Transfer: 2,
  Withdraw: 3,
  SwapAndShield: 4,
  EmergencyExit: 5,
} as const;

export type PoolAction = (typeof PoolAction)[keyof typeof PoolAction];

/** Direct `deposit` / `transact` actions. Router deposit is action 4. */
export function isDirectPoolAction(action: number): boolean {
  return action === PoolAction.Deposit || action === PoolAction.Transfer || action === PoolAction.Withdraw;
}

/** Reject emergency-exit on the normal pool paths. */
export function isNormalPoolAction(action: number): boolean {
  return action >= PoolAction.Deposit && action <= PoolAction.SwapAndShield;
}
