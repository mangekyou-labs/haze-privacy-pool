/** Application status matching `ApplicationRegistry.Status`. */
export const ApplicationStatus = {
  Unspecified: 0,
  Pending: 1,
  Active: 2,
  Suspended: 3,
  Retired: 4,
} as const;

/** Haze global policy status matching `PolicyRegistry.Status`. */
export const PolicyStatus = {
  Unspecified: 0,
  Scheduled: 1,
  Active: 2,
  Retired: 3,
} as const;

/** Release status matching `VersionRegistry.Status`. */
export const ReleaseStatus = {
  Unspecified: 0,
  Scheduled: 1,
  Active: 2,
  Retired: 3,
} as const;

/** Accept only the currently active Haze policy version and root. */
export function policyIsLive(
  activeVersion: bigint | number,
  activeRoot: string,
  version: bigint | number,
  root: string,
): boolean {
  return (
    BigInt(activeVersion) !== 0n &&
    BigInt(version) === BigInt(activeVersion) &&
    root.toLowerCase() === activeRoot.toLowerCase()
  );
}

/** Unpublished local versions and the active release remain exit-capable. */
export function releaseIsExitCapable(
  status: number,
  now: number | bigint,
  supportUntil: number | bigint,
): boolean {
  if (status === ReleaseStatus.Unspecified || status === ReleaseStatus.Active) {
    return true;
  }
  if (status === ReleaseStatus.Scheduled) {
    return false;
  }
  return BigInt(now) <= BigInt(supportUntil);
}

/** Accept only the currently active published release tag and artifact hash. */
export function releaseIsLive(
  activeTag: string,
  activeArtifact: string,
  tag: string,
  artifact: string,
): boolean {
  const zero = `0x${"00".repeat(32)}`;
  return (
    activeTag.toLowerCase() !== zero &&
    tag.toLowerCase() === activeTag.toLowerCase() &&
    artifact.toLowerCase() === activeArtifact.toLowerCase()
  );
}
