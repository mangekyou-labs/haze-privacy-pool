//! Application, policy, and version registry encodings.

/// Application status matching `ApplicationRegistry.Status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ApplicationStatus {
    /// No record.
    Unspecified = 0,
    /// Scheduled, waiting for the timelock.
    Pending = 1,
    /// Live for normal pool actions.
    Active = 2,
    /// Blocked from membership updates; notes remain user-owned.
    Suspended = 3,
    /// Terminal status.
    Retired = 4,
}

/// Haze global policy status matching `PolicyRegistry.Status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PolicyStatus {
    /// No record.
    Unspecified = 0,
    /// Scheduled, waiting for the timelock.
    Scheduled = 1,
    /// The only accepted root at execution.
    Active = 2,
    /// Replaced; stale proofs fail closed.
    Retired = 3,
}

/// Release status matching `VersionRegistry.Status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReleaseStatus {
    /// No record.
    Unspecified = 0,
    /// Scheduled, waiting for the timelock.
    Scheduled = 1,
    /// Published metadata and artifact hash.
    Active = 2,
    /// Replaced publication; does not upgrade bytecode.
    Retired = 3,
}

/// Accept only the currently active Haze policy version and root.
///
/// There is no post-activation grace period.
#[must_use]
pub fn policy_is_live(
    active_version: u64,
    active_root: [u8; 32],
    version: u64,
    root: [u8; 32],
) -> bool {
    active_version != 0 && version == active_version && root == active_root
}

/// Accept only the currently active published release tag and artifact hash.
#[must_use]
pub fn release_is_live(
    active_tag: [u8; 32],
    active_artifact: [u8; 32],
    tag: [u8; 32],
    artifact: [u8; 32],
) -> bool {
    active_tag != [0u8; 32] && tag == active_tag && artifact == active_artifact
}

#[cfg(test)]
mod tests {
    use super::{ApplicationStatus, PolicyStatus, policy_is_live, release_is_live};

    #[test]
    fn status_discriminants_match_solidity_enums() {
        assert_eq!(ApplicationStatus::Pending as u8, 1);
        assert_eq!(ApplicationStatus::Active as u8, 2);
        assert_eq!(ApplicationStatus::Suspended as u8, 3);
        assert_eq!(ApplicationStatus::Retired as u8, 4);
        assert_eq!(PolicyStatus::Scheduled as u8, 1);
        assert_eq!(PolicyStatus::Active as u8, 2);
        assert_eq!(PolicyStatus::Retired as u8, 3);
    }

    #[test]
    fn policy_freshness_has_no_grace_period() {
        let root = [0x44; 32];
        let next = [0xab; 32];
        assert!(!policy_is_live(0, root, 1, root));
        assert!(policy_is_live(1, root, 1, root));
        assert!(!policy_is_live(1, root, 1, next));
        assert!(!policy_is_live(1, root, 2, root));
        assert!(!policy_is_live(2, next, 1, root));
    }

    #[test]
    fn release_publication_is_hash_exact() {
        let tag = [0x66; 32];
        let artifact = [0x77; 32];
        assert!(release_is_live(tag, artifact, tag, artifact));
        assert!(!release_is_live(tag, artifact, tag, [0x00; 32]));
        assert!(!release_is_live([0u8; 32], artifact, tag, artifact));
    }
}
