//! EIP-712 domains, intent hashes, and authorizations.

use crate::{
    abi::{address_word, bytes32_word, keccak_abi_encode, uint_word},
    action::{DEPOSIT, SWAP_AND_SHIELD, parse_action},
    error::{ProtocolError, Result},
    keccak::keccak256,
};

/// Inclusive maximum for EIP-712 `uint48` fields.
pub const UINT48_MAX: u64 = (1 << 48) - 1;

/// Pool authorization domain name.
pub const POOL_DOMAIN_NAME: &str = "Haze Avalanche Compliant Pool";
/// Pool authorization domain version.
pub const POOL_DOMAIN_VERSION: &str = "1";
/// Shielded-account derivation domain name.
pub const KEY_DOMAIN_NAME: &str = "Haze Shielded Account";
/// Shielded-account derivation domain version.
pub const KEY_DOMAIN_VERSION: &str = "1";

/// Reject an integer that cannot be encoded as Solidity `uint48`.
pub fn require_uint48(value: u64) -> Result<()> {
    if value > UINT48_MAX {
        Err(ProtocolError::FieldOutOfRange)
    } else {
        Ok(())
    }
}

/// Reject an EIP-712 domain name that is not the frozen pool name.
pub fn require_pool_domain_name(name: &str) -> Result<()> {
    if name == POOL_DOMAIN_NAME {
        Ok(())
    } else {
        Err(ProtocolError::DomainMismatch)
    }
}

const EIP712_DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const INTENT_TYPE: &str = "HazeIntent(bytes32 applicationId,address user,address pool,bytes32 poolVersion,uint8 action,uint256 noteTreeRoot,uint64 applicationPolicyVersion,uint64 hazePolicyVersion,uint256 applicationMembershipRoot,uint256 hazeBlocklistRoot,uint256 inputNullifier0,uint256 inputNullifier1,uint256 outputCommitment0,uint256 outputCommitment1,uint64 publicAmount,address publicRecipient,bytes32 recipientCiphertextHash0,bytes32 recipientCiphertextHash1,uint256 auditDataCommitment,bytes32 auditCiphertextHash,address tokenIn,uint256 amountIn,uint64 minUsdcOut,bytes32 routeHash,uint48 deadline)";
const AUTH_TYPE: &str = "ApplicationAuthorization(bytes32 applicationId,address user,address pool,bytes32 poolVersion,uint8 action,bytes32 intentHash,uint64 applicationPolicyVersion,uint64 hazePolicyVersion,uint256 auditDataCommitment,bytes32 auditCiphertextHash,bytes32 nonce,uint48 validAfter,uint48 validUntil)";
const KEY_TYPE: &str =
    "HazeKeyDerivation(address wallet,bytes32 applicationId,bytes32 poolVersion)";

/// Type hash for the EIP-712 domain.
pub fn eip712_domain_type_hash() -> [u8; 32] {
    keccak256(EIP712_DOMAIN_TYPE.as_bytes())
}

/// Type hash for `HazeIntent`.
pub fn intent_type_hash() -> [u8; 32] {
    keccak256(INTENT_TYPE.as_bytes())
}

/// Type hash for `ApplicationAuthorization`.
pub fn authorization_type_hash() -> [u8; 32] {
    keccak256(AUTH_TYPE.as_bytes())
}

/// Type hash for shielded-key derivation.
pub fn key_derivation_type_hash() -> [u8; 32] {
    keccak256(KEY_TYPE.as_bytes())
}

/// EIP-712 domain separator.
pub fn domain_separator(
    name: &str,
    version: &str,
    chain_id: u64,
    verifying_contract: [u8; 20],
) -> [u8; 32] {
    keccak_abi_encode(&[
        eip712_domain_type_hash(),
        keccak256(name.as_bytes()),
        keccak256(version.as_bytes()),
        uint_word(u128::from(chain_id)),
        address_word(verifying_contract),
    ])
}

/// Public fields hashed into a Haze intent.
#[derive(Clone, Debug)]
pub struct HazeIntent {
    /// Application identifier.
    pub application_id: [u8; 32],
    /// Authorized user.
    pub user: [u8; 20],
    /// Pool contract.
    pub pool: [u8; 20],
    /// Immutable pool version.
    pub pool_version: [u8; 32],
    /// Action code.
    pub action: u8,
    /// Note-tree root, or zero for deposits.
    pub note_tree_root: [u8; 32],
    /// Application policy version.
    pub application_policy_version: u64,
    /// Haze policy version.
    pub haze_policy_version: u64,
    /// Application membership root.
    pub application_membership_root: [u8; 32],
    /// Haze blocklist root.
    pub haze_blocklist_root: [u8; 32],
    /// First input nullifier.
    pub input_nullifier_0: [u8; 32],
    /// Second input nullifier.
    pub input_nullifier_1: [u8; 32],
    /// First output commitment.
    pub output_commitment_0: [u8; 32],
    /// Second output commitment.
    pub output_commitment_1: [u8; 32],
    /// Public USDC amount.
    pub public_amount: u64,
    /// Public recipient, or zero.
    pub public_recipient: [u8; 20],
    /// First recipient envelope hash.
    pub recipient_ciphertext_hash_0: [u8; 32],
    /// Second recipient envelope hash.
    pub recipient_ciphertext_hash_1: [u8; 32],
    /// Circuit-bound audit commitment.
    pub audit_data_commitment: [u8; 32],
    /// Audit envelope hash.
    pub audit_ciphertext_hash: [u8; 32],
    /// Swap source token, or zero.
    pub token_in: [u8; 20],
    /// Swap input amount, or zero.
    pub amount_in: [u8; 32],
    /// Swap minimum USDC output, or zero.
    pub min_usdc_out: u64,
    /// Swap route hash, or zero.
    pub route_hash: [u8; 32],
    /// Swap deadline, or zero.
    pub deadline: u64,
}

impl HazeIntent {
    /// Reject unknown actions, out-of-range `uint48`s, and swap fields on
    /// non-swap actions.
    pub fn validate(&self) -> Result<()> {
        parse_action(self.action)?;
        require_uint48(self.deadline)?;
        if self.action != SWAP_AND_SHIELD {
            let swap_zero = self.token_in == [0u8; 20]
                && self.amount_in == [0u8; 32]
                && self.min_usdc_out == 0
                && self.route_hash == [0u8; 32]
                && self.deadline == 0;
            if !swap_zero {
                return Err(ProtocolError::EncodingInvalid);
            }
        }
        if self.action == DEPOSIT {
            let deposit_zero = self.note_tree_root == [0u8; 32]
                && self.input_nullifier_0 == [0u8; 32]
                && self.input_nullifier_1 == [0u8; 32];
            if !deposit_zero {
                return Err(ProtocolError::EncodingInvalid);
            }
        }
        Ok(())
    }

    /// EIP-712 struct hash.
    pub fn struct_hash(&self) -> Result<[u8; 32]> {
        self.validate()?;
        Ok(keccak_abi_encode(&[
            intent_type_hash(),
            bytes32_word(self.application_id),
            address_word(self.user),
            address_word(self.pool),
            bytes32_word(self.pool_version),
            uint_word(u128::from(self.action)),
            bytes32_word(self.note_tree_root),
            uint_word(u128::from(self.application_policy_version)),
            uint_word(u128::from(self.haze_policy_version)),
            bytes32_word(self.application_membership_root),
            bytes32_word(self.haze_blocklist_root),
            bytes32_word(self.input_nullifier_0),
            bytes32_word(self.input_nullifier_1),
            bytes32_word(self.output_commitment_0),
            bytes32_word(self.output_commitment_1),
            uint_word(u128::from(self.public_amount)),
            address_word(self.public_recipient),
            bytes32_word(self.recipient_ciphertext_hash_0),
            bytes32_word(self.recipient_ciphertext_hash_1),
            bytes32_word(self.audit_data_commitment),
            bytes32_word(self.audit_ciphertext_hash),
            address_word(self.token_in),
            bytes32_word(self.amount_in),
            uint_word(u128::from(self.min_usdc_out)),
            bytes32_word(self.route_hash),
            uint_word(u128::from(self.deadline)),
        ]))
    }

    /// Final EIP-712 digest for the pool domain.
    pub fn digest(&self, chain_id: u64) -> Result<[u8; 32]> {
        Ok(typed_data_digest(
            domain_separator(POOL_DOMAIN_NAME, POOL_DOMAIN_VERSION, chain_id, self.pool),
            self.struct_hash()?,
        ))
    }
}

/// Gatekeeper authorization payload.
#[derive(Clone, Debug)]
pub struct ApplicationAuthorization {
    /// Application identifier.
    pub application_id: [u8; 32],
    /// Authorized user.
    pub user: [u8; 20],
    /// Pool contract.
    pub pool: [u8; 20],
    /// Immutable pool version.
    pub pool_version: [u8; 32],
    /// Action code.
    pub action: u8,
    /// Intent struct hash.
    pub intent_hash: [u8; 32],
    /// Application policy version.
    pub application_policy_version: u64,
    /// Haze policy version.
    pub haze_policy_version: u64,
    /// Audit-data commitment.
    pub audit_data_commitment: [u8; 32],
    /// Audit envelope hash.
    pub audit_ciphertext_hash: [u8; 32],
    /// Authorization nonce.
    pub nonce: [u8; 32],
    /// Inclusive validity start.
    pub valid_after: u64,
    /// Inclusive validity end.
    pub valid_until: u64,
}

impl ApplicationAuthorization {
    /// Reject unknown actions and out-of-range `uint48` windows.
    pub fn validate(&self) -> Result<()> {
        parse_action(self.action)?;
        require_uint48(self.valid_after)?;
        require_uint48(self.valid_until)
    }

    /// EIP-712 struct hash.
    pub fn struct_hash(&self) -> Result<[u8; 32]> {
        self.validate()?;
        Ok(keccak_abi_encode(&[
            authorization_type_hash(),
            bytes32_word(self.application_id),
            address_word(self.user),
            address_word(self.pool),
            bytes32_word(self.pool_version),
            uint_word(u128::from(self.action)),
            bytes32_word(self.intent_hash),
            uint_word(u128::from(self.application_policy_version)),
            uint_word(u128::from(self.haze_policy_version)),
            bytes32_word(self.audit_data_commitment),
            bytes32_word(self.audit_ciphertext_hash),
            bytes32_word(self.nonce),
            uint_word(u128::from(self.valid_after)),
            uint_word(u128::from(self.valid_until)),
        ]))
    }

    /// Final EIP-712 digest for the pool domain.
    pub fn digest(&self, chain_id: u64) -> Result<[u8; 32]> {
        Ok(typed_data_digest(
            domain_separator(POOL_DOMAIN_NAME, POOL_DOMAIN_VERSION, chain_id, self.pool),
            self.struct_hash()?,
        ))
    }
}

/// `keccak256("\x19\x01" || domainSeparator || structHash)`.
pub fn typed_data_digest(domain_separator: [u8; 32], struct_hash: [u8; 32]) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(66);
    encoded.extend_from_slice(&[0x19, 0x01]);
    encoded.extend_from_slice(&domain_separator);
    encoded.extend_from_slice(&struct_hash);
    keccak256(&encoded)
}

/// Shielded-account derivation struct hash.
pub fn key_derivation_struct_hash(
    wallet: [u8; 20],
    application_id: [u8; 32],
    pool_version: [u8; 32],
) -> [u8; 32] {
    keccak_abi_encode(&[
        key_derivation_type_hash(),
        address_word(wallet),
        bytes32_word(application_id),
        bytes32_word(pool_version),
    ])
}
