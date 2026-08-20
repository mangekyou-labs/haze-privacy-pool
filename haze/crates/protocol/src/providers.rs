//! Provider-neutral integration interfaces.
//!
//! Concrete vendor SDKs stay behind adapters. Public Haze types name
//! capabilities, not vendors.

/// Fail-closed provider error family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    /// The dependency is down, timed out, or otherwise unreachable.
    Unavailable,
    /// The dependency answered but refused the request.
    Rejected,
    /// A quote expired or no longer satisfies the caller bounds.
    QuoteStale,
    /// The backend is bound to a different EVM chain.
    ChainMismatch,
}

/// Result of a provider call.
pub type ProviderResult<T> = core::result::Result<T, ProviderError>;

/// Inputs required to request a public-to-USDC quote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwapQuoteRequest {
    /// Application-approved source token.
    pub token_in: [u8; 20],
    /// Source amount as a left-padded 32-byte integer.
    pub amount_in: [u8; 32],
    /// Minimum USDC the caller will accept.
    pub min_usdc_out: u64,
    /// Inclusive unix deadline.
    pub deadline: u64,
}

/// Provider-neutral swap quote used by the router path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwapQuote {
    /// Source token copied from the request.
    pub token_in: [u8; 20],
    /// Quoted USDC output.
    pub usdc_out: u64,
    /// Commitment over the opaque route description.
    pub route_hash: [u8; 32],
    /// Inclusive unix deadline copied from the request.
    pub deadline: u64,
}

/// Application KMS unwrap request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnwrapRequest<'a> {
    /// Application that owns the key policy.
    pub application_id: [u8; 32],
    /// Opaque key reference, never a vendor ARN type.
    pub key_ref: &'a str,
    /// Wrapped data-encryption key.
    pub wrapped_key: Vec<u8>,
}

/// Authenticated identity assertion after a successful IdP exchange.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityAssertion {
    /// Logical issuer identifier.
    pub issuer: String,
    /// Subject identifier inside that issuer.
    pub subject: String,
    /// Unix expiry.
    pub expires_at: u64,
}

/// Quote source for swap-and-shield.
pub trait DexQuoteSource {
    /// Return a fresh quote or fail closed.
    fn quote(&self, request: &SwapQuoteRequest) -> ProviderResult<SwapQuote>;
}

/// Narrow EVM transport used by Haze services.
pub trait ChainRpc {
    /// Report the bound chain id.
    fn chain_id(&self) -> ProviderResult<u64>;
}

/// Application-owned key unwrap.
pub trait KeyManagement {
    /// Unwrap a data key or fail closed.
    fn unwrap_data_key(&self, request: &UnwrapRequest<'_>) -> ProviderResult<Vec<u8>>;
}

/// OIDC/SAML session intake.
pub trait IdentityProvider {
    /// Validate a bearer assertion or fail closed.
    fn authenticate(&self, assertion: &str) -> ProviderResult<IdentityAssertion>;
}

/// Object storage for ciphertext and manifests.
pub trait ObjectStore {
    /// Persist bytes under an opaque key.
    fn put(&self, key: &str, value: &[u8]) -> ProviderResult<()>;
    /// Load bytes or fail closed if missing.
    fn get(&self, key: &str) -> ProviderResult<Vec<u8>>;
}

/// Deterministic mocks used until a vendor adapter is accepted.
pub mod mocks {
    use std::{collections::HashMap, sync::Mutex};

    use super::{
        ChainRpc, DexQuoteSource, IdentityAssertion, IdentityProvider, KeyManagement, ObjectStore,
        ProviderError, ProviderResult, SwapQuote, SwapQuoteRequest, UnwrapRequest,
    };
    use crate::keccak::keccak256;

    /// DEX that always returns the configured USDC amount.
    pub struct AlwaysQuoteDex {
        /// Fixed USDC output used by tests.
        pub usdc_out: u64,
    }

    impl DexQuoteSource for AlwaysQuoteDex {
        fn quote(&self, request: &SwapQuoteRequest) -> ProviderResult<SwapQuote> {
            if request.min_usdc_out > self.usdc_out {
                return Err(ProviderError::QuoteStale);
            }
            let mut material = Vec::new();
            material.extend_from_slice(&request.token_in);
            material.extend_from_slice(&request.amount_in);
            material.extend_from_slice(&self.usdc_out.to_be_bytes());
            Ok(SwapQuote {
                token_in: request.token_in,
                usdc_out: self.usdc_out,
                route_hash: keccak256(&material),
                deadline: request.deadline,
            })
        }
    }

    /// DEX that is down.
    pub struct UnavailableDex;

    impl DexQuoteSource for UnavailableDex {
        fn quote(&self, _request: &SwapQuoteRequest) -> ProviderResult<SwapQuote> {
            Err(ProviderError::Unavailable)
        }
    }

    /// KMS that is down.
    pub struct UnavailableKms;

    impl KeyManagement for UnavailableKms {
        fn unwrap_data_key(&self, _request: &UnwrapRequest<'_>) -> ProviderResult<Vec<u8>> {
            Err(ProviderError::Unavailable)
        }
    }

    /// Identity provider that is down.
    pub struct UnavailableIdentity;

    impl IdentityProvider for UnavailableIdentity {
        fn authenticate(&self, _assertion: &str) -> ProviderResult<IdentityAssertion> {
            Err(ProviderError::Unavailable)
        }
    }

    /// Static chain-id RPC.
    pub struct StaticChainRpc {
        /// Bound chain id.
        pub chain_id: u64,
    }

    impl ChainRpc for StaticChainRpc {
        fn chain_id(&self) -> ProviderResult<u64> {
            Ok(self.chain_id)
        }
    }

    /// In-memory object store.
    #[derive(Default)]
    pub struct MemoryObjectStore {
        records: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl ObjectStore for MemoryObjectStore {
        fn put(&self, key: &str, value: &[u8]) -> ProviderResult<()> {
            let mut records = self
                .records
                .lock()
                .map_err(|_| ProviderError::Unavailable)?;
            records.insert(key.to_owned(), value.to_vec());
            Ok(())
        }

        fn get(&self, key: &str) -> ProviderResult<Vec<u8>> {
            let records = self
                .records
                .lock()
                .map_err(|_| ProviderError::Unavailable)?;
            records.get(key).cloned().ok_or(ProviderError::Rejected)
        }
    }
}
