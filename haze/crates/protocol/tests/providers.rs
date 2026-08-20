//! Provider-neutral interface contract for T0.3.

use haze_protocol::providers::{
    ChainRpc, DexQuoteSource, IdentityProvider, KeyManagement, ObjectStore, ProviderError,
    SwapQuoteRequest, UnwrapRequest, mocks,
};

#[test]
fn mock_dex_returns_a_deterministic_quote() {
    let dex = mocks::AlwaysQuoteDex {
        usdc_out: 1_000_000,
    };
    let quote = dex
        .quote(&SwapQuoteRequest {
            token_in: [0x11; 20],
            amount_in: [0u8; 32],
            min_usdc_out: 1,
            deadline: 2_000_000_000,
        })
        .expect("quote");
    assert_eq!(quote.usdc_out, 1_000_000);
    assert_ne!(quote.route_hash, [0u8; 32]);
}

#[test]
fn dex_outage_fails_closed() {
    let dex = mocks::UnavailableDex;
    assert_eq!(
        dex.quote(&SwapQuoteRequest {
            token_in: [0u8; 20],
            amount_in: [0u8; 32],
            min_usdc_out: 1,
            deadline: 1,
        }),
        Err(ProviderError::Unavailable)
    );
}

#[test]
fn kms_outage_fails_closed() {
    let kms = mocks::UnavailableKms;
    assert_eq!(
        kms.unwrap_data_key(&UnwrapRequest {
            application_id: [0xaa; 32],
            key_ref: "app-audit",
            wrapped_key: vec![1, 2, 3],
        }),
        Err(ProviderError::Unavailable)
    );
}

#[test]
fn identity_outage_fails_closed() {
    let idp = mocks::UnavailableIdentity;
    assert_eq!(
        idp.authenticate("session-assertion"),
        Err(ProviderError::Unavailable)
    );
}

#[test]
fn rpc_reports_fuji_without_vendor_url_types() {
    let rpc = mocks::StaticChainRpc { chain_id: 43113 };
    assert_eq!(rpc.chain_id().expect("rpc"), 43113);
}

#[test]
fn object_store_round_trips_ciphertext() {
    let store = mocks::MemoryObjectStore::default();
    store.put("audit/1", b"ciphertext").expect("put");
    assert_eq!(store.get("audit/1").expect("get"), b"ciphertext");
}
