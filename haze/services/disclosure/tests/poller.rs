//! Fuji log poller against a mock JSON-RPC endpoint with a provider block-range cap.

use std::sync::{Arc, Mutex};

use axum::{Json, Router, extract::State, routing::post};
use haze_disclosure::{
    fuji::FujiDisclosureConfig,
    poller::{FujiLogPoller, PRIVATE_TRANSACTION_SIGNATURE},
    store::ComplianceStore,
};
use haze_protocol::{action::WITHDRAW, keccak::keccak256};
use serde_json::{Value, json};

const PROVIDER_MAX_RANGE: u64 = 1_000;
const LOG_BLOCK: u64 = 3_456;
const LOG_BLOCK_TIMESTAMP: u64 = 1_764_000_000;
const HEAD: u64 = 4_500;
const TX_HASH: [u8; 32] = [0x40; 32];

#[derive(Clone, Default)]
struct MockRpc {
    get_logs_ranges: Arc<Mutex<Vec<(u64, u64)>>>,
}

fn hex_u64(value: &Value) -> u64 {
    u64::from_str_radix(
        value.as_str().expect("hex string").trim_start_matches("0x"),
        16,
    )
    .expect("hex u64")
}

fn config() -> FujiDisclosureConfig {
    FujiDisclosureConfig {
        chain_id: 43113,
        application_id: [0xaa; 32],
        pool: [0x11; 20],
        pool_version: [0x22; 32],
        development_fixture_keys: true,
    }
}

fn withdrawal_log() -> Value {
    let cfg = config();
    let mut action_word = [0u8; 32];
    action_word[31] = WITHDRAW;
    let mut user_word = [0u8; 32];
    user_word[12..].copy_from_slice(&[0x55; 20]);
    json!({
        "address": format!("0x{}", hex::encode(cfg.pool)),
        "transactionHash": format!("0x{}", hex::encode(TX_HASH)),
        "blockNumber": format!("0x{LOG_BLOCK:x}"),
        "blockHash": format!("0x{}", hex::encode([0x0b; 32])),
        "logIndex": "0x0",
        "topics": [
            format!("0x{}", hex::encode(keccak256(PRIVATE_TRANSACTION_SIGNATURE.as_bytes()))),
            format!("0x{}", hex::encode(cfg.application_id)),
            format!("0x{}", hex::encode(action_word)),
            format!("0x{}", hex::encode(user_word)),
        ],
        "data": format!("0x{}", "00".repeat(16 * 32)),
    })
}

async fn handle(State(mock): State<MockRpc>, Json(request): Json<Value>) -> Json<Value> {
    let id = request["id"].clone();
    let params = &request["params"];
    let result = match request["method"].as_str().unwrap_or_default() {
        "eth_blockNumber" => json!(format!("0x{HEAD:x}")),
        "eth_getLogs" => {
            let from = hex_u64(&params[0]["fromBlock"]);
            let to = hex_u64(&params[0]["toBlock"]);
            mock.get_logs_ranges.lock().expect("lock").push((from, to));
            if to - from + 1 > PROVIDER_MAX_RANGE {
                return Json(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": -32005, "message": "block range too large"},
                }));
            }
            if (from..=to).contains(&LOG_BLOCK) {
                json!([withdrawal_log()])
            } else {
                json!([])
            }
        }
        "eth_getBlockByNumber" => {
            let number = hex_u64(&params[0]);
            json!({
                "number": format!("0x{number:x}"),
                "hash": format!("0x{}", hex::encode([0x0b; 32])),
                "timestamp": format!("0x{:x}", if number == LOG_BLOCK { LOG_BLOCK_TIMESTAMP } else { 1 }),
            })
        }
        other => json!({"unexpected_method": other}),
    };
    Json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

async fn spawn_mock() -> (String, MockRpc) {
    let mock = MockRpc::default();
    let app = Router::new()
        .route("/", post(handle))
        .with_state(mock.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    (url, mock)
}

#[tokio::test]
async fn scan_range_splits_large_ranges_into_provider_sized_windows() {
    let (url, mock) = spawn_mock().await;
    let store = ComplianceStore::new();
    let mut poller = FujiLogPoller::new(config(), url, store.clone());
    poller.max_block_range = PROVIDER_MAX_RANGE;

    let ingested = poller.scan_range(0, HEAD).await.expect("scan succeeds");
    assert_eq!(ingested, 1);

    let ranges = mock.get_logs_ranges.lock().expect("lock").clone();
    assert!(ranges.len() > 1, "expected several windows, got {ranges:?}");
    assert_eq!(ranges.first().expect("first").0, 0);
    assert_eq!(ranges.last().expect("last").1, HEAD);
    for pair in ranges.windows(2) {
        assert_eq!(
            pair[1].0,
            pair[0].1 + 1,
            "windows must be contiguous: {ranges:?}"
        );
    }
    for (from, to) in &ranges {
        assert!(
            to - from < PROVIDER_MAX_RANGE,
            "window {from}..={to} too large"
        );
    }
}

#[tokio::test]
async fn ingested_evidence_records_the_block_timestamp() {
    let (url, _mock) = spawn_mock().await;
    let store = ComplianceStore::new();
    let mut poller = FujiLogPoller::new(config(), url, store.clone());
    poller.max_block_range = PROVIDER_MAX_RANGE;

    poller
        .scan_range(LOG_BLOCK - 10, LOG_BLOCK + 10)
        .await
        .expect("scan succeeds");

    let evidence = store.get_evidence(&TX_HASH).expect("evidence stored");
    assert_eq!(evidence[0].record.recorded_at, LOG_BLOCK_TIMESTAMP);
    assert_eq!(evidence[0].record.record_id, TX_HASH);
}
