//! Axum HTTP boundary and Fuji JSON-RPC evidence adapter.

use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use haze_protocol::{envelope::Envelope, keccak::keccak256};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tower_http::cors::CorsLayer;

use crate::{
    DisclosureError, StoredAuditRecord,
    fuji::{
        FujiDisclosureConfig, FujiDisclosureRequest, FujiWithdrawalEvidence, verify_fuji_withdrawal,
    },
};

/// Immutable HTTP application state.
#[derive(Clone)]
pub struct HttpState {
    /// Fuji development verification configuration.
    pub config: FujiDisclosureConfig,
    /// Optional fixture IKM, available only in the Fuji-development build.
    pub fixture_ikm: Option<[u8; 32]>,
    /// Fuji JSON-RPC URL.
    pub rpc_url: String,
    client: reqwest::Client,
}

impl HttpState {
    /// Create state without making a network request.
    #[must_use]
    pub fn new(
        config: FujiDisclosureConfig,
        fixture_ikm: Option<[u8; 32]>,
        rpc_url: String,
    ) -> Self {
        Self {
            config,
            fixture_ikm,
            rpc_url,
            client: reqwest::Client::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WithdrawalBody {
    transaction_hash: String,
    application_id: String,
    requested_fields: Vec<String>,
    expires_at: u64,
    signature: String,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
}

fn fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], DisclosureError> {
    let raw = value
        .strip_prefix("0x")
        .ok_or(DisclosureError::InvalidBinding)?;
    let bytes = hex::decode(raw).map_err(|_| DisclosureError::InvalidBinding)?;
    bytes
        .try_into()
        .map_err(|_| DisclosureError::InvalidBinding)
}

fn error_response(error: DisclosureError) -> Response {
    let status = match error {
        DisclosureError::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        DisclosureError::KeysMissing => StatusCode::SERVICE_UNAVAILABLE,
        DisclosureError::ReceiptNotSuccessful => StatusCode::UNPROCESSABLE_ENTITY,
        _ => StatusCode::BAD_REQUEST,
    };
    (
        status,
        Json(ErrorBody {
            code: error.as_code(),
        }),
    )
        .into_response()
}

async fn healthz() -> impl IntoResponse {
    Json(json!({"status":"ok"}))
}

async fn readyz(State(state): State<Arc<HttpState>>) -> Response {
    if state.config.chain_id == 43_113
        && state.config.development_fixture_keys
        && state.fixture_ikm.is_some()
        && !state.rpc_url.is_empty()
    {
        Json(json!({"status":"ready"})).into_response()
    } else {
        error_response(DisclosureError::KeysMissing)
    }
}

async fn rpc(state: &HttpState, method: &str, params: Value) -> Result<Value, DisclosureError> {
    let response = state
        .client
        .post(&state.rpc_url)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
        .send()
        .await
        .map_err(|_| DisclosureError::Unavailable)?;
    let body: Value = response
        .json()
        .await
        .map_err(|_| DisclosureError::Unavailable)?;
    body.get("result")
        .cloned()
        .ok_or(DisclosureError::Unavailable)
}

fn words(data: &str) -> Result<Vec<[u8; 32]>, DisclosureError> {
    let bytes = hex::decode(
        data.strip_prefix("0x")
            .ok_or(DisclosureError::InvalidBinding)?,
    )
    .map_err(|_| DisclosureError::InvalidBinding)?;
    if bytes.len() % 32 != 0 {
        return Err(DisclosureError::InvalidBinding);
    }
    Ok(bytes
        .chunks_exact(32)
        .map(|word| word.try_into().unwrap_or([0u8; 32]))
        .collect())
}

fn dynamic_bytes(data: &str, offset_word: [u8; 32]) -> Result<Vec<u8>, DisclosureError> {
    let raw = hex::decode(
        data.strip_prefix("0x")
            .ok_or(DisclosureError::InvalidBinding)?,
    )
    .map_err(|_| DisclosureError::InvalidBinding)?;
    let offset = usize::try_from(u64::from_be_bytes(
        offset_word[24..]
            .try_into()
            .map_err(|_| DisclosureError::InvalidBinding)?,
    ))
    .map_err(|_| DisclosureError::InvalidBinding)?;
    let length_word = raw
        .get(offset..offset + 32)
        .ok_or(DisclosureError::InvalidBinding)?;
    let length = usize::try_from(u64::from_be_bytes(
        length_word[24..]
            .try_into()
            .map_err(|_| DisclosureError::InvalidBinding)?,
    ))
    .map_err(|_| DisclosureError::InvalidBinding)?;
    Ok(raw
        .get(offset + 32..offset + 32 + length)
        .ok_or(DisclosureError::InvalidBinding)?
        .to_vec())
}

async fn evidence_candidates(
    state: &HttpState,
    hash: [u8; 32],
) -> Result<Vec<FujiWithdrawalEvidence>, DisclosureError> {
    let hash_hex = format!("0x{}", hex::encode(hash));
    let receipt = rpc(state, "eth_getTransactionReceipt", json!([hash_hex])).await?;
    if receipt.is_null() || receipt.get("status").and_then(Value::as_str) != Some("0x1") {
        return Err(DisclosureError::ReceiptNotSuccessful);
    }
    let block_number = receipt
        .get("blockNumber")
        .and_then(Value::as_str)
        .ok_or(DisclosureError::InvalidBinding)?;
    let block = rpc(state, "eth_getBlockByNumber", json!([block_number, false])).await?;
    let recorded_at = block
        .get("timestamp")
        .and_then(Value::as_str)
        .and_then(|value| u64::from_str_radix(value.trim_start_matches("0x"), 16).ok())
        .ok_or(DisclosureError::InvalidBinding)?;
    let transaction = rpc(state, "eth_getTransactionByHash", json!([hash_hex])).await?;
    let input = transaction
        .get("input")
        .and_then(Value::as_str)
        .ok_or(DisclosureError::InvalidBinding)?;
    let input_bytes = hex::decode(
        input
            .strip_prefix("0x")
            .ok_or(DisclosureError::InvalidBinding)?,
    )
    .map_err(|_| DisclosureError::InvalidBinding)?;
    let action_refs: Vec<[u8; 32]> = input_bytes
        .get(4..)
        .unwrap_or_default()
        .chunks_exact(32)
        .map(|word| word.try_into().unwrap_or([0u8; 32]))
        .collect();
    let logs = receipt
        .get("logs")
        .and_then(Value::as_array)
        .ok_or(DisclosureError::InvalidBinding)?;
    let event_signature = keccak256(b"PrivateTransaction(bytes32,uint8,address,uint64,uint64,uint256,uint256,uint256,uint256,uint256,uint64,address,bytes32,bytes32,uint256,bytes32,bytes,bytes,bytes)");
    for log in logs {
        let address: [u8; 20] = fixed_hex(
            log.get("address")
                .and_then(Value::as_str)
                .ok_or(DisclosureError::InvalidBinding)?,
        )?;
        if address != state.config.pool {
            continue;
        }
        let topics = log
            .get("topics")
            .and_then(Value::as_array)
            .ok_or(DisclosureError::InvalidBinding)?;
        if topics.len() < 4
            || fixed_hex::<32>(topics[0].as_str().unwrap_or_default())? != event_signature
        {
            continue;
        }
        let application_id = fixed_hex(topics[1].as_str().unwrap_or_default())?;
        let action_word: [u8; 32] = fixed_hex(topics[2].as_str().unwrap_or_default())?;
        let user_word: [u8; 32] = fixed_hex(topics[3].as_str().unwrap_or_default())?;
        let mut user = [0u8; 20];
        user.copy_from_slice(&user_word[12..]);
        let data = log
            .get("data")
            .and_then(Value::as_str)
            .ok_or(DisclosureError::InvalidBinding)?;
        let data_words = words(data)?;
        if data_words.len() < 16 {
            return Err(DisclosureError::InvalidBinding);
        }
        let envelope = dynamic_bytes(data, data_words[15])?;
        let parsed =
            Envelope::from_bytes(&envelope).map_err(|_| DisclosureError::InvalidBinding)?;
        let mut out = Vec::new();
        for action_reference in action_refs.iter().copied() {
            let record = StoredAuditRecord {
                record_id: hash,
                application_id,
                recorded_at,
                chain_id: state.config.chain_id,
                pool: address,
                pool_version: state.config.pool_version,
                key_version: parsed.key_version,
                action: action_word[31],
                action_reference,
                audit_data_commitment: data_words[11],
                audit_ciphertext_hash: data_words[12],
                envelope: envelope.clone(),
                key_ref: "fuji-fixture".to_owned(),
                wrapped_key: Vec::new(),
                finalized: true,
                reorged: false,
            };
            out.push(FujiWithdrawalEvidence {
                receipt_successful: true,
                transaction_hash: hash,
                pool: address,
                application_id,
                action: action_word[31],
                authorized_user: user,
                pool_version: state.config.pool_version,
                audit_data_commitment: data_words[11],
                audit_ciphertext_hash: data_words[12],
                action_reference,
                record,
            });
        }
        return Ok(out);
    }
    Err(DisclosureError::InvalidBinding)
}

async fn withdrawal(
    State(state): State<Arc<HttpState>>,
    Json(body): Json<WithdrawalBody>,
) -> Response {
    let request = match (
        fixed_hex(&body.transaction_hash),
        fixed_hex(&body.application_id),
        fixed_hex(&body.signature),
    ) {
        (Ok(transaction_hash), Ok(application_id), Ok(signature)) => FujiDisclosureRequest {
            transaction_hash,
            application_id,
            requested_fields: body.requested_fields,
            expires_at: body.expires_at,
            signature,
        },
        _ => return error_response(DisclosureError::InvalidBinding),
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let candidates = match evidence_candidates(&state, request.transaction_hash).await {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let mut last = DisclosureError::InvalidBinding;
    for evidence in candidates {
        match verify_fuji_withdrawal(&state.config, &request, &evidence, state.fixture_ikm.as_ref(), now) {
            Ok(response) => return Json(json!({"transactionHash":format!("0x{}", hex::encode(response.transaction_hash)),"fields":response.fields})).into_response(),
            Err(error) => last = error,
        }
    }
    error_response(last)
}

/// Build the stateless adapter with exact-origin CORS.
pub fn router(state: HttpState, allowed_origin: &str) -> Result<Router, DisclosureError> {
    let origin =
        HeaderValue::from_str(allowed_origin).map_err(|_| DisclosureError::InvalidBinding)?;
    let cors = CorsLayer::new()
        .allow_origin(origin)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([axum::http::header::CONTENT_TYPE]);
    Ok(Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/v1/fuji/disclosures/withdrawal", post(withdrawal))
        .layer(cors)
        .with_state(Arc::new(state)))
}
