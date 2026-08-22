//! Axum HTTP boundary and Fuji JSON-RPC evidence adapter.

use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use haze_protocol::{envelope::Envelope, keccak::keccak256};
use serde::Deserialize;
use serde_json::{Value, json};
use tower_http::cors::CorsLayer;

use crate::{
    DisclosureError, StoredAuditRecord,
    auth::{
        AuditSession, ChallengeRequest, SiweChallenge, SiweConfig, StoredSession, VerifyRequest,
        format_siwe_message, hash_session_token, verify_siwe_signature,
    },
    cases::AuditCaseSummary,
    export::{DEFAULT_SIGNING_KEY_ID, create_signed_export},
    fuji::{
        FujiDisclosureConfig, FujiDisclosureRequest, FujiWithdrawalEvidence,
        verify_compliance_case_evidence, verify_fuji_withdrawal,
    },
    store::{ComplianceStore, StoredChallenge},
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
    /// SIWE configuration.
    pub siwe_config: SiweConfig,
    /// Compliance store.
    pub store: Arc<ComplianceStore>,
    client: reqwest::Client,
}

impl HttpState {
    /// Create state without making a network request.
    #[must_use]
    pub fn new(
        config: FujiDisclosureConfig,
        fixture_ikm: Option<[u8; 32]>,
        rpc_url: String,
        siwe_config: SiweConfig,
        store: Arc<ComplianceStore>,
    ) -> Self {
        Self {
            config,
            fixture_ikm,
            rpc_url,
            siwe_config,
            store,
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
        DisclosureError::Unauthorized => StatusCode::UNAUTHORIZED,
        DisclosureError::Forbidden
        | DisclosureError::UserIneligible
        | DisclosureError::GrantRevoked
        | DisclosureError::CaseUnassigned => StatusCode::FORBIDDEN,
        DisclosureError::Unavailable | DisclosureError::KeysMissing => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        DisclosureError::ReceiptNotSuccessful | DisclosureError::InsufficientFinality => {
            StatusCode::UNPROCESSABLE_ENTITY
        }
        _ => StatusCode::BAD_REQUEST,
    };
    (
        status,
        Json(json!({
            "code": error.as_code(),
            "message": error.to_string(),
        })),
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
    if let Some(mut cached) = state.store.get_evidence(&hash) {
        if let Ok(head_val) = rpc(state, "eth_blockNumber", json!([])).await
            && let Some(head_hex) = head_val.as_str()
            && let Ok(head_num) = u64::from_str_radix(head_hex.trim_start_matches("0x"), 16)
        {
            for item in &mut cached {
                item.current_block_number = head_num;
            }
        }
        return Ok(cached);
    }

    let hash_hex = format!("0x{}", hex::encode(hash));
    let receipt = rpc(state, "eth_getTransactionReceipt", json!([hash_hex])).await?;
    if receipt.is_null() || receipt.get("status").and_then(Value::as_str) != Some("0x1") {
        return Err(DisclosureError::ReceiptNotSuccessful);
    }
    let block_number_hex = receipt
        .get("blockNumber")
        .and_then(Value::as_str)
        .ok_or(DisclosureError::InvalidBinding)?;
    let block_number = u64::from_str_radix(block_number_hex.trim_start_matches("0x"), 16)
        .map_err(|_| DisclosureError::InvalidBinding)?;

    let head_block_val = rpc(state, "eth_blockNumber", json!([])).await?;
    let current_block_number = head_block_val

        .as_str()
        .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok())
        .unwrap_or(block_number);

    let block = rpc(
        state,
        "eth_getBlockByNumber",
        json!([block_number_hex, false]),
    )
    .await?;
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
                block_number,
                current_block_number,
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
        match verify_fuji_withdrawal(
            &state.config,
            &request,
            &evidence,
            state.fixture_ikm.as_ref(),
            now,
        ) {
            Ok(response) => {
                return Json(json!({"transactionHash":format!("0x{}", hex::encode(response.transaction_hash)),"fields":response.fields})).into_response();
            }
            Err(error) => last = error,
        }
    }
    error_response(last)
}

// --- Institutional Compliance Routes ---

fn extract_session(headers: &HeaderMap, state: &HttpState) -> Result<StoredSession, DisclosureError> {
    let token = if let Some(auth_header) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        auth_header.strip_prefix("Bearer ").unwrap_or(auth_header).trim()
    } else if let Some(cookie_header) = headers.get("cookie").and_then(|v| v.to_str().ok()) {
        let mut found = "";
        for cookie in cookie_header.split(';') {
            let parts: Vec<&str> = cookie.trim().splitn(2, '=').collect();
            if parts.len() == 2 && parts[0] == "haze_audit_session" {
                found = parts[1];
                break;
            }
        }
        found
    } else {
        ""
    };

    if token.is_empty() {
        return Err(DisclosureError::Unauthorized);
    }

    let token_hash = hash_session_token(token);
    let session = state
        .store
        .get_session(&token_hash)
        .ok_or(DisclosureError::Unauthorized)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    if session.expires_at < now {
        return Err(DisclosureError::AuthorizationExpired);
    }

    Ok(session)
}

async fn auth_challenge(
    State(state): State<Arc<HttpState>>,
    Json(body): Json<ChallengeRequest>,
) -> Response {
    let wallet_bytes: [u8; 20] = match fixed_hex(&body.wallet) {
        Ok(w) => w,
        Err(_) => return error_response(DisclosureError::InvalidBinding),
    };
    let app_bytes: [u8; 32] = match fixed_hex(&body.application_id) {
        Ok(a) => a,
        Err(_) => return error_response(DisclosureError::InvalidBinding),
    };

    if app_bytes != state.config.application_id {
        return error_response(DisclosureError::ApplicationMismatch);
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let expires_at = now + state.siwe_config.challenge_ttl_secs;

    let challenge_id_bytes = state.store.next_id(b"siwe_challenge");
    let challenge_id = format!("0x{}", hex::encode(challenge_id_bytes));
    let nonce = hex::encode(&challenge_id_bytes[..8]);

    let message = format_siwe_message(
        &state.siwe_config,
        &body.wallet,
        &nonce,
        now,
        expires_at,
    );

    let stored = StoredChallenge {
        challenge_id: challenge_id_bytes,
        nonce: nonce.clone(),
        domain: state.siwe_config.domain.clone(),
        uri: state.siwe_config.uri.clone(),
        statement: "Sign in to Haze Compliance Portal (Fuji)".to_owned(),
        wallet: wallet_bytes,
        application_id: app_bytes,
        issued_at: now,
        expires_at,
        consumed: false,
        message: message.clone(),
    };
    state.store.save_challenge(stored);

    Json(SiweChallenge {
        challenge_id,
        nonce,
        domain: state.siwe_config.domain.clone(),
        uri: state.siwe_config.uri.clone(),
        statement: "Sign in to Haze Compliance Portal (Fuji)".to_owned(),
        message,
        issued_at: now,
        expires_at,
    })
    .into_response()
}

async fn auth_verify(
    State(state): State<Arc<HttpState>>,
    Json(body): Json<VerifyRequest>,
) -> Response {
    let challenge_id_bytes: [u8; 32] = match fixed_hex(&body.challenge_id) {
        Ok(c) => c,
        Err(_) => return error_response(DisclosureError::InvalidBinding),
    };
    let signature_bytes: [u8; 65] = match fixed_hex(&body.signature) {
        Ok(s) => s,
        Err(_) => return error_response(DisclosureError::InvalidBinding),
    };

    let challenge = match state.store.consume_challenge(&challenge_id_bytes) {
        Some(c) => c,
        None => return error_response(DisclosureError::Rejected),
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    if challenge.expires_at < now {
        return error_response(DisclosureError::AuthorizationExpired);
    }

    if body.message != challenge.message {
        return error_response(DisclosureError::InvalidBinding);
    }

    if let Err(err) = verify_siwe_signature(&body.message, &signature_bytes, challenge.wallet) {
        state.store.append_access_log(
            "auth_denied",
            &challenge.application_id,
            None,
            &challenge.wallet,
            vec![],
            false,
            now,
        );
        return error_response(err);
    }

    let grant = match state.store.get_grant(&challenge.wallet, &challenge.application_id) {
        Some(g) if !g.revoked && g.expires_at >= now => g,
        Some(_) => {
            state.store.append_access_log(
                "auth_denied",
                &challenge.application_id,
                None,
                &challenge.wallet,
                vec![],
                false,
                now,
            );
            return error_response(DisclosureError::GrantRevoked);
        }
        None => {
            state.store.append_access_log(
                "auth_denied",
                &challenge.application_id,
                None,
                &challenge.wallet,
                vec![],
                false,
                now,
            );
            return error_response(DisclosureError::UserIneligible);
        }
    };

    let session_token_bytes = state.store.next_id(b"session_secret");
    let session_token = format!("0x{}", hex::encode(session_token_bytes));
    let session_hash = hash_session_token(&session_token);
    let session_expiry = now + state.siwe_config.session_ttl_secs.min(grant.expires_at.saturating_sub(now));

    let session = StoredSession {
        session_hash,
        wallet: challenge.wallet,
        application_id: challenge.application_id,
        role: grant.role.clone(),
        grant_id: grant.grant_id,
        expires_at: session_expiry,
    };
    state.store.save_session(session);

    state.store.append_access_log(
        "auth",
        &challenge.application_id,
        None,
        &challenge.wallet,
        vec![],
        true,
        now,
    );

    Json(AuditSession {
        token: session_token,
        address: format!("0x{}", hex::encode(challenge.wallet)),
        application_id: format!("0x{}", hex::encode(challenge.application_id)),
        role: grant.role,
        expires_at: session_expiry,
    })
    .into_response()
}

async fn get_session_info(
    headers: HeaderMap,
    State(state): State<Arc<HttpState>>,
) -> Response {
    let session = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(err) => return error_response(err),
    };

    Json(json!({
        "address": format!("0x{}", hex::encode(session.wallet)),
        "applicationId": format!("0x{}", hex::encode(session.application_id)),
        "role": session.role,
        "expiresAt": session.expires_at,
    }))
    .into_response()
}

async fn delete_session_handler(
    headers: HeaderMap,
    State(state): State<Arc<HttpState>>,
) -> Response {
    if let Ok(session) = extract_session(&headers, &state) {
        state.store.delete_session(&session.session_hash);
    }
    Json(json!({"ok": true})).into_response()
}

async fn list_cases_handler(
    headers: HeaderMap,
    State(state): State<Arc<HttpState>>,
) -> Response {
    let session = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(err) => return error_response(err),
    };

    let grant = match state.store.get_grant(&session.wallet, &session.application_id) {
        Some(g) => g,
        None => return error_response(DisclosureError::Forbidden),
    };

    let cases = state
        .store
        .list_cases(&session.application_id, &grant.assigned_cases);

    let summaries: Vec<AuditCaseSummary> = cases
        .into_iter()
        .map(|c| AuditCaseSummary {
            case_id: c.case_id,
            title: c.title,
            application_id: c.application_id,
            transaction_hash: c.transaction_hash,
            granted_fields: c.granted_fields,
            status: c.status,
            block_number: c.block_number,
            confirmations: c.confirmations,
            sync_status: c.sync_status,
            integrity_status: c.integrity_status,
            grant_expires_at: grant.expires_at,
        })
        .collect();

    Json(json!({ "cases": summaries })).into_response()
}

async fn case_disclosure_handler(
    Path(case_id): Path<String>,
    headers: HeaderMap,
    State(state): State<Arc<HttpState>>,
) -> Response {
    let session = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(err) => return error_response(err),
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let grant = match state.store.get_grant(&session.wallet, &session.application_id) {
        Some(g) if !g.revoked && g.expires_at >= now => g,
        Some(_) => return error_response(DisclosureError::GrantRevoked),
        None => return error_response(DisclosureError::Forbidden),
    };

    let case = match state.store.get_case(&case_id) {
        Some(c) => c,
        None => return error_response(DisclosureError::CaseUnassigned),
    };

    if !grant.assigned_cases.is_empty() && !grant.assigned_cases.contains(&case.case_id) {
        state.store.append_access_log(
            "denied",
            &session.application_id,
            Some(&case_id),
            &session.wallet,
            vec![],
            false,
            now,
        );
        return error_response(DisclosureError::CaseUnassigned);
    }


    let tx_hash_bytes: [u8; 32] = match fixed_hex(&case.transaction_hash) {
        Ok(h) => h,
        Err(_) => return error_response(DisclosureError::InvalidBinding),
    };

    let candidates = match evidence_candidates(&state, tx_hash_bytes).await {
        Ok(c) => c,
        Err(err) => {
            state.store.append_access_log(
                "denied",
                &session.application_id,
                Some(&case_id),
                &session.wallet,
                case.granted_fields.clone(),
                false,
                now,
            );
            return error_response(err);
        }
    };

    let mut last_err = DisclosureError::InvalidBinding;
    for evidence in candidates {
        match verify_compliance_case_evidence(
            &state.config,
            tx_hash_bytes,
            &case.granted_fields,
            &evidence,
            state.fixture_ikm.as_ref(),
        ) {
            Ok(resp) => {
                state.store.append_access_log(
                    "query",
                    &session.application_id,
                    Some(&case_id),
                    &session.wallet,
                    case.granted_fields.clone(),
                    true,
                    now,
                );
                return Json(resp).into_response();
            }
            Err(err) => last_err = err,
        }
    }

    state.store.append_access_log(
        "denied",
        &session.application_id,
        Some(&case_id),
        &session.wallet,
        case.granted_fields,
        false,
        now,
    );
    error_response(last_err)
}

#[derive(Deserialize)]
struct ExportBody {
    #[serde(default)]
    fields: Option<Vec<String>>,
}

async fn case_export_handler(
    Path(case_id): Path<String>,
    headers: HeaderMap,
    State(state): State<Arc<HttpState>>,
    body: Option<Json<ExportBody>>,
) -> Response {
    let session = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(err) => return error_response(err),
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let grant = match state.store.get_grant(&session.wallet, &session.application_id) {
        Some(g) if !g.revoked && g.expires_at >= now => g,
        Some(_) => return error_response(DisclosureError::GrantRevoked),
        None => return error_response(DisclosureError::Forbidden),
    };

    let case = match state.store.get_case(&case_id) {
        Some(c) => c,
        None => return error_response(DisclosureError::CaseUnassigned),
    };

    if !grant.assigned_cases.contains(&case.case_id) {
        state.store.append_access_log(
            "denied",
            &session.application_id,
            Some(&case_id),
            &session.wallet,
            vec![],
            false,
            now,
        );
        return error_response(DisclosureError::CaseUnassigned);
    }

    let requested_fields = body
        .and_then(|b| b.fields.clone())
        .unwrap_or_else(|| case.granted_fields.clone());

    for field in &requested_fields {
        if !case.granted_fields.contains(field) || case.denied_fields.contains(field) {
            state.store.append_access_log(
                "denied",
                &session.application_id,
                Some(&case_id),
                &session.wallet,
                requested_fields.clone(),
                false,
                now,
            );
            return error_response(DisclosureError::UnauthorizedField);
        }
    }

    let tx_hash_bytes: [u8; 32] = match fixed_hex(&case.transaction_hash) {
        Ok(h) => h,
        Err(_) => return error_response(DisclosureError::InvalidBinding),
    };

    let candidates = match evidence_candidates(&state, tx_hash_bytes).await {
        Ok(c) => c,
        Err(err) => return error_response(err),
    };

    let mut disclosed_fields: Option<BTreeMap<String, String>> = None;
    let mut provenance = BTreeMap::new();
    provenance.insert("chainId".to_owned(), state.config.chain_id.to_string());
    provenance.insert("applicationId".to_owned(), case.application_id.clone());
    provenance.insert("transactionHash".to_owned(), case.transaction_hash.clone());

    for evidence in candidates {
        if let Ok(resp) = verify_compliance_case_evidence(
            &state.config,
            tx_hash_bytes,
            &requested_fields,
            &evidence,
            state.fixture_ikm.as_ref(),
        ) {
            disclosed_fields = Some(resp.fields);
            provenance.insert("confirmations".to_owned(), resp.confirmations.to_string());
            provenance.insert("minedBlock".to_owned(), evidence.block_number.to_string());
            break;
        }
    }

    let fields = match disclosed_fields {
        Some(f) => f,
        None => return error_response(DisclosureError::IntegrityFailure),
    };

    let export_id_bytes = state.store.next_id(b"export_id");
    let export_expiry = now + 600; // 10 minute export validity

    let bundle = create_signed_export(
        export_id_bytes,
        &case_id,
        &case.transaction_hash,
        &format!("0x{}", hex::encode(session.wallet)),
        DEFAULT_SIGNING_KEY_ID,
        fields,
        provenance,
        export_expiry,
    );

    state.store.save_export(bundle.clone());
    state.store.append_access_log(
        "export",
        &session.application_id,
        Some(&case_id),
        &session.wallet,
        requested_fields,
        true,
        now,
    );

    Json(bundle).into_response()
}

#[derive(Deserialize)]
struct AccessLogParams {
    case_id: Option<String>,
}

async fn access_log_handler(
    Query(params): Query<AccessLogParams>,
    headers: HeaderMap,
    State(state): State<Arc<HttpState>>,
) -> Response {
    let session = match extract_session(&headers, &state) {
        Ok(s) => s,
        Err(err) => return error_response(err),
    };

    let entries = state
        .store
        .list_access_log(&session.application_id, params.case_id.as_deref());

    Json(json!({ "entries": entries })).into_response()
}

/// Build the Axum router with exact-origin CORS and all routes.
pub fn router(state: HttpState, allowed_origin: &str) -> Result<Router, DisclosureError> {
    let origin =
        HeaderValue::from_str(allowed_origin).map_err(|_| DisclosureError::InvalidBinding)?;
    let cors = CorsLayer::new()
        .allow_origin(origin)
        .allow_methods([Method::GET, Method::POST, Method::DELETE])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            axum::http::header::COOKIE,
        ]);

    Ok(Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        // Legacy D7 wallet disclosure
        .route("/v1/fuji/disclosures/withdrawal", post(withdrawal))
        // Institutional Compliance API
        .route("/v1/auth/challenge", post(auth_challenge))
        .route("/v1/auth/verify", post(auth_verify))
        .route("/v1/session", get(get_session_info).delete(delete_session_handler))
        .route("/v1/cases", get(list_cases_handler))
        .route("/v1/cases/{case_id}/disclosure", post(case_disclosure_handler))
        .route("/v1/cases/{case_id}/export", post(case_export_handler))
        .route("/v1/access-log", get(access_log_handler))
        .layer(cors)
        .with_state(Arc::new(state)))
}
