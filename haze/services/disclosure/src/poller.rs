//! Internal Fuji on-chain log poller and dynamic compliance case ingestion.

use std::{sync::Arc, time::Duration};

use haze_protocol::{action::WITHDRAW, envelope::Envelope, keccak::keccak256};
use serde_json::{Value, json};

use crate::{
    DisclosureError, StoredAuditRecord,
    cases::create_withdrawal_case,
    fuji::{FujiDisclosureConfig, FujiWithdrawalEvidence},
    repository::{ComplianceRepository, PollerCheckpoint},
    store::ComplianceStore,
};

/// Event signature for HazePool PrivateTransaction.
pub const PRIVATE_TRANSACTION_SIGNATURE: &str = "PrivateTransaction(bytes32,uint8,address,uint64,uint64,uint256,uint256,uint256,uint256,uint256,uint64,address,bytes32,bytes32,uint256,bytes32,bytes,bytes,bytes)";

/// Default `eth_getLogs` window; Infura caps Fuji requests at 10k blocks.
pub const DEFAULT_MAX_BLOCK_RANGE: u64 = 2_000;

/// Internal poller that scans Fuji logs, ingests withdrawal cases, and updates confirmations.
pub struct FujiLogPoller {
    /// Fuji disclosure configuration.
    pub config: FujiDisclosureConfig,
    /// JSON-RPC URL.
    pub rpc_url: String,
    /// Target store.
    pub store: Arc<ComplianceRepository>,
    /// First deployment block eligible for backfill.
    pub deployment_block: u64,
    /// Canonical blocks replayed on each cycle to detect short reorgs.
    pub replay_window: u64,
    /// Largest inclusive block span sent in one `eth_getLogs` request.
    pub max_block_range: u64,
    client: reqwest::Client,
}

impl FujiLogPoller {
    /// Create a new log poller.
    #[must_use]
    pub fn new(config: FujiDisclosureConfig, rpc_url: String, store: Arc<ComplianceStore>) -> Self {
        Self {
            config,
            rpc_url,
            store: Arc::new(store.into()),
            deployment_block: 0,
            replay_window: 32,
            max_block_range: DEFAULT_MAX_BLOCK_RANGE,
            client: reqwest::Client::new(),
        }
    }

    /// Create a production poller over a durable repository.
    #[must_use]
    pub fn with_repository(
        config: FujiDisclosureConfig,
        rpc_url: String,
        store: ComplianceRepository,
        deployment_block: u64,
        replay_window: u64,
    ) -> Self {
        Self {
            config,
            rpc_url,
            store: Arc::new(store),
            deployment_block,
            replay_window,
            max_block_range: DEFAULT_MAX_BLOCK_RANGE,
            client: reqwest::Client::new(),
        }
    }

    async fn rpc(&self, method: &str, params: Value) -> Result<Value, DisclosureError> {
        let response = self
            .client
            .post(&self.rpc_url)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            }))
            .send()
            .await
            .map_err(|_| DisclosureError::Unavailable)?;

        let payload: Value = response
            .json()
            .await
            .map_err(|_| DisclosureError::Unavailable)?;

        payload
            .get("result")
            .cloned()
            .ok_or(DisclosureError::Unavailable)
    }

    /// Query the current head block number on Fuji.
    pub async fn current_block_number(&self) -> Result<u64, DisclosureError> {
        let val = self.rpc("eth_blockNumber", json!([])).await?;
        let hex_str = val.as_str().ok_or(DisclosureError::Unavailable)?;
        u64::from_str_radix(hex_str.trim_start_matches("0x"), 16)
            .map_err(|_| DisclosureError::Unavailable)
    }

    /// Scan a specific block range on the configured HazePool for withdrawal events.
    ///
    /// The range is split into windows of at most `max_block_range` blocks so
    /// RPC providers with an `eth_getLogs` span cap accept every request.
    pub async fn scan_range(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<usize, DisclosureError> {
        let span = self.max_block_range.max(1);
        let mut total = 0;
        let mut start = from_block;
        while start <= to_block {
            let end = start.saturating_add(span - 1).min(to_block);
            total += self.scan_window(start, end).await?;
            if end == u64::MAX {
                break;
            }
            start = end + 1;
        }
        Ok(total)
    }

    async fn block_timestamp(&self, block_number: u64) -> Result<u64, DisclosureError> {
        let block = self
            .rpc(
                "eth_getBlockByNumber",
                json!([format!("0x{block_number:x}"), false]),
            )
            .await?;
        let timestamp = block
            .get("timestamp")
            .and_then(Value::as_str)
            .ok_or(DisclosureError::Unavailable)?;
        u64::from_str_radix(timestamp.trim_start_matches("0x"), 16)
            .map_err(|_| DisclosureError::Unavailable)
    }

    async fn scan_window(&self, from_block: u64, to_block: u64) -> Result<usize, DisclosureError> {
        let event_sig = keccak256(PRIVATE_TRANSACTION_SIGNATURE.as_bytes());
        let pool_hex = format!("0x{}", hex::encode(self.config.pool));
        let app_topic = format!("0x{}", hex::encode(self.config.application_id));
        let sig_topic = format!("0x{}", hex::encode(event_sig));

        let filter = json!({
            "address": pool_hex,
            "fromBlock": format!("0x{:x}", from_block),
            "toBlock": format!("0x{:x}", to_block),
            "topics": [sig_topic, app_topic],
        });

        let logs_val = self.rpc("eth_getLogs", json!([filter])).await?;
        let logs = logs_val.as_array().ok_or(DisclosureError::Unavailable)?;

        let head = self.current_block_number().await?;
        let mut ingested = Vec::new();

        let mut timestamps = std::collections::BTreeMap::new();
        for log in logs {
            let (mut evidence, tx_hash) = self.parse_log_evidence(log, head).await?;
            if evidence.action == WITHDRAW {
                let recorded_at = match timestamps.get(&evidence.block_number) {
                    Some(timestamp) => *timestamp,
                    None => {
                        let timestamp = self.block_timestamp(evidence.block_number).await?;
                        timestamps.insert(evidence.block_number, timestamp);
                        timestamp
                    }
                };
                evidence.record.recorded_at = recorded_at;
                let confirmations = if head >= evidence.block_number {
                    head - evidence.block_number + 1
                } else {
                    0
                };
                let case = create_withdrawal_case(
                    tx_hash,
                    evidence.block_number,
                    confirmations,
                    self.config.application_id,
                );
                ingested.push((case, evidence));
            }
        }
        let ingested_count = ingested.len();
        self.store
            .replace_ingestion_range(
                self.config.chain_id,
                self.config.pool,
                from_block,
                to_block,
                ingested,
            )
            .await
            .map_err(|_| DisclosureError::Unavailable)?;
        Ok(ingested_count)
    }

    async fn parse_log_evidence(
        &self,
        log: &Value,
        head_block: u64,
    ) -> Result<(FujiWithdrawalEvidence, [u8; 32]), DisclosureError> {
        let tx_hash_str = log
            .get("transactionHash")
            .and_then(Value::as_str)
            .ok_or(DisclosureError::InvalidBinding)?;
        let tx_hash_bytes = hex::decode(tx_hash_str.trim_start_matches("0x"))
            .map_err(|_| DisclosureError::InvalidBinding)?;
        let tx_hash: [u8; 32] = tx_hash_bytes
            .try_into()
            .map_err(|_| DisclosureError::InvalidBinding)?;

        let block_num_str = log
            .get("blockNumber")
            .and_then(Value::as_str)
            .ok_or(DisclosureError::InvalidBinding)?;
        let block_number = u64::from_str_radix(block_num_str.trim_start_matches("0x"), 16)
            .map_err(|_| DisclosureError::InvalidBinding)?;
        let block_hash: [u8; 32] = hex::decode(
            log.get("blockHash")
                .and_then(Value::as_str)
                .ok_or(DisclosureError::InvalidBinding)?
                .trim_start_matches("0x"),
        )
        .map_err(|_| DisclosureError::InvalidBinding)?
        .try_into()
        .map_err(|_| DisclosureError::InvalidBinding)?;
        let log_index = u64::from_str_radix(
            log.get("logIndex")
                .and_then(Value::as_str)
                .ok_or(DisclosureError::InvalidBinding)?
                .trim_start_matches("0x"),
            16,
        )
        .map_err(|_| DisclosureError::InvalidBinding)?;

        let topics = log
            .get("topics")
            .and_then(Value::as_array)
            .ok_or(DisclosureError::InvalidBinding)?;
        if topics.len() < 4 {
            return Err(DisclosureError::InvalidBinding);
        }

        let app_bytes = hex::decode(
            topics[1]
                .as_str()
                .unwrap_or_default()
                .trim_start_matches("0x"),
        )
        .map_err(|_| DisclosureError::InvalidBinding)?;
        let application_id: [u8; 32] = app_bytes
            .try_into()
            .map_err(|_| DisclosureError::InvalidBinding)?;

        let action_bytes = hex::decode(
            topics[2]
                .as_str()
                .unwrap_or_default()
                .trim_start_matches("0x"),
        )
        .map_err(|_| DisclosureError::InvalidBinding)?;
        let action_word: [u8; 32] = action_bytes
            .try_into()
            .map_err(|_| DisclosureError::InvalidBinding)?;
        let action = action_word[31];

        let user_bytes = hex::decode(
            topics[3]
                .as_str()
                .unwrap_or_default()
                .trim_start_matches("0x"),
        )
        .map_err(|_| DisclosureError::InvalidBinding)?;
        let mut authorized_user = [0u8; 20];
        if user_bytes.len() >= 32 {
            authorized_user.copy_from_slice(&user_bytes[12..32]);
        }

        let data_str = log
            .get("data")
            .and_then(Value::as_str)
            .ok_or(DisclosureError::InvalidBinding)?;
        let data_bytes = hex::decode(data_str.trim_start_matches("0x"))
            .map_err(|_| DisclosureError::InvalidBinding)?;

        if data_bytes.len() < 16 * 32 {
            return Err(DisclosureError::InvalidBinding);
        }

        let mut data_words = Vec::new();
        for chunk in data_bytes.chunks_exact(32) {
            let mut word = [0u8; 32];
            word.copy_from_slice(chunk);
            data_words.push(word);
        }

        let audit_commitment = data_words[11];
        let audit_ciphertext_hash = data_words[12];

        // Dynamic offset for envelope bytes
        let offset_word = data_words[15];
        let offset =
            u64::from_be_bytes(offset_word[24..32].try_into().unwrap_or_default()) as usize;
        let envelope = if data_bytes.len() >= offset + 32 {
            let len = u64::from_be_bytes(
                data_bytes[offset + 24..offset + 32]
                    .try_into()
                    .unwrap_or_default(),
            ) as usize;
            if data_bytes.len() >= offset + 32 + len {
                data_bytes[offset + 32..offset + 32 + len].to_vec()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        let key_version = Envelope::from_bytes(&envelope)
            .map(|e| e.key_version)
            .unwrap_or(1);

        let record = StoredAuditRecord {
            record_id: tx_hash,
            application_id,
            recorded_at: 0,
            chain_id: self.config.chain_id,
            pool: self.config.pool,
            pool_version: self.config.pool_version,
            key_version,
            action,
            action_reference: tx_hash,
            audit_data_commitment: audit_commitment,
            audit_ciphertext_hash,
            envelope,
            key_ref: "fuji-fixture".to_owned(),
            wrapped_key: Vec::new(),
            finalized: true,
            reorged: false,
        };

        let evidence = FujiWithdrawalEvidence {
            receipt_successful: true,
            transaction_hash: tx_hash,
            block_number,
            block_hash,
            log_index,
            current_block_number: head_block,
            pool: self.config.pool,
            application_id,
            action,
            authorized_user,
            pool_version: self.config.pool_version,
            audit_data_commitment: audit_commitment,
            audit_ciphertext_hash,
            action_reference: tx_hash,
            record,
        };

        Ok((evidence, tx_hash))
    }

    /// Update confirmations for all existing pending cases in the store.
    pub async fn update_confirmations(&self, current_head: u64) -> Result<(), DisclosureError> {
        let cases = self
            .store
            .list_cases(&self.config.application_id, &[])
            .await
            .map_err(|_| DisclosureError::Unavailable)?;
        for case in cases {
            if case.status == "pending_finality" && case.block_number > 0 {
                let confirmations = if current_head >= case.block_number {
                    current_head - case.block_number + 1
                } else {
                    0
                };
                if confirmations >= 12 {
                    self.store
                        .update_case_status(&case.case_id, "ready", confirmations)
                        .await
                        .map_err(|_| DisclosureError::Unavailable)?;
                } else {
                    self.store
                        .update_case_status(&case.case_id, "pending_finality", confirmations)
                        .await
                        .map_err(|_| DisclosureError::Unavailable)?;
                }
            }
        }
        Ok(())
    }

    /// Run a single poll cycle: get head, scan delta from cursor, update confirmations.
    pub async fn poll_cycle(&self) -> Result<usize, DisclosureError> {
        let head = self.current_block_number().await?;
        let poller_id = format!(
            "fuji:{}:0x{}",
            self.config.chain_id,
            hex::encode(self.config.pool)
        );
        let previous = self
            .store
            .get_checkpoint(
                &poller_id,
                self.config.chain_id,
                self.config.pool,
                self.config.application_id,
            )
            .await
            .map_err(|_| DisclosureError::Unavailable)?;
        let next_block = previous
            .as_ref()
            .map_or(self.deployment_block, |value| value.next_block);
        let from_block = next_block
            .saturating_sub(self.replay_window)
            .max(self.deployment_block);
        let to_block = head;

        let ingested = if from_block <= to_block {
            self.scan_range(from_block, to_block).await?
        } else {
            0
        };

        self.update_confirmations(head).await?;
        let block = self
            .rpc(
                "eth_getBlockByNumber",
                json!([format!("0x{head:x}"), false]),
            )
            .await?;
        let last_block_hash = block
            .get("hash")
            .and_then(Value::as_str)
            .and_then(|value| hex::decode(value.trim_start_matches("0x")).ok())
            .and_then(|value| value.try_into().ok());
        self.store
            .save_checkpoint(PollerCheckpoint {
                poller_id,
                chain_id: self.config.chain_id,
                pool: self.config.pool,
                application_id: self.config.application_id,
                next_block: head.saturating_add(1),
                last_block_hash,
                healthy: true,
                consecutive_failures: 0,
                last_error: None,
            })
            .await
            .map_err(|_| DisclosureError::Unavailable)?;
        Ok(ingested)
    }

    /// Spawn a background tokio task that runs poll_cycle periodically.
    pub fn start_background_loop(
        self: Arc<Self>,
        interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                if let Err(error) = self.poll_cycle().await {
                    let poller_id = format!(
                        "fuji:{}:0x{}",
                        self.config.chain_id,
                        hex::encode(self.config.pool)
                    );
                    let previous = self
                        .store
                        .get_checkpoint(
                            &poller_id,
                            self.config.chain_id,
                            self.config.pool,
                            self.config.application_id,
                        )
                        .await
                        .ok()
                        .flatten();
                    let failures = previous
                        .as_ref()
                        .map_or(1, |value| value.consecutive_failures.saturating_add(1));
                    let _ = self
                        .store
                        .save_checkpoint(PollerCheckpoint {
                            poller_id,
                            chain_id: self.config.chain_id,
                            pool: self.config.pool,
                            application_id: self.config.application_id,
                            next_block: previous
                                .as_ref()
                                .map_or(self.deployment_block, |value| value.next_block),
                            last_block_hash: previous.and_then(|value| value.last_block_hash),
                            healthy: false,
                            consecutive_failures: failures,
                            last_error: Some(json!({"code":error.as_code(),"stage":"poll_cycle"})),
                        })
                        .await;
                }
                tokio::time::sleep(interval).await;
            }
        })
    }
}
