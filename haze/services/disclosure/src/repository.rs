//! Async PostgreSQL persistence for the production compliance runtime.

use std::{collections::BTreeMap, sync::Arc};

use sqlx::{PgPool, Row, postgres::PgPoolOptions};

use crate::{
    access_log::{ComplianceAccessLogEntry, compute_entry_hash},
    auth::StoredSession,
    cases::{
        AuditorGrant, CaseScope, ComplianceCase, DEFAULT_DENIED_FIELDS, DEFAULT_GRANTED_FIELDS,
    },
    export::ComplianceExportBundle,
    fuji::FujiWithdrawalEvidence,
    store::{ComplianceStore, StoredChallenge, StoredDisclosureReceipt},
};

/// Runtime persistence. Memory is intentionally available only to tests and local fixtures.
#[derive(Clone)]
pub enum ComplianceRepository {
    /// Isolated in-memory test adapter.
    Memory(Arc<ComplianceStore>),
    /// Durable production adapter.
    Postgres(PostgresRepository),
}

impl From<Arc<ComplianceStore>> for ComplianceRepository {
    fn from(value: Arc<ComplianceStore>) -> Self {
        Self::Memory(value)
    }
}

impl From<PostgresRepository> for ComplianceRepository {
    fn from(value: PostgresRepository) -> Self {
        Self::Postgres(value)
    }
}

impl ComplianceRepository {
    /// Report database/migration readiness; memory is ready only in tests.
    pub async fn ready(&self) -> Result<bool, sqlx::Error> {
        match self {
            Self::Memory(_) => Ok(true),
            Self::Postgres(repo) => repo.ready().await,
        }
    }
    /// Generate a unique runtime ID.
    pub async fn next_id(&self, label: &[u8]) -> Result<[u8; 32], sqlx::Error> {
        match self {
            Self::Memory(store) => Ok(store.next_id(label)),
            Self::Postgres(repo) => repo.next_id(label).await,
        }
    }
    /// Save a challenge.
    pub async fn save_challenge(&self, value: StoredChallenge) -> Result<(), sqlx::Error> {
        match self {
            Self::Memory(store) => {
                store.save_challenge(value);
                Ok(())
            }
            Self::Postgres(repo) => repo.save_challenge(value).await,
        }
    }
    /// Consume a challenge once.
    pub async fn consume_challenge(
        &self,
        id: &[u8; 32],
    ) -> Result<Option<StoredChallenge>, sqlx::Error> {
        match self {
            Self::Memory(store) => Ok(store.consume_challenge(id)),
            Self::Postgres(repo) => repo.consume_challenge(id).await,
        }
    }
    /// Look up a grant.
    pub async fn get_grant(
        &self,
        wallet: &[u8; 20],
        app: &[u8; 32],
    ) -> Result<Option<AuditorGrant>, sqlx::Error> {
        match self {
            Self::Memory(store) => Ok(store.get_grant(wallet, app)),
            Self::Postgres(repo) => repo.get_grant(wallet, app).await,
        }
    }
    /// Save a session.
    pub async fn save_session(&self, value: StoredSession) -> Result<(), sqlx::Error> {
        match self {
            Self::Memory(store) => {
                store.save_session(value);
                Ok(())
            }
            Self::Postgres(repo) => repo.save_session(value).await,
        }
    }
    /// Load a session.
    pub async fn get_session(&self, hash: &[u8; 32]) -> Result<Option<StoredSession>, sqlx::Error> {
        match self {
            Self::Memory(store) => Ok(store.get_session(hash)),
            Self::Postgres(repo) => repo.get_session(hash).await,
        }
    }
    /// Delete a session.
    pub async fn delete_session(&self, hash: &[u8; 32]) -> Result<(), sqlx::Error> {
        match self {
            Self::Memory(store) => {
                store.delete_session(hash);
                Ok(())
            }
            Self::Postgres(repo) => repo.delete_session(hash).await,
        }
    }
    /// Save a case.
    pub async fn save_case(&self, value: ComplianceCase) -> Result<(), sqlx::Error> {
        match self {
            Self::Memory(store) => {
                store.save_case(value);
                Ok(())
            }
            Self::Postgres(repo) => repo.save_case(value).await,
        }
    }
    /// List cases.
    pub async fn list_cases(
        &self,
        app: &[u8; 32],
        assigned: &[String],
    ) -> Result<Vec<ComplianceCase>, sqlx::Error> {
        match self {
            Self::Memory(store) => Ok(store.list_cases(app, assigned)),
            Self::Postgres(repo) => repo.list_cases(app, assigned).await,
        }
    }
    /// Load one case for a specific application.
    pub async fn get_case_for_app(
        &self,
        app: &[u8; 32],
        id: &str,
    ) -> Result<Option<ComplianceCase>, sqlx::Error> {
        match self {
            Self::Memory(store) => Ok(store.get_case_for_app(app, id)),
            Self::Postgres(repo) => repo.get_case_for_app(app, id).await,
        }
    }
    /// Load one case.
    pub async fn get_case(&self, id: &str) -> Result<Option<ComplianceCase>, sqlx::Error> {
        match self {
            Self::Memory(store) => Ok(store.get_case(id)),
            Self::Postgres(repo) => repo.get_case(id).await,
        }
    }
    /// Save a disclosure receipt.
    pub async fn save_disclosure_receipt(
        &self,
        value: StoredDisclosureReceipt,
    ) -> Result<(), sqlx::Error> {
        match self {
            Self::Memory(store) => {
                store.save_disclosure_receipt(value);
                Ok(())
            }
            Self::Postgres(repo) => repo.save_disclosure_receipt(value).await,
        }
    }
    /// Load a disclosure receipt.
    pub async fn get_disclosure_receipt(
        &self,
        session_hash: &[u8; 32],
        app: &[u8; 32],
        case_id: &str,
    ) -> Result<Option<StoredDisclosureReceipt>, sqlx::Error> {
        match self {
            Self::Memory(store) => Ok(store.get_disclosure_receipt(session_hash, app, case_id)),
            Self::Postgres(repo) => {
                repo.get_disclosure_receipt(session_hash, app, case_id)
                    .await
            }
        }
    }
    /// Update case finality.
    pub async fn update_case_status(
        &self,
        id: &str,
        status: &str,
        confirmations: u64,
    ) -> Result<(), sqlx::Error> {
        match self {
            Self::Memory(store) => {
                store.update_case_status(id, status, confirmations);
                Ok(())
            }
            Self::Postgres(repo) => repo.update_case_status(id, status, confirmations).await,
        }
    }
    /// Save evidence.
    pub async fn save_evidence(&self, value: FujiWithdrawalEvidence) -> Result<(), sqlx::Error> {
        match self {
            Self::Memory(store) => {
                store.save_evidence(value.transaction_hash, value);
                Ok(())
            }
            Self::Postgres(repo) => repo.save_evidence(value).await,
        }
    }
    /// Atomically replace one replay window with its canonical withdrawal events.
    pub async fn replace_ingestion_range(
        &self,
        chain_id: u64,
        pool: [u8; 20],
        from_block: u64,
        to_block: u64,
        values: Vec<(ComplianceCase, FujiWithdrawalEvidence)>,
    ) -> Result<(), sqlx::Error> {
        match self {
            Self::Memory(store) => {
                for (case, evidence) in values {
                    store.save_case(case);
                    store.save_evidence(evidence.transaction_hash, evidence);
                }
                Ok(())
            }
            Self::Postgres(repo) => {
                repo.replace_ingestion_range(chain_id, pool, from_block, to_block, values)
                    .await
            }
        }
    }
    /// Load evidence.
    pub async fn get_evidence(
        &self,
        hash: &[u8; 32],
    ) -> Result<Vec<FujiWithdrawalEvidence>, sqlx::Error> {
        match self {
            Self::Memory(store) => Ok(store.get_evidence(hash).unwrap_or_default()),
            Self::Postgres(repo) => repo.get_evidence(hash).await,
        }
    }
    /// Save an export.
    pub async fn save_export(&self, value: ComplianceExportBundle) -> Result<(), sqlx::Error> {
        match self {
            Self::Memory(store) => {
                store.save_export(value);
                Ok(())
            }
            Self::Postgres(repo) => repo.save_export(value).await,
        }
    }
    /// Append access log.
    #[allow(clippy::too_many_arguments)]
    pub async fn append_access_log(
        &self,
        name: &str,
        app: &[u8; 32],
        case_id: Option<&str>,
        wallet: &[u8; 20],
        fields: Vec<String>,
        allowed: bool,
        at: u64,
    ) -> Result<ComplianceAccessLogEntry, sqlx::Error> {
        match self {
            Self::Memory(store) => {
                Ok(store.append_access_log(name, app, case_id, wallet, fields, allowed, at))
            }
            Self::Postgres(repo) => {
                repo.append_access_log(name, app, case_id, wallet, fields, allowed, at)
                    .await
            }
        }
    }
    /// List access log.
    pub async fn list_access_log(
        &self,
        app: &[u8; 32],
        case_id: Option<&str>,
    ) -> Result<Vec<ComplianceAccessLogEntry>, sqlx::Error> {
        match self {
            Self::Memory(store) => Ok(store.list_access_log(app, case_id)),
            Self::Postgres(repo) => repo.list_access_log(app, case_id).await,
        }
    }
    /// Load poller checkpoint (memory tests retain their legacy cursor).
    pub async fn get_checkpoint(
        &self,
        id: &str,
        chain_id: u64,
        pool: [u8; 20],
        app: [u8; 32],
    ) -> Result<Option<PollerCheckpoint>, sqlx::Error> {
        match self {
            Self::Memory(store) => {
                let cursor = store.get_cursor();
                Ok((cursor > 0).then_some(PollerCheckpoint {
                    poller_id: id.to_owned(),
                    chain_id,
                    pool,
                    application_id: app,
                    next_block: cursor + 1,
                    last_block_hash: None,
                    healthy: true,
                    consecutive_failures: 0,
                    last_error: None,
                }))
            }
            Self::Postgres(repo) => repo.get_checkpoint(id).await,
        }
    }
    /// Save poller checkpoint.
    pub async fn save_checkpoint(&self, value: PollerCheckpoint) -> Result<(), sqlx::Error> {
        match self {
            Self::Memory(store) => {
                store.set_cursor(value.next_block.saturating_sub(1));
                Ok(())
            }
            Self::Postgres(repo) => repo.save_checkpoint(value).await,
        }
    }
}

/// Durable Fuji poller progress and health state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PollerCheckpoint {
    /// Stable worker identifier.
    pub poller_id: String,
    /// EVM chain identifier.
    pub chain_id: u64,
    /// Contract address being scanned.
    pub pool: [u8; 20],
    /// Application event partition.
    pub application_id: [u8; 32],
    /// First block not yet committed.
    pub next_block: u64,
    /// Hash of the last committed canonical block.
    pub last_block_hash: Option<[u8; 32]>,
    /// Whether the latest poll completed successfully.
    pub healthy: bool,
    /// Number of consecutive failed poll attempts.
    pub consecutive_failures: u32,
    /// Redacted structured failure payload.
    pub last_error: Option<serde_json::Value>,
}

/// PostgreSQL-backed compliance repository.
#[derive(Clone, Debug)]
pub struct PostgresRepository {
    pool: PgPool,
}

impl PostgresRepository {
    /// Connect using a bounded pool suitable for the smallest Render service tier.
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await?;
        Ok(Self { pool })
    }

    /// Verify that the database is reachable and all runtime migrations exist.
    pub async fn ready(&self) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            "select count(*) from haze_schema_migrations where version = any($1)",
        )
        .bind(["0001", "0002", "0003", "0004"].as_slice())
        .fetch_one(&self.pool)
        .await?;
        let poller_healthy: bool = sqlx::query_scalar("select exists(select 1 from haze_compliance_poller_checkpoints where healthy=true and updated_at > now() - interval '30 seconds')")
            .fetch_one(&self.pool).await?;
        Ok(count == 4 && poller_healthy)
    }

    /// Apply the append-only migration history in order.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        for sql in [
            include_str!("../../../dev/postgres/migrations/0001_init.sql"),
            include_str!("../../../dev/postgres/migrations/0002_ops.sql"),
            include_str!("../../../dev/postgres/migrations/0003_compliance_portal.sql"),
            include_str!("../../../dev/postgres/migrations/0004_compliance_runtime.sql"),
            include_str!("../../../dev/postgres/migrations/0005_fuji_compliance_remediation.sql"),
        ] {
            sqlx::raw_sql(sql).execute(&self.pool).await?;
        }
        for version in ["0001", "0002", "0003", "0004", "0005"] {
            sqlx::query(
                "insert into haze_schema_migrations(version) values ($1) on conflict do nothing",
            )
            .bind(version)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    /// Remove compliance tables from an isolated test database.
    #[doc(hidden)]
    pub async fn reset_for_test(&self) -> Result<(), sqlx::Error> {
        sqlx::raw_sql(
            "drop table if exists haze_compliance_disclosure_receipts, haze_compliance_case_assignments, haze_compliance_evidence, haze_compliance_poller_checkpoints, haze_compliance_access_log_heads, haze_compliance_export_counters, haze_compliance_access_log, haze_compliance_exports, haze_compliance_cases, haze_compliance_sessions, haze_compliance_grants, haze_compliance_challenges cascade",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Idempotently create or refresh the dedicated Fuji auditor grant.
    pub async fn seed_auditor_grant(
        &self,
        application_id: [u8; 32],
        wallet: [u8; 20],
    ) -> Result<(), sqlx::Error> {
        let grant_id = haze_protocol::keccak::keccak256(b"seed_fuji_grant");
        sqlx::query(
            "insert into haze_compliance_grants (grant_id, wallet, application_id, role, granted_fields, denied_fields, assigned_cases, revoked, expires_at) values ($1,$2,$3,$4,$5,$6,$7,false,to_timestamp($8)) on conflict (grant_id) do update set wallet=excluded.wallet, application_id=excluded.application_id, role=excluded.role, granted_fields=excluded.granted_fields, denied_fields=excluded.denied_fields, revoked=false, expires_at=excluded.expires_at",
        )
        .bind(grant_id.as_slice())
        .bind(wallet.as_slice())
        .bind(application_id.as_slice())
        .bind("application-auditor")
        .bind(DEFAULT_GRANTED_FIELDS.as_slice())
        .bind(DEFAULT_DENIED_FIELDS.as_slice())
        .bind(Vec::<String>::new())
        .bind(2_147_483_647_i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Look up the active grant bound to a wallet and application.
    pub async fn get_grant(
        &self,
        wallet: &[u8; 20],
        application_id: &[u8; 32],
    ) -> Result<Option<AuditorGrant>, sqlx::Error> {
        let row = sqlx::query("select grant_id, wallet, application_id, role, assigned_cases, granted_fields, denied_fields, extract(epoch from expires_at)::bigint as expires_at, revoked from haze_compliance_grants where wallet=$1 and application_id=$2 order by created_at desc limit 1")
            .bind(wallet.as_slice())
            .bind(application_id.as_slice())
            .fetch_optional(&self.pool)
            .await?;
        row.map(grant_from_row).transpose()
    }

    /// Persist a one-time challenge.
    pub async fn save_challenge(&self, value: StoredChallenge) -> Result<(), sqlx::Error> {
        sqlx::query("insert into haze_compliance_challenges (challenge_id,nonce,domain,uri,statement,wallet,application_id,issued_at,expires_at,consumed,message) values ($1,$2,$3,$4,$5,$6,$7,to_timestamp($8),to_timestamp($9),$10,$11)")
            .bind(value.challenge_id.as_slice()).bind(value.nonce).bind(value.domain)
            .bind(value.uri).bind(value.statement).bind(value.wallet.as_slice())
            .bind(value.application_id.as_slice()).bind(as_i64(value.issued_at)?)
            .bind(as_i64(value.expires_at)?).bind(value.consumed).bind(value.message)
            .execute(&self.pool).await?;
        Ok(())
    }

    /// Atomically consume a challenge once.
    pub async fn consume_challenge(
        &self,
        id: &[u8; 32],
    ) -> Result<Option<StoredChallenge>, sqlx::Error> {
        let row = sqlx::query("update haze_compliance_challenges set consumed=true where challenge_id=$1 and consumed=false returning challenge_id,nonce,domain,uri,statement,wallet,application_id,extract(epoch from issued_at)::bigint issued_at,extract(epoch from expires_at)::bigint expires_at,consumed,message")
            .bind(id.as_slice()).fetch_optional(&self.pool).await?;
        row.map(challenge_from_row).transpose()
    }

    /// Persist an authenticated session.
    pub async fn save_session(&self, value: StoredSession) -> Result<(), sqlx::Error> {
        sqlx::query("insert into haze_compliance_sessions (session_hash,wallet,application_id,role,grant_id,expires_at) values ($1,$2,$3,$4,$5,to_timestamp($6)) on conflict (session_hash) do update set expires_at=excluded.expires_at")
            .bind(value.session_hash.as_slice()).bind(value.wallet.as_slice())
            .bind(value.application_id.as_slice()).bind(value.role).bind(value.grant_id.as_slice())
            .bind(as_i64(value.expires_at)?).execute(&self.pool).await?;
        Ok(())
    }

    /// Retrieve an authenticated session.
    pub async fn get_session(&self, hash: &[u8; 32]) -> Result<Option<StoredSession>, sqlx::Error> {
        let row = sqlx::query("select session_hash,wallet,application_id,role,grant_id,extract(epoch from expires_at)::bigint expires_at from haze_compliance_sessions where session_hash=$1")
            .bind(hash.as_slice()).fetch_optional(&self.pool).await?;
        row.map(session_from_row).transpose()
    }

    /// Revoke a session.
    pub async fn delete_session(&self, hash: &[u8; 32]) -> Result<(), sqlx::Error> {
        sqlx::query("delete from haze_compliance_sessions where session_hash=$1")
            .bind(hash.as_slice())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Idempotently insert/update an ingested case.
    pub async fn save_case(&self, case: ComplianceCase) -> Result<(), sqlx::Error> {
        let app = decode_fixed::<32>(&case.application_id)?;
        let tx = decode_fixed::<32>(&case.transaction_hash)?;
        sqlx::query("insert into haze_compliance_cases (case_id,title,application_id,transaction_hash,granted_fields,denied_fields,status,block_number,confirmations,sync_status,integrity_status) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) on conflict (case_id) do update set title=excluded.title,status=excluded.status,block_number=excluded.block_number,confirmations=greatest(haze_compliance_cases.confirmations,excluded.confirmations),sync_status=excluded.sync_status,integrity_status=excluded.integrity_status")
            .bind(&case.case_id)
            .bind(&case.title)
            .bind(app.as_slice())
            .bind(tx.as_slice())
            .bind(&case.granted_fields)
            .bind(&case.denied_fields)
            .bind(&case.status)
            .bind(i64::try_from(case.block_number).map_err(|error| sqlx::Error::Decode(Box::new(error)))?)
            .bind(i64::try_from(case.confirmations).map_err(|error| sqlx::Error::Decode(Box::new(error)))?)
            .bind(&case.sync_status)
            .bind(&case.integrity_status)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// List cases authorized by the grant assignment set.
    pub async fn list_cases(
        &self,
        application_id: &[u8; 32],
        assigned_case_ids: &[String],
    ) -> Result<Vec<ComplianceCase>, sqlx::Error> {
        let rows = sqlx::query("select case_id,title,application_id,transaction_hash,granted_fields,denied_fields,status,block_number,confirmations,sync_status,integrity_status from haze_compliance_cases where application_id=$1 and (cardinality($2::text[]) = 0 or case_id = any($2::text[])) and orphaned=false order by block_number desc, case_id")
            .bind(application_id.as_slice())
            .bind(assigned_case_ids)
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().map(case_from_row).collect()
    }

    /// Retrieve one non-orphaned case for a specific application.
    pub async fn get_case_for_app(
        &self,
        application_id: &[u8; 32],
        case_id: &str,
    ) -> Result<Option<ComplianceCase>, sqlx::Error> {
        let row = sqlx::query("select case_id,title,application_id,transaction_hash,granted_fields,denied_fields,status,block_number,confirmations,sync_status,integrity_status from haze_compliance_cases where application_id=$1 and case_id=$2 and orphaned=false")
            .bind(application_id.as_slice())
            .bind(case_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(case_from_row).transpose()
    }

    /// Retrieve one non-orphaned case.
    pub async fn get_case(&self, case_id: &str) -> Result<Option<ComplianceCase>, sqlx::Error> {
        let row = sqlx::query("select case_id,title,application_id,transaction_hash,granted_fields,denied_fields,status,block_number,confirmations,sync_status,integrity_status from haze_compliance_cases where case_id=$1 and orphaned=false")
            .bind(case_id).fetch_optional(&self.pool).await?;
        row.map(case_from_row).transpose()
    }

    /// Save a disclosure receipt.
    pub async fn save_disclosure_receipt(
        &self,
        value: StoredDisclosureReceipt,
    ) -> Result<(), sqlx::Error> {
        let fields_json = serde_json::to_value(&value.disclosed_fields).map_err(json_error)?;
        sqlx::query("insert into haze_compliance_disclosure_receipts (receipt_id,session_hash,application_id,case_id,evidence_digest,disclosed_fields,created_at,expires_at) values ($1,$2,$3,$4,$5,$6,to_timestamp($7),to_timestamp($8)) on conflict (session_hash,application_id,case_id,evidence_digest) do update set expires_at=excluded.expires_at")
            .bind(value.receipt_id.as_slice())
            .bind(value.session_hash.as_slice())
            .bind(value.application_id.as_slice())
            .bind(&value.case_id)
            .bind(value.evidence_digest.as_slice())
            .bind(fields_json)
            .bind(as_i64(value.created_at)?)
            .bind(as_i64(value.expires_at)?)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Load a disclosure receipt.
    pub async fn get_disclosure_receipt(
        &self,
        session_hash: &[u8; 32],
        application_id: &[u8; 32],
        case_id: &str,
    ) -> Result<Option<StoredDisclosureReceipt>, sqlx::Error> {
        let row = sqlx::query("select receipt_id,session_hash,application_id,case_id,evidence_digest,disclosed_fields,extract(epoch from created_at)::bigint as created_at,extract(epoch from expires_at)::bigint as expires_at from haze_compliance_disclosure_receipts where session_hash=$1 and application_id=$2 and case_id=$3 and expires_at > now()")
            .bind(session_hash.as_slice())
            .bind(application_id.as_slice())
            .bind(case_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(receipt_from_row).transpose()
    }

    /// Update finality for an existing case without allowing confirmation regression.
    pub async fn update_case_status(
        &self,
        case_id: &str,
        status: &str,
        confirmations: u64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("update haze_compliance_cases set status=$2, confirmations=greatest(confirmations,$3), finalized_at=case when $2='ready' then coalesce(finalized_at,now()) else finalized_at end where case_id=$1")
            .bind(case_id).bind(status).bind(as_i64(confirmations)?).execute(&self.pool).await?;
        Ok(())
    }

    /// Idempotently persist one event evidence record with canonical provenance.
    pub async fn save_evidence(&self, value: FujiWithdrawalEvidence) -> Result<(), sqlx::Error> {
        let payload = serde_json::to_value(&value).map_err(json_error)?;
        sqlx::query("insert into haze_compliance_evidence (chain_id,pool,application_id,transaction_hash,log_index,block_number,block_hash,action,authorized_user,pool_version,audit_data_commitment,audit_ciphertext_hash,action_reference,envelope,key_version,finality_status,integrity_status,orphaned,payload) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,false,$18) on conflict (chain_id,pool,transaction_hash,log_index) do update set block_number=excluded.block_number,block_hash=excluded.block_hash,finality_status=excluded.finality_status,integrity_status=excluded.integrity_status,orphaned=false,payload=excluded.payload")
            .bind(as_i64(value.record.chain_id)?).bind(value.pool.as_slice())
            .bind(value.application_id.as_slice()).bind(value.transaction_hash.as_slice())
            .bind(as_i64(value.log_index)?).bind(as_i64(value.block_number)?)
            .bind(value.block_hash.as_slice()).bind(i16::from(value.action))
            .bind(value.authorized_user.as_slice()).bind(value.pool_version.as_slice())
            .bind(value.audit_data_commitment.as_slice()).bind(value.audit_ciphertext_hash.as_slice())
            .bind(value.action_reference.as_slice()).bind(&value.record.envelope)
            .bind(as_i64(value.record.key_version)?)
            .bind(if value.current_block_number.saturating_sub(value.block_number)+1 >= 12 { "ready" } else { "pending_finality" })
            .bind("pending").bind(payload).execute(&self.pool).await?;
        Ok(())
    }

    /// Atomically reconcile a bounded replay range, orphaning events no longer canonical.
    pub async fn replace_ingestion_range(
        &self,
        chain_id: u64,
        pool: [u8; 20],
        from_block: u64,
        to_block: u64,
        values: Vec<(ComplianceCase, FujiWithdrawalEvidence)>,
    ) -> Result<(), sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("update haze_compliance_evidence set orphaned=true, finality_status='orphaned' where chain_id=$1 and pool=$2 and block_number between $3 and $4")
            .bind(as_i64(chain_id)?).bind(pool.as_slice()).bind(as_i64(from_block)?).bind(as_i64(to_block)?)
            .execute(&mut *transaction).await?;
        sqlx::query("update haze_compliance_cases set orphaned=true, status='orphaned', integrity_status='failed' where transaction_hash in (select transaction_hash from haze_compliance_evidence where chain_id=$1 and pool=$2 and block_number between $3 and $4 and orphaned=true)")
            .bind(as_i64(chain_id)?).bind(pool.as_slice()).bind(as_i64(from_block)?).bind(as_i64(to_block)?)
            .execute(&mut *transaction).await?;

        for (case, evidence) in values {
            let application_id = decode_fixed::<32>(&case.application_id)?;
            let transaction_hash = decode_fixed::<32>(&case.transaction_hash)?;
            sqlx::query("insert into haze_compliance_cases (case_id,title,application_id,transaction_hash,granted_fields,denied_fields,status,block_number,block_hash,log_index,confirmations,sync_status,integrity_status,orphaned) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,false) on conflict (case_id) do update set title=excluded.title,status=excluded.status,block_number=excluded.block_number,block_hash=excluded.block_hash,log_index=excluded.log_index,confirmations=excluded.confirmations,sync_status=excluded.sync_status,integrity_status=excluded.integrity_status,orphaned=false")
                .bind(&case.case_id).bind(&case.title).bind(application_id.as_slice()).bind(transaction_hash.as_slice())
                .bind(&case.granted_fields).bind(&case.denied_fields).bind(&case.status).bind(as_i64(case.block_number)?)
                .bind(evidence.block_hash.as_slice()).bind(as_i64(evidence.log_index)?).bind(as_i64(case.confirmations)?)
                .bind(&case.sync_status).bind(&case.integrity_status).execute(&mut *transaction).await?;

            let payload = serde_json::to_value(&evidence).map_err(json_error)?;
            sqlx::query("insert into haze_compliance_evidence (chain_id,pool,application_id,transaction_hash,log_index,block_number,block_hash,action,authorized_user,pool_version,audit_data_commitment,audit_ciphertext_hash,action_reference,envelope,key_version,finality_status,integrity_status,orphaned,payload) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,false,$18) on conflict (chain_id,pool,transaction_hash,log_index) do update set block_number=excluded.block_number,block_hash=excluded.block_hash,finality_status=excluded.finality_status,integrity_status=excluded.integrity_status,orphaned=false,payload=excluded.payload")
                .bind(as_i64(evidence.record.chain_id)?).bind(evidence.pool.as_slice()).bind(evidence.application_id.as_slice())
                .bind(evidence.transaction_hash.as_slice()).bind(as_i64(evidence.log_index)?).bind(as_i64(evidence.block_number)?)
                .bind(evidence.block_hash.as_slice()).bind(i16::from(evidence.action)).bind(evidence.authorized_user.as_slice())
                .bind(evidence.pool_version.as_slice()).bind(evidence.audit_data_commitment.as_slice()).bind(evidence.audit_ciphertext_hash.as_slice())
                .bind(evidence.action_reference.as_slice()).bind(&evidence.record.envelope).bind(as_i64(evidence.record.key_version)?)
                .bind(if evidence.current_block_number.saturating_sub(evidence.block_number) + 1 >= 12 { "ready" } else { "pending_finality" })
                .bind("pending").bind(payload).execute(&mut *transaction).await?;
        }
        transaction.commit().await
    }

    /// Load canonical evidence candidates for one transaction.
    pub async fn get_evidence(
        &self,
        hash: &[u8; 32],
    ) -> Result<Vec<FujiWithdrawalEvidence>, sqlx::Error> {
        let values: Vec<serde_json::Value> = sqlx::query_scalar("select payload from haze_compliance_evidence where transaction_hash=$1 and orphaned=false order by log_index")
            .bind(hash.as_slice()).fetch_all(&self.pool).await?;
        values
            .into_iter()
            .map(|value| serde_json::from_value(value).map_err(json_error))
            .collect()
    }

    /// List the immutable access chain for an application and optional case.
    pub async fn list_access_log(
        &self,
        application_id: &[u8; 32],
        case_id: Option<&str>,
    ) -> Result<Vec<ComplianceAccessLogEntry>, sqlx::Error> {
        let rows = sqlx::query("select application_sequence as seq,prev_hash,entry_hash,name,application_id,case_id,wallet,fields,allowed,extract(epoch from at)::bigint at from haze_compliance_access_log where application_id=$1 and ($2::text is null or case_id=$2) order by application_sequence")
            .bind(application_id.as_slice()).bind(case_id).fetch_all(&self.pool).await?;
        rows.into_iter().map(access_from_row).collect()
    }

    /// Return the current application access-chain head.
    pub async fn get_access_log_head(
        &self,
        application_id: &[u8; 32],
    ) -> Result<String, sqlx::Error> {
        let hash: Option<Vec<u8>> = sqlx::query_scalar(
            "select entry_hash from haze_compliance_access_log_heads where application_id=$1",
        )
        .bind(application_id.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        Ok(hash
            .map(|bytes| format!("0x{}", hex::encode(bytes)))
            .unwrap_or_else(|| hex32([0; 32])))
    }

    /// Allocate a restart-safe identifier from an application-independent sequence.
    pub async fn next_id(&self, label: &[u8]) -> Result<[u8; 32], sqlx::Error> {
        let value: i64 = sqlx::query_scalar("select nextval('haze_compliance_runtime_id_seq')")
            .fetch_one(&self.pool)
            .await?;
        let mut material = label.to_vec();
        material.extend_from_slice(&value.to_be_bytes());
        Ok(haze_protocol::keccak::keccak256(&material))
    }

    /// Persist a signed export.
    pub async fn save_export(&self, value: ComplianceExportBundle) -> Result<(), sqlx::Error> {
        sqlx::query("insert into haze_compliance_exports (export_id,case_id,record_id,subject,token_id,fields,provenance,signature,signing_key_id,expires_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,to_timestamp($10)) on conflict (export_id) do nothing")
            .bind(decode_fixed::<32>(&value.export_id)?.as_slice()).bind(value.case_id)
            .bind(decode_fixed::<32>(&value.record_id)?.as_slice()).bind(decode_fixed::<20>(&value.subject)?.as_slice())
            .bind(Vec::<u8>::new()).bind(serde_json::to_value(value.fields).map_err(json_error)?)
            .bind(serde_json::to_value(value.provenance).map_err(json_error)?)
            .bind(decode_fixed::<32>(&value.signature)?.as_slice()).bind(value.signing_key_id)
            .bind(as_i64(value.expires_at)?).execute(&self.pool).await?;
        Ok(())
    }

    /// Append one hash-chained access record while serializing writers per application.
    #[allow(clippy::too_many_arguments)]
    pub async fn append_access_log(
        &self,
        name: &str,
        application_id: &[u8; 32],
        case_id: Option<&str>,
        wallet: &[u8; 20],
        fields: Vec<String>,
        allowed: bool,
        at: u64,
    ) -> Result<ComplianceAccessLogEntry, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("insert into haze_compliance_access_log_heads(application_id,sequence,entry_hash) values ($1,0,decode(repeat('00',32),'hex')) on conflict do nothing")
            .bind(application_id.as_slice()).execute(&mut *tx).await?;
        let head = sqlx::query("select sequence,entry_hash from haze_compliance_access_log_heads where application_id=$1 for update")
            .bind(application_id.as_slice()).fetch_one(&mut *tx).await?;
        let seq = u64::try_from(head.try_get::<i64, _>("sequence")? + 1).map_err(decode_error)?;
        let prev: [u8; 32] = head
            .try_get::<Vec<u8>, _>("entry_hash")?
            .try_into()
            .map_err(|_| sqlx::Error::Decode("invalid head".into()))?;
        let hash = compute_entry_hash(
            seq,
            &prev,
            name,
            application_id,
            case_id,
            wallet,
            &fields,
            allowed,
            at,
        );
        sqlx::query("insert into haze_compliance_access_log(application_sequence,prev_hash,entry_hash,name,application_id,case_id,wallet,fields,allowed,at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,to_timestamp($10))")
            .bind(as_i64(seq)?).bind(prev.as_slice()).bind(hash.as_slice()).bind(name)
            .bind(application_id.as_slice()).bind(case_id).bind(wallet.as_slice())
            .bind(serde_json::to_string(&fields).map_err(json_error)?).bind(allowed).bind(as_i64(at)?)
            .execute(&mut *tx).await?;
        sqlx::query("update haze_compliance_access_log_heads set sequence=$2,entry_hash=$3,updated_at=now() where application_id=$1")
            .bind(application_id.as_slice()).bind(as_i64(seq)?).bind(hash.as_slice()).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(ComplianceAccessLogEntry {
            seq,
            prev_hash: hex32(prev),
            entry_hash: hex32(hash),
            name: name.to_owned(),
            application_id: hex32(*application_id),
            case_id: case_id.map(str::to_owned),
            wallet: format!("0x{}", hex::encode(wallet)),
            fields,
            allowed,
            at,
        })
    }

    /// Upsert the durable scan checkpoint and health state.
    pub async fn save_checkpoint(&self, checkpoint: PollerCheckpoint) -> Result<(), sqlx::Error> {
        sqlx::query("insert into haze_compliance_poller_checkpoints (poller_id,chain_id,pool,application_id,next_block,last_block_hash,last_success_at,last_error,consecutive_failures,healthy,updated_at) values ($1,$2,$3,$4,$5,$6,case when $10 then now() else null end,$7,$8,$9,now()) on conflict (poller_id) do update set next_block=excluded.next_block,last_block_hash=excluded.last_block_hash,last_success_at=case when excluded.healthy then now() else haze_compliance_poller_checkpoints.last_success_at end,last_error=excluded.last_error,consecutive_failures=excluded.consecutive_failures,healthy=excluded.healthy,updated_at=now()")
            .bind(&checkpoint.poller_id)
            .bind(i64::try_from(checkpoint.chain_id).map_err(|error| sqlx::Error::Decode(Box::new(error)))?)
            .bind(checkpoint.pool.as_slice())
            .bind(checkpoint.application_id.as_slice())
            .bind(i64::try_from(checkpoint.next_block).map_err(|error| sqlx::Error::Decode(Box::new(error)))?)
            .bind(checkpoint.last_block_hash.map(|hash| hash.to_vec()))
            .bind(checkpoint.last_error)
            .bind(i32::try_from(checkpoint.consecutive_failures).map_err(|error| sqlx::Error::Decode(Box::new(error)))?)
            .bind(checkpoint.healthy)
            .bind(checkpoint.healthy)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Load a durable scan checkpoint.
    pub async fn get_checkpoint(
        &self,
        poller_id: &str,
    ) -> Result<Option<PollerCheckpoint>, sqlx::Error> {
        let row = sqlx::query("select poller_id,chain_id,pool,application_id,next_block,last_block_hash,healthy,consecutive_failures,last_error from haze_compliance_poller_checkpoints where poller_id=$1")
            .bind(poller_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(checkpoint_from_row).transpose()
    }
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], sqlx::Error> {
    hex::decode(value.trim_start_matches("0x"))
        .map_err(|error| sqlx::Error::Decode(Box::new(error)))?
        .try_into()
        .map_err(|_| sqlx::Error::Decode("invalid fixed-width hex".into()))
}

fn as_i64(value: u64) -> Result<i64, sqlx::Error> {
    i64::try_from(value).map_err(decode_error)
}

fn decode_error(error: impl std::error::Error + Send + Sync + 'static) -> sqlx::Error {
    sqlx::Error::Decode(Box::new(error))
}

fn json_error(error: serde_json::Error) -> sqlx::Error {
    decode_error(error)
}

fn hex32(value: [u8; 32]) -> String {
    format!("0x{}", hex::encode(value))
}

fn fixed_from_row<const N: usize>(
    row: &sqlx::postgres::PgRow,
    name: &str,
) -> Result<[u8; N], sqlx::Error> {
    row.try_get::<Vec<u8>, _>(name)?
        .try_into()
        .map_err(|_| sqlx::Error::Decode(format!("invalid {name} width").into()))
}

fn grant_from_row(row: sqlx::postgres::PgRow) -> Result<AuditorGrant, sqlx::Error> {
    let scope_kind: Option<String> = row.try_get("scope_kind").ok();
    let assigned_cases: Vec<String> = row.try_get("assigned_cases").unwrap_or_default();
    let case_scope = match scope_kind.as_deref() {
        Some("explicit_cases") => CaseScope::ExplicitCases {
            case_ids: assigned_cases.clone(),
        },
        Some("all_application_cases") => CaseScope::AllApplicationCases,
        _ => {
            if assigned_cases.is_empty() {
                CaseScope::AllApplicationCases
            } else {
                CaseScope::ExplicitCases {
                    case_ids: assigned_cases.clone(),
                }
            }
        }
    };

    Ok(AuditorGrant {
        grant_id: fixed_from_row(&row, "grant_id")?,
        wallet: fixed_from_row(&row, "wallet")?,
        application_id: fixed_from_row(&row, "application_id")?,
        role: row.try_get("role")?,
        case_scope,
        assigned_cases,
        granted_fields: row.try_get("granted_fields")?,
        denied_fields: row.try_get("denied_fields")?,
        expires_at: u64::try_from(row.try_get::<i64, _>("expires_at")?)
            .map_err(|error| sqlx::Error::Decode(Box::new(error)))?,
        revoked: row.try_get("revoked")?,
    })
}

fn receipt_from_row(row: sqlx::postgres::PgRow) -> Result<StoredDisclosureReceipt, sqlx::Error> {
    let fields_value: serde_json::Value = row.try_get("disclosed_fields")?;
    let disclosed_fields: BTreeMap<String, String> =
        serde_json::from_value(fields_value).map_err(json_error)?;
    Ok(StoredDisclosureReceipt {
        receipt_id: fixed_from_row(&row, "receipt_id")?,
        session_hash: fixed_from_row(&row, "session_hash")?,
        application_id: fixed_from_row(&row, "application_id")?,
        case_id: row.try_get("case_id")?,
        evidence_digest: fixed_from_row(&row, "evidence_digest")?,
        disclosed_fields,
        created_at: u64::try_from(row.try_get::<i64, _>("created_at")?).map_err(decode_error)?,
        expires_at: u64::try_from(row.try_get::<i64, _>("expires_at")?).map_err(decode_error)?,
    })
}

fn challenge_from_row(row: sqlx::postgres::PgRow) -> Result<StoredChallenge, sqlx::Error> {
    Ok(StoredChallenge {
        challenge_id: fixed_from_row(&row, "challenge_id")?,
        nonce: row.try_get("nonce")?,
        domain: row.try_get("domain")?,
        uri: row.try_get("uri")?,
        statement: row.try_get("statement")?,
        wallet: fixed_from_row(&row, "wallet")?,
        application_id: fixed_from_row(&row, "application_id")?,
        issued_at: u64::try_from(row.try_get::<i64, _>("issued_at")?).map_err(decode_error)?,
        expires_at: u64::try_from(row.try_get::<i64, _>("expires_at")?).map_err(decode_error)?,
        consumed: row.try_get("consumed")?,
        message: row.try_get("message")?,
    })
}

fn session_from_row(row: sqlx::postgres::PgRow) -> Result<StoredSession, sqlx::Error> {
    Ok(StoredSession {
        session_hash: fixed_from_row(&row, "session_hash")?,
        wallet: fixed_from_row(&row, "wallet")?,
        application_id: fixed_from_row(&row, "application_id")?,
        role: row.try_get("role")?,
        grant_id: fixed_from_row(&row, "grant_id")?,
        expires_at: u64::try_from(row.try_get::<i64, _>("expires_at")?).map_err(decode_error)?,
    })
}

fn access_from_row(row: sqlx::postgres::PgRow) -> Result<ComplianceAccessLogEntry, sqlx::Error> {
    let fields: String = row.try_get("fields")?;
    Ok(ComplianceAccessLogEntry {
        seq: u64::try_from(row.try_get::<i64, _>("seq")?).map_err(decode_error)?,
        prev_hash: format!("0x{}", hex::encode(row.try_get::<Vec<u8>, _>("prev_hash")?)),
        entry_hash: format!(
            "0x{}",
            hex::encode(row.try_get::<Vec<u8>, _>("entry_hash")?)
        ),
        name: row.try_get("name")?,
        application_id: format!(
            "0x{}",
            hex::encode(row.try_get::<Vec<u8>, _>("application_id")?)
        ),
        case_id: row.try_get("case_id")?,
        wallet: format!("0x{}", hex::encode(row.try_get::<Vec<u8>, _>("wallet")?)),
        fields: serde_json::from_str(&fields).map_err(json_error)?,
        allowed: row.try_get("allowed")?,
        at: u64::try_from(row.try_get::<i64, _>("at")?).map_err(decode_error)?,
    })
}

fn case_from_row(row: sqlx::postgres::PgRow) -> Result<ComplianceCase, sqlx::Error> {
    Ok(ComplianceCase {
        case_id: row.try_get("case_id")?,
        title: row.try_get("title")?,
        application_id: format!(
            "0x{}",
            hex::encode(row.try_get::<Vec<u8>, _>("application_id")?)
        ),
        transaction_hash: format!(
            "0x{}",
            hex::encode(row.try_get::<Vec<u8>, _>("transaction_hash")?)
        ),
        granted_fields: row.try_get("granted_fields")?,
        denied_fields: row.try_get("denied_fields")?,
        status: row.try_get("status")?,
        block_number: u64::try_from(row.try_get::<i64, _>("block_number")?)
            .map_err(|error| sqlx::Error::Decode(Box::new(error)))?,
        confirmations: u64::try_from(row.try_get::<i64, _>("confirmations")?)
            .map_err(|error| sqlx::Error::Decode(Box::new(error)))?,
        sync_status: row.try_get("sync_status")?,
        integrity_status: row.try_get("integrity_status")?,
    })
}

fn checkpoint_from_row(row: sqlx::postgres::PgRow) -> Result<PollerCheckpoint, sqlx::Error> {
    Ok(PollerCheckpoint {
        poller_id: row.try_get("poller_id")?,
        chain_id: u64::try_from(row.try_get::<i64, _>("chain_id")?)
            .map_err(|error| sqlx::Error::Decode(Box::new(error)))?,
        pool: fixed_from_row(&row, "pool")?,
        application_id: fixed_from_row(&row, "application_id")?,
        next_block: u64::try_from(row.try_get::<i64, _>("next_block")?)
            .map_err(|error| sqlx::Error::Decode(Box::new(error)))?,
        last_block_hash: row
            .try_get::<Option<Vec<u8>>, _>("last_block_hash")?
            .map(|value| {
                value
                    .try_into()
                    .map_err(|_| sqlx::Error::Decode("invalid block hash width".into()))
            })
            .transpose()?,
        healthy: row.try_get("healthy")?,
        consecutive_failures: u32::try_from(row.try_get::<i32, _>("consecutive_failures")?)
            .map_err(|error| sqlx::Error::Decode(Box::new(error)))?,
        last_error: row.try_get("last_error")?,
    })
}
