//! PostgreSQL persistence, restart, replay, and concurrency integration tests.

use haze_disclosure::{
    access_log::verify_access_log_chain,
    cases::{DEFAULT_GRANTED_FIELDS, create_withdrawal_case},
    repository::{PollerCheckpoint, PostgresRepository},
};
use std::sync::OnceLock;

fn database_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn database_url() -> Option<String> {
    std::env::var("HAZE_TEST_DATABASE_URL").ok()
}

#[tokio::test]
async fn concurrent_access_log_writers_remain_one_immutable_chain() {
    let _guard = database_lock().lock().await;
    let Some(url) = std::env::var("HAZE_TEST_DATABASE_URL").ok() else {
        return;
    };
    let repository = PostgresRepository::connect(&url).await.expect("connect");
    repository.reset_for_test().await.expect("reset");
    repository.migrate().await.expect("migrate");
    let app = [0x11; 32];
    let mut writers = Vec::new();
    for at in 1..=16 {
        let repository = repository.clone();
        writers.push(tokio::spawn(async move {
            repository
                .append_access_log(
                    "query",
                    &app,
                    Some("case-1"),
                    &[0xaa; 20],
                    vec!["tx_hash".into()],
                    true,
                    at,
                )
                .await
                .expect("append")
        }));
    }
    let mut entries = Vec::new();
    for writer in writers {
        entries.push(writer.await.expect("join"));
    }
    entries.sort_by_key(|entry| entry.seq);
    assert_eq!(entries.len(), 16);
    verify_access_log_chain(&entries).expect("valid chain");
}

#[tokio::test]
async fn access_log_sequences_are_independent_across_applications() {
    let _guard = database_lock().lock().await;
    let Some(url) = database_url() else { return };
    let repository = PostgresRepository::connect(&url).await.expect("connect");
    repository.reset_for_test().await.expect("reset");
    repository.migrate().await.expect("migrate");

    for app in [[0x11; 32], [0x22; 32]] {
        let first = repository
            .append_access_log(
                "query",
                &app,
                None,
                &[0xaa; 20],
                vec!["tx_hash".into()],
                true,
                1,
            )
            .await
            .expect("append");
        assert_eq!(first.seq, 1);
    }
}

#[tokio::test]
async fn restart_preserves_grant_case_and_checkpoint_without_duplicate_replay() {
    let _guard = database_lock().lock().await;
    let Some(database_url) = database_url() else {
        eprintln!("HAZE_TEST_DATABASE_URL not set; PostgreSQL integration test skipped");
        return;
    };
    let app = [0x11; 32];
    let wallet = [0x22; 20];
    let tx_hash = [0x33; 32];

    let repository = PostgresRepository::connect(&database_url)
        .await
        .expect("connect");
    repository.reset_for_test().await.expect("reset");
    repository.migrate().await.expect("migrate");
    repository
        .seed_auditor_grant(app, wallet)
        .await
        .expect("grant");
    repository
        .save_case(create_withdrawal_case(tx_hash, 123, 1, app))
        .await
        .expect("case");
    repository
        .save_checkpoint(PollerCheckpoint {
            poller_id: "fuji-withdrawals".to_owned(),
            chain_id: 43_113,
            pool: [0x44; 20],
            application_id: app,
            next_block: 124,
            last_block_hash: Some([0x55; 32]),
            healthy: true,
            consecutive_failures: 0,
            last_error: None,
        })
        .await
        .expect("checkpoint");

    let restarted = PostgresRepository::connect(&database_url)
        .await
        .expect("restart");
    restarted
        .seed_auditor_grant(app, wallet)
        .await
        .expect("idempotent grant");
    restarted
        .save_case(create_withdrawal_case(tx_hash, 123, 1, app))
        .await
        .expect("idempotent case");

    let grant = restarted
        .get_grant(&wallet, &app)
        .await
        .expect("query")
        .expect("grant");
    assert_eq!(grant.granted_fields, DEFAULT_GRANTED_FIELDS);
    assert_eq!(
        grant.case_scope,
        haze_disclosure::cases::CaseScope::AllApplicationCases
    );
    let cases = restarted.list_cases(&app, &[]).await.expect("cases");
    assert_eq!(cases.len(), 1);
    assert_eq!(cases[0].confirmations, 1);
    let checkpoint = restarted
        .get_checkpoint("fuji-withdrawals")
        .await
        .expect("query")
        .expect("checkpoint");
    assert_eq!(checkpoint.next_block, 124);
    assert!(checkpoint.healthy);
}

#[tokio::test]
async fn migration_0005_case_scope_isolation_and_disclosure_receipts() {
    let _guard = database_lock().lock().await;
    let Some(database_url) = database_url() else {
        return;
    };
    let app_a = [0x11; 32];
    let app_b = [0x22; 32];
    let wallet = [0x33; 20];
    let tx_hash = [0x44; 32];

    let repository = PostgresRepository::connect(&database_url)
        .await
        .expect("connect");
    repository.reset_for_test().await.expect("reset");
    repository.migrate().await.expect("migrate");

    // Seed grant on App A
    repository
        .seed_auditor_grant(app_a, wallet)
        .await
        .expect("grant");
    let grant = repository
        .get_grant(&wallet, &app_a)
        .await
        .expect("query")
        .expect("grant");
    assert_eq!(
        grant.case_scope,
        haze_disclosure::cases::CaseScope::AllApplicationCases
    );

    // Save case under App A
    let case = create_withdrawal_case(tx_hash, 100, 12, app_a);
    let case_id = case.case_id.clone();
    repository.save_case(case).await.expect("save case");

    // Case exists for App A
    let found_a = repository
        .get_case_for_app(&app_a, &case_id)
        .await
        .expect("query");
    assert!(found_a.is_some());

    // Case NOT visible from App B
    let found_b = repository
        .get_case_for_app(&app_b, &case_id)
        .await
        .expect("query");
    assert!(found_b.is_none());

    // Save and retrieve disclosure receipt
    let session_token = "0xabcdef123456";
    let session_hash = haze_disclosure::auth::hash_session_token(session_token);
    repository
        .save_session(haze_disclosure::auth::StoredSession {
            session_hash,
            wallet,
            application_id: app_a,
            role: "application-auditor".to_owned(),
            grant_id: grant.grant_id,
            expires_at: 2000,
        })
        .await
        .expect("save session");

    let receipt = haze_disclosure::store::StoredDisclosureReceipt {
        receipt_id: [0x55; 32],
        session_hash,
        application_id: app_a,
        case_id: case_id.clone(),
        evidence_digest: [0x66; 32],
        disclosed_fields: std::collections::BTreeMap::from([
            ("amount".to_owned(), "1000000".to_owned()),
            (
                "asset".to_owned(),
                "0x5425890298aed601595a70AB815c96711a31Bc65".to_owned(),
            ),
        ]),
        created_at: 1_700_000_000,
        expires_at: 4_000_000_000,
    };

    repository
        .save_disclosure_receipt(receipt.clone())
        .await
        .expect("save receipt");
    let loaded = repository
        .get_disclosure_receipt(&session_hash, &app_a, &case_id)
        .await
        .expect("query");
    assert!(loaded.is_some());
    let loaded = loaded.expect("loaded receipt");
    assert_eq!(loaded.evidence_digest, [0x66; 32]);
    assert_eq!(
        loaded.disclosed_fields.get("amount").map(String::as_str),
        Some("1000000")
    );
}
