//! T4.5 persistence and operations suite.

use std::{fs, path::PathBuf};

use haze_protocol::{
    PRODUCT_ID, ProtocolError,
    ops::{
        Compatibility, DurableSnapshot, DurableStore, HealthStatus, IdempotencyRecord,
        IdempotencyStore, MIGRATION_FILES, MigrationCatalog, ReadyStatus, SCHEMA_VERSION,
        SERVICE_P95_TARGET_MS, ServiceOps, WriteOnceRetention, check_compatibility, rotation_id,
    },
};

fn migrations_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../dev/postgres/migrations")
}

#[test]
fn committed_sql_files_match_the_catalog() {
    let dir = migrations_dir();
    for file in MIGRATION_FILES {
        let sql = fs::read_to_string(dir.join(file)).expect("sql");
        assert!(sql.to_ascii_lowercase().contains("create table"));
    }
    let files = MigrationCatalog::files();
    assert_eq!(files[0].file, "0001_init.sql");
    assert_eq!(files[1].file, "0002_ops.sql");
    assert_eq!(files[2].file, "0003_compliance_portal.sql");
    assert_eq!(files[2].version, SCHEMA_VERSION);
}

#[test]
fn migrations_apply_forward_and_roll_back() {
    let catalog = MigrationCatalog::new();
    assert_eq!(catalog.current_version().expect("v0"), 0);
    assert_eq!(catalog.apply_next().expect("0001"), 1);
    assert!(catalog.has_table("haze_access_log").expect("t1"));
    assert_eq!(catalog.apply_next().expect("0002"), 2);
    assert!(catalog.has_table("haze_idempotency").expect("t2"));
    assert_eq!(catalog.apply_next().expect("0003"), 3);
    assert!(catalog.has_table("haze_compliance_cases").expect("t3"));
    assert_eq!(
        catalog.apply_next().expect_err("no 0004"),
        ProtocolError::VersionUnsupported
    );
    assert_eq!(catalog.rollback().expect("down 0003"), 3);
    assert!(!catalog.has_table("haze_compliance_cases").expect("dropped"));
    assert_eq!(catalog.current_version().expect("v2"), 2);
    assert_eq!(catalog.rollback().expect("down 0002"), 2);
    assert!(!catalog.has_table("haze_idempotency").expect("dropped"));
    assert_eq!(catalog.current_version().expect("v1"), 1);
    assert_eq!(catalog.rollback().expect("down 0001"), 1);
    assert_eq!(catalog.current_version().expect("empty"), 0);
}

#[test]
fn incompatible_pins_fail_closed() {
    let expected = Compatibility::current();
    assert_eq!(expected.product_id, PRODUCT_ID);
    assert_eq!(
        check_compatibility(&expected, &expected).expect("current"),
        ()
    );
    let mut actual = expected.clone();
    actual.schema_version = 1;
    assert_eq!(
        check_compatibility(&expected, &actual).expect_err("schema"),
        ProtocolError::VersionUnsupported
    );
    actual = expected.clone();
    actual.circuit_version = "spend-v0".to_owned();
    assert_eq!(
        check_compatibility(&expected, &actual).expect_err("circuit"),
        ProtocolError::VersionUnsupported
    );
}

#[test]
fn bootstrap_becomes_ready_and_shutdown_fails_closed() {
    let ops = ServiceOps::uninitialized("replica-a");
    assert_eq!(ops.runtime.health(), HealthStatus::Live);
    assert_eq!(ops.runtime.ready(), ReadyStatus::NotReady);
    ops.bootstrap().expect("bootstrap");
    assert_eq!(ops.runtime.ready(), ReadyStatus::Ready);
    ops.runtime.shutdown();
    assert_eq!(ops.runtime.health(), HealthStatus::Stopping);
    assert_eq!(ops.runtime.ready(), ReadyStatus::NotReady);
    assert_eq!(
        ops.require_ready().expect_err("stopping"),
        ProtocolError::VersionUnsupported
    );
}

#[test]
fn idempotency_replays_and_rejects_conflicts() {
    let store = IdempotencyStore::new();
    let first = store
        .put(IdempotencyRecord {
            key: "gk-1".to_owned(),
            request_hash: ServiceOps::hash_body(b"auth-a"),
            response_hash: ServiceOps::hash_body(b"ok-1"),
        })
        .expect("first");
    let replay = store
        .put(IdempotencyRecord {
            key: "gk-1".to_owned(),
            request_hash: ServiceOps::hash_body(b"auth-a"),
            response_hash: ServiceOps::hash_body(b"ignored"),
        })
        .expect("replay");
    assert_eq!(replay.response_hash, first.response_hash);
    assert_eq!(
        store
            .put(IdempotencyRecord {
                key: "gk-1".to_owned(),
                request_hash: ServiceOps::hash_body(b"auth-b"),
                response_hash: ServiceOps::hash_body(b"other"),
            })
            .expect_err("conflict"),
        ProtocolError::DomainMismatch
    );
}

#[test]
fn backup_restore_and_replicas_share_durable_state() {
    let ops = ServiceOps::uninitialized("primary");
    ops.bootstrap().expect("boot");
    ops.durable.put("checkpoint", b"block-9").expect("put");
    let backup = ops.durable.backup().expect("backup");
    assert_eq!(backup.schema_version, SCHEMA_VERSION);

    let restored = DurableStore::new();
    restored.restore(backup.clone()).expect("restore");
    assert_eq!(
        restored.get("checkpoint").expect("get").expect("value"),
        b"block-9"
    );

    let replica = ops.replica("replica-b");
    assert_eq!(replica.runtime.ready(), ReadyStatus::Ready);
    replica
        .idempotency
        .put(IdempotencyRecord {
            key: "shared".to_owned(),
            request_hash: ServiceOps::hash_body(b"req"),
            response_hash: ServiceOps::hash_body(b"res"),
        })
        .expect("shared");
    assert!(ops.idempotency.get("shared").expect("lookup").is_some());

    assert_eq!(
        restored
            .restore(DurableSnapshot {
                schema_version: 99,
                records: backup.records,
            })
            .expect_err("bad schema"),
        ProtocolError::VersionUnsupported
    );
}

#[test]
fn write_once_retention_rejects_overwrite() {
    let retention = WriteOnceRetention::new();
    retention.put("log/1", b"entry").expect("put");
    assert_eq!(retention.get("log/1").expect("get"), b"entry");
    assert_eq!(
        retention.put("log/1", b"mutated").expect_err("overwrite"),
        ProtocolError::DomainMismatch
    );
}

#[test]
fn redacted_logs_never_include_secrets() {
    let ops = ServiceOps::ready_default();
    ops.log.record(
        "query",
        "trace-1",
        vec![("code", "OK".to_owned()), ("fields", "amount".to_owned())],
    );
    let rendered = ops.log.rendered();
    assert!(rendered.contains("code=OK"));
    assert!(!rendered.contains("oidc-secret"));
    assert!(!rendered.contains("BEGIN PRIVATE KEY"));
}

#[test]
fn load_baseline_records_service_samples() {
    let ops = ServiceOps::ready_default();
    for index in 0..128 {
        ops.time("idempotent_put", || {
            let _ = ops.idempotency.put(IdempotencyRecord {
                key: format!("k-{index}"),
                request_hash: ServiceOps::hash_body(&[index as u8]),
                response_hash: ServiceOps::hash_body(b"ok"),
            });
        });
    }
    assert_eq!(ops.metrics.count("idempotent_put"), 128);
    assert!(ops.metrics.max_us("idempotent_put") < SERVICE_P95_TARGET_MS.saturating_mul(1_000));
}

#[test]
fn rotation_id_is_deterministic_and_domain_separated() {
    let app = [0xaa; 32];
    let first = rotation_id(app, "v1", "v2");
    let again = rotation_id(app, "v1", "v2");
    let other = rotation_id(app, "v1", "v3");
    assert_eq!(first, again);
    assert_ne!(first, other);
    assert_ne!(first, [0u8; 32]);
}
