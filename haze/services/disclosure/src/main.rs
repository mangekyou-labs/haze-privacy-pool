//! Fuji compliance and disclosure runtime process.

use std::{env, net::SocketAddr, sync::Arc, time::Duration};

use haze_disclosure::{
    auth::SiweConfig,
    fuji::FujiDisclosureConfig,
    http::{HttpState, router},
    poller::FujiLogPoller,
    repository::{ComplianceRepository, PostgresRepository},
    store::ComplianceStore,
};

fn fixed_hex<const N: usize>(name: &str) -> Result<[u8; N], String> {
    let value = env::var(name).map_err(|_| format!("{name} missing"))?;
    let raw = value
        .strip_prefix("0x")
        .ok_or_else(|| format!("{name} invalid"))?;
    let bytes = hex::decode(raw).map_err(|_| format!("{name} invalid"))?;
    bytes.try_into().map_err(|_| format!("{name} invalid"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let development = env::var("HAZE_FUJI_DEVELOPMENT_BUILD").is_ok_and(|value| value == "true");
    let chain_id: u64 = env::var("HAZE_CHAIN_ID")
        .unwrap_or_else(|_| "43113".to_owned())
        .parse()?;
    let application_id = fixed_hex("HAZE_APPLICATION_ID")?;
    let pool = fixed_hex("HAZE_POOL_ADDRESS")?;
    let pool_version = fixed_hex("HAZE_POOL_VERSION")?;

    let config = FujiDisclosureConfig {
        chain_id,
        application_id,
        pool,
        pool_version,
        development_fixture_keys: development,
    };

    let fixture_ikm = if development {
        fixed_hex("HAZE_FUJI_AUDIT_IKM").ok()
    } else {
        None
    };

    let origin =
        env::var("HAZE_VERCEL_ORIGIN").unwrap_or_else(|_| "http://127.0.0.1:3000".to_owned());
    let domain = origin
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .to_owned();

    let siwe_config = SiweConfig {
        chain_id,
        domain,
        uri: format!("{origin}/audit"),
        application_id,
        challenge_ttl_secs: 300,
        session_ttl_secs: 3600,
    };

    let auditor_wallet = fixed_hex::<20>("HAZE_AUDITOR_WALLET")
        .or_else(|_| fixed_hex::<20>("HAZE_DEV_AUDITOR"))
        .unwrap_or([
            0xed, 0x37, 0xfd, 0x0d, 0x6f, 0x0f, 0x69, 0x23, 0x6e, 0x74, 0x72, 0xb3, 0x67, 0x96,
            0xe1, 0x33, 0xd2, 0x0e, 0xcc, 0x32,
        ]);

    let repo: ComplianceRepository = if let Ok(database_url) = env::var("DATABASE_URL") {
        let store = PostgresRepository::connect(&database_url).await?;
        store.migrate().await?;
        store
            .seed_auditor_grant(application_id, auditor_wallet)
            .await?;
        ComplianceRepository::from(store)
    } else if development {
        let store = ComplianceStore::new();
        store.seed_auditor_grant(application_id, auditor_wallet);
        ComplianceRepository::from(store)
    } else {
        return Err("DATABASE_URL missing".into());
    };

    let rpc_url = env::var("HAZE_FUJI_RPC_URL")?;

    // Start background internal Fuji log poller
    let deployment_block = env::var("HAZE_DEPLOYMENT_BLOCK")
        .unwrap_or_else(|_| "48900000".to_owned())
        .parse()?;
    let replay_window = env::var("HAZE_POLLER_REPLAY_WINDOW")
        .unwrap_or_else(|_| "32".to_owned())
        .parse()?;
    let mut poller = FujiLogPoller::with_repository(
        config.clone(),
        rpc_url.clone(),
        repo.clone(),
        deployment_block,
        replay_window,
    );
    if let Ok(max_block_range) = env::var("HAZE_POLLER_MAX_BLOCK_RANGE") {
        poller.max_block_range = max_block_range.parse()?;
    }
    let poller = Arc::new(poller);
    poller.start_background_loop(Duration::from_secs(5));

    let signer = if let Ok(key_b64) = env::var("HAZE_EXPORT_SIGNING_KEY_PKCS8_B64") {
        haze_disclosure::export::ExportSigner::from_pkcs8_b64(
            &key_b64,
            haze_disclosure::export::DEFAULT_SIGNING_KEY_ID,
        )?
    } else if development {
        haze_disclosure::export::ExportSigner::generate_test_signer()
    } else {
        return Err("HAZE_EXPORT_SIGNING_KEY_PKCS8_B64 missing".into());
    };

    let state = HttpState::with_repository(config, fixture_ikm, rpc_url, siwe_config, repo)
        .with_export_signer(signer);

    let app = router(state, &origin)?;
    let port = env::var("PORT")
        .unwrap_or_else(|_| "10000".to_owned())
        .parse()?;
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port))).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
