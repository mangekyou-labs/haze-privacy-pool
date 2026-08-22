//! Fuji compliance and disclosure runtime process.

use std::{env, net::SocketAddr, sync::Arc, time::Duration};

use haze_disclosure::{
    auth::SiweConfig,
    fuji::FujiDisclosureConfig,
    http::{HttpState, router},
    poller::FujiLogPoller,
    repository::{ComplianceRepository, PostgresRepository},
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

    let database_url = env::var("DATABASE_URL").map_err(|_| "DATABASE_URL missing")?;
    let store = PostgresRepository::connect(&database_url).await?;
    store.migrate().await?;
    let auditor_wallet = fixed_hex::<20>("HAZE_AUDITOR_WALLET")?;
    store
        .seed_auditor_grant(application_id, auditor_wallet)
        .await?;

    let rpc_url = env::var("HAZE_FUJI_RPC_URL")?;

    // Start background internal Fuji log poller
    let deployment_block = env::var("HAZE_DEPLOYMENT_BLOCK")
        .map_err(|_| "HAZE_DEPLOYMENT_BLOCK missing")?
        .parse()?;
    let replay_window = env::var("HAZE_POLLER_REPLAY_WINDOW")
        .unwrap_or_else(|_| "32".to_owned())
        .parse()?;
    let poller = Arc::new(FujiLogPoller::with_repository(
        config.clone(),
        rpc_url.clone(),
        ComplianceRepository::from(store.clone()),
        deployment_block,
        replay_window,
    ));
    poller.start_background_loop(Duration::from_secs(5));

    let state = HttpState::with_repository(config, fixture_ikm, rpc_url, siwe_config, store.into());

    let app = router(state, &origin)?;
    let port = env::var("PORT")
        .unwrap_or_else(|_| "10000".to_owned())
        .parse()?;
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port))).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
