//! Stateless Fuji wallet-disclosure HTTP process.

use std::{env, net::SocketAddr};

use haze_disclosure::{
    fuji::FujiDisclosureConfig,
    http::{HttpState, router},
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
    let config = FujiDisclosureConfig {
        chain_id: env::var("HAZE_CHAIN_ID")?.parse()?,
        application_id: fixed_hex("HAZE_APPLICATION_ID")?,
        pool: fixed_hex("HAZE_POOL_ADDRESS")?,
        pool_version: fixed_hex("HAZE_POOL_VERSION")?,
        development_fixture_keys: development,
    };
    let fixture_ikm = if development {
        fixed_hex("HAZE_FUJI_AUDIT_IKM").ok()
    } else {
        None
    };
    let state = HttpState::new(config, fixture_ikm, env::var("HAZE_FUJI_RPC_URL")?);
    let app = router(state, &env::var("HAZE_VERCEL_ORIGIN")?)?;
    let port = env::var("PORT")
        .unwrap_or_else(|_| "10000".to_owned())
        .parse()?;
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port))).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
