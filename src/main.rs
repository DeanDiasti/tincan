mod auth;
mod config;
mod hooks;
mod mail;
mod mcp;
mod sessions;
mod store;
mod subject;
mod web;

use std::{sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::json;
use sqlx::{PgPool, postgres::PgPoolOptions};

use auth::{GOOGLE_JWKS_URL, JwtVerifier};
use config::Config;

struct App {
    config: Config,
    db: PgPool,
    http: reqwest::Client,
    google: JwtVerifier,
    mcp: JwtVerifier,
}

impl App {
    fn new(config: Config, db: PgPool) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let google = JwtVerifier::new(
            &["https://accounts.google.com", "accounts.google.com"],
            config.google_client_id.clone(),
            GOOGLE_JWKS_URL.parse()?,
        );
        let mcp = JwtVerifier::new(
            &[&config.mcp_issuer],
            config.url("/mcp").into(),
            config.mcp_jwks_url.clone(),
        );
        Ok(Self {
            config,
            db,
            http,
            google,
            mcp,
        })
    }
}

fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(mcp::metadata),
        )
        .route("/.well-known/oauth-protected-resource", get(mcp::metadata))
        .merge(mcp::router(app.clone()))
        .merge(web::router())
        .merge(hooks::router())
        .layer(middleware::map_response(no_cache))
        .with_state(app)
}

async fn no_cache(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
}

async fn health(State(app): State<Arc<App>>) -> Response {
    match sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&app.db)
        .await
    {
        Ok(1) => Json(json!({"status": "ok"})).into_response(),
        _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "tincan=info".into()),
        )
        .init();
    let config = Config::from_env()?;
    let db = PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await?;
    sqlx::migrate!().run(&db).await?;
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    tracing::info!(address = %listener.local_addr()?, "Tincan listening");
    let app = Arc::new(App::new(config, db)?);
    let maintenance_pool = app.db.clone();
    let maintenance = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if let Err(err) = sessions::sweep(&maintenance_pool).await {
                tracing::warn!(%err, "Session and mailbox maintenance failed");
            }
        }
    });
    let result = axum::serve(listener, router(app))
        .with_graceful_shutdown(shutdown())
        .await;
    maintenance.abort();
    result?;
    Ok(())
}

async fn shutdown() {
    #[cfg(unix)]
    if let Ok(mut terminate) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
        return;
    }
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests;
