use snex_api::{routes, state::ApiState};
use snex_core::config::AppConfig;
use sqlx::PgPool;
use tokio::signal;
use tracing::{info, error};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // TODO: tracing-subscriber is not in the offline registry cache; re-enable logging init when available.
    
    let config = AppConfig::load(None).unwrap_or_default();
    let database_url = &config.database.url;
    
    let pool = PgPool::connect(database_url).await?;
    sqlx::migrate!("../../migrations").run(&pool).await?;
    
    let state = ApiState::new(config.clone(), pool).await?;
    
    let app = routes::router(&state);
    
    let addr = format!("{}:{}", config.server.host, config.server.port);
    info!("Starting SNEX API on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    
    if let Err(e) = axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()).await {
        error!("Server error: {}", e);
    }
    
    info!("Server shutdown complete");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("Failed to install Ctrl+C handler");
    };
    
    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };
    
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    
    info!("Shutdown signal received");
}