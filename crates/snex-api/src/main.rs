use snex_api::{routes, state::ApiState};
use snex_core::config::AppConfig;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::signal;
use tracing::{info, error};
use axum::Server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    
    let config = AppConfig::load(None).unwrap_or_default();
    let database_url = &config.database.url;
    
    let pool = PgPool::connect(database_url).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    
    let state = Arc::new(ApiState::new(config.clone(), pool).await?);
    
    let app = routes::router().with_state(state.clone());
    
    let addr = format!("{}:{}", config.server.host, config.server.port).parse()?;
    info!("Starting SNEX API on {}", addr);
    
    let server = Server::bind(&addr).serve(app.into_make_service());
    
    let graceful = server.with_graceful_shutdown(shutdown_signal());
    
    if let Err(e) = graceful.await {
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