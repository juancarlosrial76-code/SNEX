use axum::{
    routing::{get, post},
    Router,
};
use crate::state::ApiState;

pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/health", get(health_check))
        .nest("/api/issuer", snex_issuer::handlers::router())
        .nest("/api/verifier", snex_verifier::handlers::router())
        .nest("/api/registry", snex_registry::handlers::router())
        .nest("/api/reporting", snex_reporting::handlers::router())
        .nest("/api/voting", snex_voting::handlers::router())
        .nest("/api/level-c", snex_levelc::handlers::router())
        .nest("/api/anchoring", snex_anchoring::handlers::router())
        .nest("/api/retention", snex_retention::handlers::router())
        .nest("/api/tenant", snex_tenant::handlers::router())
}

async fn health_check() -> &'static str {
    "OK"
}