use axum::{routing::get, Router};
use crate::state::ApiState;

/// Builds the unified API router. Each service router carries its own
/// `Arc<Service>` state, so they are bound to that state before nesting.
pub fn router(state: &ApiState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .nest("/api/issuer", snex_issuer::handlers::router().with_state(state.issuer.clone()))
        .nest("/api/verifier", snex_verifier::handlers::router().with_state(state.verifier.clone()))
        .nest("/api/registry", snex_registry::handlers::router().with_state(state.registry.clone()))
        .nest("/api/reporting", snex_reporting::handlers::router().with_state(state.reporting.clone()))
        .nest("/api/voting", snex_voting::handlers::router().with_state(state.voting.clone()))
        .nest("/api/level-c", snex_levelc::handlers::router().with_state(state.level_c.clone()))
        .nest("/api/anchoring", snex_anchoring::handlers::router().with_state(state.anchoring.clone()))
        .nest("/api/retention", snex_retention::handlers::router().with_state(state.retention.clone()))
        .nest("/api/tenant", snex_tenant::handlers::router().with_state(state.tenant.clone()))
}

async fn health_check() -> &'static str {
    "OK"
}
