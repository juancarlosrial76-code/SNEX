use axum::{
    extract::{State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use snex_core::{
    anchoring::{AnchoredHash, SecurityCriticalEventType},
    error::{CoreError, Result},
};
use snex_crypto::hashing::Hash;
use crate::service::AnchoringService;

#[derive(Deserialize)]
pub struct AppendRequest {
    pub component: String,
    pub action: String,
    pub data: serde_json::Value,
    pub tenant_id: Option<Uuid>,
    pub epoch: Option<u64>,
}

#[derive(Serialize)]
pub struct AppendResponse {
    pub appended: bool,
}

#[derive(Serialize)]
pub struct AnchorResponse {
    pub anchored: bool,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub valid: bool,
}

#[derive(Serialize)]
pub struct LatestAnchorResponse {
    pub anchor: Option<AnchoredHash>,
}

#[derive(Deserialize)]
pub struct SecurityEventRequest {
    pub event_type: SecurityCriticalEventType,
    pub data: serde_json::Value,
}

pub fn router() -> Router<Arc<AnchoringService>> {
    Router::new()
        .route("/append", post(append))
        .route("/anchor", post(anchor))
        .route("/verify", get(verify))
        .route("/latest-anchor", get(latest_anchor))
        .route("/security-event", post(security_event))
}

async fn append(
    State(service): State<Arc<AnchoringService>>,
    Json(req): Json<AppendRequest>,
) -> Result<Json<AppendResponse>, (StatusCode, String)> {
    service.append(req.component, req.action, req.data, req.tenant_id, req.epoch).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(AppendResponse { appended: true }))
}

async fn anchor(
    State(service): State<Arc<AnchoringService>>,
) -> Result<Json<AnchorResponse>, (StatusCode, String)> {
    service.anchor().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(AnchorResponse { anchored: true }))
}

async fn verify(
    State(service): State<Arc<AnchoringService>>,
) -> Result<Json<VerifyResponse>, (StatusCode, String)> {
    let valid = service.verify_chain().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(VerifyResponse { valid }))
}

async fn latest_anchor(
    State(service): State<Arc<AnchoringService>>,
) -> Result<Json<LatestAnchorResponse>, (StatusCode, String)> {
    let anchor = service.get_latest_anchor().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(LatestAnchorResponse { anchor }))
}

async fn security_event(
    State(service): State<Arc<AnchoringService>>,
    Json(req): Json<SecurityEventRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    service.log_security_critical_event(req.event_type, req.data).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::OK)
}

use std::sync::Arc;