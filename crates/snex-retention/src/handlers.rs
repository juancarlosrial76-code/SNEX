use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use snex_core::{
    retention::{RetentionClass, RetentionRecord, LegalHold, DeletionJournalEntry, BackupGeneration},
    error::{CoreError, Result},
};
use crate::service::RetentionService;

#[derive(Deserialize)]
pub struct RegisterDataRequest {
    pub data_id: String,
    pub retention_class: RetentionClass,
    pub tenant_id: Option<Uuid>,
    pub person_key_id: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterDataResponse {
    pub registered: bool,
}

#[derive(Deserialize)]
pub struct RequestDeletionRequest {
    pub requested_by: String,
    pub volume: u64,
}

#[derive(Serialize)]
pub struct RequestDeletionResponse {
    pub requested: bool,
    pub pending_approval: bool,
}

#[derive(Deserialize)]
pub struct ApproveDestructionRequest {
    pub approved_by: String,
}

#[derive(Serialize)]
pub struct ApproveDestructionResponse {
    pub approved: bool,
}

#[derive(Deserialize)]
pub struct PlaceLegalHoldRequest {
    pub reason: String,
    pub placed_by: String,
    pub review_interval_days: u32,
    pub expires_at: Option<String>,
}

#[derive(Serialize)]
pub struct PlaceLegalHoldResponse {
    pub hold_id: Uuid,
}

#[derive(Deserialize)]
pub struct LiftLegalHoldRequest {
    pub hold_id: Uuid,
}

#[derive(Serialize)]
pub struct LiftLegalHoldResponse {
    pub lifted: bool,
}

#[derive(Serialize)]
pub struct CheckLegalHoldResponse {
    pub active: bool,
}

#[derive(Serialize)]
pub struct RecordResponse {
    pub record: RetentionRecord,
}

#[derive(Serialize)]
pub struct DeletionJournalResponse {
    pub entries: Vec<DeletionJournalEntry>,
}

pub fn router() -> Router<Arc<RetentionService>> {
    Router::new()
        .route("/data", post(register_data))
        .route("/data/:data_id", get(get_record))
        .route("/data/:data_id/delete", post(request_deletion))
        .route("/destruction/:pending_id/approve", post(approve_destruction))
        .route("/data/:data_id/legal-hold", post(place_legal_hold))
        .route("/data/:data_id/legal-hold/:hold_id", post(lift_legal_hold))
        .route("/data/:data_id/legal-hold", get(check_legal_hold))
        .route("/deletion-journal", get(get_deletion_journal))
        .route("/backup-expiry/:generation", post(process_backup_expiry))
}

async fn register_data(
    State(service): State<Arc<RetentionService>>,
    Json(req): Json<RegisterDataRequest>,
) -> Result<Json<RegisterDataResponse>, (StatusCode, String)> {
    service.register_data(req.data_id, req.retention_class, req.tenant_id, req.person_key_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(RegisterDataResponse { registered: true }))
}

async fn get_record(
    State(service): State<Arc<RetentionService>>,
    Path(data_id): Path<String>,
) -> Result<Json<RecordResponse>, (StatusCode, String)> {
    let record = service.get_record(&data_id).await
        .ok_or((StatusCode::NOT_FOUND, "Record not found".into()))?;
    Ok(Json(RecordResponse { record }))
}

async fn request_deletion(
    State(service): State<Arc<RetentionService>>,
    Path(data_id): Path<String>,
    Json(req): Json<RequestDeletionRequest>,
) -> Result<Json<RequestDeletionResponse>, (StatusCode, String)> {
    service.request_deletion(&data_id, req.requested_by, req.volume).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let record = service.get_record(&data_id).await.unwrap();
    Ok(Json(RequestDeletionResponse {
        requested: true,
        pending_approval: record.state == snex_core::retention::DeletionState::RemovedFromApplication,
    }))
}

async fn approve_destruction(
    State(service): State<Arc<RetentionService>>,
    Path(pending_id): Path<Uuid>,
    Json(req): Json<ApproveDestructionRequest>,
) -> Result<Json<ApproveDestructionResponse>, (StatusCode, String)> {
    service.approve_destruction(pending_id, req.approved_by).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(ApproveDestructionResponse { approved: true }))
}

async fn place_legal_hold(
    State(service): State<Arc<RetentionService>>,
    Path(data_id): Path<String>,
    Json(req): Json<PlaceLegalHoldRequest>,
) -> Result<Json<PlaceLegalHoldResponse>, (StatusCode, String)> {
    let expires_at = if let Some(s) = req.expires_at {
        Some(chrono::DateTime::parse_from_rfc3339(&s)
            .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid expires_at".into()))?
            .with_timezone(&chrono::Utc))
    } else {
        None
    };
    
    service.place_legal_hold(&data_id, req.reason, req.placed_by, req.review_interval_days, expires_at).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let record = service.get_record(&data_id).await.unwrap();
    let hold_id = record.legal_holds.last().unwrap().id;
    
    Ok(Json(PlaceLegalHoldResponse { hold_id }))
}

async fn lift_legal_hold(
    State(service): State<Arc<RetentionService>>,
    Path((data_id, hold_id)): Path<(String, Uuid)>,
) -> Result<Json<LiftLegalHoldResponse>, (StatusCode, String)> {
    service.lift_legal_hold(&data_id, hold_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(LiftLegalHoldResponse { lifted: true }))
}

async fn check_legal_hold(
    State(service): State<Arc<RetentionService>>,
    Path(data_id): Path<String>,
) -> Result<Json<CheckLegalHoldResponse>, (StatusCode, String)> {
    let active = service.check_legal_hold(&data_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(CheckLegalHoldResponse { active }))
}

async fn get_deletion_journal(
    State(service): State<Arc<RetentionService>>,
) -> Result<Json<DeletionJournalResponse>, (StatusCode, String)> {
    let entries = service.get_deletion_journal().await;
    Ok(Json(DeletionJournalResponse { entries }))
}

async fn process_backup_expiry(
    State(service): State<Arc<RetentionService>>,
    Path(generation): Path<u64>,
) -> Result<StatusCode, (StatusCode, String)> {
    service.process_backup_expiry(generation).await;
    Ok(StatusCode::OK)
}

use std::sync::Arc;