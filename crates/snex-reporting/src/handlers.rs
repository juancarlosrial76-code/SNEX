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
    reporting::{ReplySender, ExternalVerificationLevel},
    epoch::Epoch,
    error::{CoreError, Result},
};
use snex_crypto::{
    nullifiers::{Nullifier, CaseHandle, OperationSecret},
    encryption::EncryptedData,
};
use crate::service::ReportingService;

fn case_handle_from_hex(s: &str) -> std::result::Result<CaseHandle, String> {
    let bytes = hex::decode(s).map_err(|e| e.to_string())?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "CaseHandle must be 32 bytes".to_string())?;
    Ok(CaseHandle(arr))
}

#[derive(Deserialize)]
pub struct SubmitReportRequest {
    pub tenant_id: Uuid,
    pub reporting_office_id: Uuid,
    pub operation_secret: Vec<u8>,
    pub report_window: u64,
    pub slot: u32,
    pub content: Vec<u8>,
    pub case_key_wrapped: Vec<u8>,
}

#[derive(Serialize)]
pub struct SubmitReportResponse {
    pub report_id: Uuid,
    pub case_id: Uuid,
    pub case_handle: String,
}

#[derive(Deserialize)]
pub struct SubmitReplyRequest {
    pub content: Vec<u8>,
    pub sent_by: String,
}

#[derive(Serialize)]
pub struct SubmitReplyResponse {
    pub reply_id: Uuid,
}

#[derive(Deserialize)]
pub struct HandoverCaseRequest {
    pub new_officer_key: Vec<u8>,
}

#[derive(Serialize)]
pub struct HandoverCaseResponse {
    pub handed_over: bool,
}

#[derive(Serialize)]
pub struct MailboxResponse {
    pub case_handle: String,
    pub messages: Vec<MailboxMessageResponse>,
    pub last_accessed: Option<String>,
}

#[derive(Serialize)]
pub struct MailboxMessageResponse {
    pub id: Uuid,
    pub direction: String,
    pub sent_at: String,
    pub read_at: Option<String>,
}

#[derive(Deserialize)]
pub struct ExternalIntakeRequest {
    pub tenant_id: Uuid,
    pub content: Vec<u8>,
    pub proof_of_work: Vec<u8>,
}

#[derive(Serialize)]
pub struct ExternalIntakeResponse {
    pub report_id: Uuid,
    pub verification_level: String,
}

pub fn router() -> Router<Arc<ReportingService>> {
    Router::new()
        .route("/reports", post(submit_report))
        .route("/cases/:id/replies", post(submit_reply))
        .route("/cases/:id/handover", post(handover_case))
        .route("/cases/:id/close", post(close_case))
        .route("/mailboxes/:case_handle", get(get_mailbox))
        .route("/external-intake", post(submit_external_intake))
}

async fn submit_report(
    State(service): State<Arc<ReportingService>>,
    Json(req): Json<SubmitReportRequest>,
) -> std::result::Result<Json<SubmitReportResponse>, (StatusCode, String)> {
    let op_secret = OperationSecret::from_bytes(req.operation_secret.try_into().map_err(|_| (StatusCode::BAD_REQUEST, "Invalid operation secret".into()))?);
    
    let (report, case) = service.submit_report(
        req.tenant_id,
        req.reporting_office_id,
        &op_secret,
        req.report_window,
        req.slot,
        EncryptedData(req.content),
        req.case_key_wrapped,
    ).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(SubmitReportResponse {
        report_id: report.id,
        case_id: case.id,
        case_handle: hex::encode(report.case_handle.0),
    }))
}

async fn submit_reply(
    State(service): State<Arc<ReportingService>>,
    Path(case_id): Path<Uuid>,
    Json(req): Json<SubmitReplyRequest>,
) -> std::result::Result<Json<SubmitReplyResponse>, (StatusCode, String)> {
    let sent_by = match req.sent_by.as_str() {
        "reporter" => ReplySender::Reporter,
        "officer" => ReplySender::Officer,
        _ => return Err((StatusCode::BAD_REQUEST, "Invalid sender".into())),
    };

    let reply = service.submit_reply(case_id, EncryptedData(req.content), sent_by).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(SubmitReplyResponse { reply_id: reply.id }))
}

async fn handover_case(
    State(service): State<Arc<ReportingService>>,
    Path(id): Path<Uuid>,
    Json(req): Json<HandoverCaseRequest>,
) -> std::result::Result<Json<HandoverCaseResponse>, (StatusCode, String)> {
    service.handover_case(id, req.new_officer_key).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(HandoverCaseResponse { handed_over: true }))
}

async fn close_case(
    State(service): State<Arc<ReportingService>>,
    Path(id): Path<Uuid>,
) -> std::result::Result<StatusCode, (StatusCode, String)> {
    service.close_case(id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::OK)
}

async fn get_mailbox(
    State(service): State<Arc<ReportingService>>,
    Path(case_handle_hex): Path<String>,
) -> std::result::Result<Json<MailboxResponse>, (StatusCode, String)> {
    let case_handle = case_handle_from_hex(&case_handle_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let mailbox = service.get_mailbox(&case_handle).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Mailbox not found".into()))?;

    Ok(Json(MailboxResponse {
        case_handle: hex::encode(mailbox.case_handle.0),
        messages: mailbox.messages.into_iter().map(|m| MailboxMessageResponse {
            id: m.id,
            direction: format!("{:?}", m.direction),
            sent_at: m.sent_at.to_rfc3339(),
            read_at: m.read_at.map(|t| t.to_rfc3339()),
        }).collect(),
        last_accessed: mailbox.last_accessed_at.map(|t| t.to_rfc3339()),
    }))
}

async fn submit_external_intake(
    State(service): State<Arc<ReportingService>>,
    Json(req): Json<ExternalIntakeRequest>,
) -> std::result::Result<Json<ExternalIntakeResponse>, (StatusCode, String)> {
    let report = service.submit_external_intake(
        req.tenant_id,
        EncryptedData(req.content),
        req.proof_of_work,
    ).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(ExternalIntakeResponse {
        report_id: report.id,
        verification_level: format!("{:?}", report.verification_level),
    }))
}

use std::sync::Arc;