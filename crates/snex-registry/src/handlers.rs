use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use snex_core::{
    voting::{Vote, VoteValue},
    reporting::{Report, Case, Reply},
    epoch::Epoch,
    error::{CoreError, Result},
};
use snex_crypto::{
    nullifiers::{Nullifier, CaseHandle, MailboxAccess},
    hash::Hash,
    encryption::EncryptedData,
};
use crate::service::RegistryService;

#[derive(Deserialize)]
pub struct RegisterVoteRequest {
    pub ballot_id: Uuid,
    pub nullifier: Vec<u8>,
    pub vote_value: VoteValue,
    pub vote_hash: Vec<u8>,
    pub pseudonym: Vec<u8>,
    pub proof: Vec<u8>,
}

#[derive(Serialize)]
pub struct RegisterVoteResponse {
    pub registered: bool,
}

#[derive(Deserialize)]
pub struct RegisterReportRequest {
    pub case_handle: Vec<u8>,
    pub tenant_id: Uuid,
    pub reporting_office_id: Uuid,
    pub rate_limit_tag: Vec<u8>,
    pub content: Vec<u8>,
    pub case_key_wrapped: Vec<u8>,
    pub epoch: u64,
}

#[derive(Serialize)]
pub struct RegisterReportResponse {
    pub report_id: Uuid,
    pub case_id: Uuid,
}

#[derive(Deserialize)]
pub struct AddReplyRequest {
    pub case_id: Uuid,
    pub content: Vec<u8>,
    pub sent_by: String,
}

#[derive(Serialize)]
pub struct AddReplyResponse {
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

#[derive(Serialize)]
pub struct CheckNullifierResponse {
    pub exists: bool,
}

#[derive(Serialize)]
pub struct AdmissionJournalResponse {
    pub entries: Vec<AdmissionJournalEntryResponse>,
}

#[derive(Serialize)]
pub struct AdmissionJournalEntryResponse {
    pub id: Uuid,
    pub nullifier: String,
    pub domain: String,
    pub created_at: String,
    pub confirmed: bool,
    pub tombstone: bool,
}

pub fn router() -> Router<Arc<RegistryService>> {
    Router::new()
        .route("/votes", post(register_vote))
        .route("/votes/:ballot_id", get(get_vote_register))
        .route("/votes/:ballot_id/finalize", post(finalize_vote_register))
        .route("/reports", post(register_report))
        .route("/replies", post(add_reply))
        .route("/cases/:id/handover", post(handover_case))
        .route("/cases/:id/close", post(close_case))
        .route("/mailboxes/:case_handle", get(get_mailbox))
        .route("/nullifiers/:domain/:nullifier", get(check_nullifier))
        .route("/admission-journal", get(get_admission_journal))
}

async fn register_vote(
    State(service): State<Arc<RegistryService>>,
    Json(req): Json<RegisterVoteRequest>,
) -> Result<Json<RegisterVoteResponse>, (StatusCode, String)> {
    let nullifier = Nullifier::from_slice(&req.nullifier)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    
    let vote = Vote::new(
        req.ballot_id,
        nullifier,
        req.vote_value,
        snex_crypto::nullifiers::Pseudonym::from_slice(&req.pseudonym)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?,
        req.proof,
    );

    service.register_vote(&vote).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(RegisterVoteResponse { registered: true }))
}

async fn get_vote_register(
    State(service): State<Arc<RegistryService>>,
    Path(ballot_id): Path<Uuid>,
) -> Result<Json<snex_core::voting::VoteRegister>, (StatusCode, String)> {
    let register = service.get_vote_register(ballot_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Vote register not found".into()))?;
    Ok(Json(register))
}

async fn finalize_vote_register(
    State(service): State<Arc<RegistryService>>,
    Path(ballot_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    service.finalize_vote_register(ballot_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::OK)
}

async fn register_report(
    State(service): State<Arc<RegistryService>>,
    Json(req): Json<RegisterReportRequest>,
) -> Result<Json<RegisterReportResponse>, (StatusCode, String)> {
    let case_handle = CaseHandle::from_slice(&req.case_handle)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    
    let rate_limit_tag = Nullifier::from_slice(&req.rate_limit_tag)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let report = snex_core::reporting::Report::new(
        req.tenant_id,
        req.reporting_office_id,
        rate_limit_tag,
        EncryptedData(req.content),
        req.case_key_wrapped,
        Epoch(req.epoch),
    );

    let case = snex_core::reporting::Case::new(
        &report,
        snex_crypto::key_hierarchy::Dek::generate(),
        vec![],
        vec![],
        Uuid::new_v4(),
    );

    service.register_report(&report, &case).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(RegisterReportResponse {
        report_id: report.id,
        case_id: case.id,
    }))
}

async fn add_reply(
    State(service): State<Arc<RegistryService>>,
    Json(req): Json<AddReplyRequest>,
) -> Result<Json<AddReplyResponse>, (StatusCode, String)> {
    let sent_by = match req.sent_by.as_str() {
        "reporter" => snex_core::reporting::ReplySender::Reporter,
        "officer" => snex_core::reporting::ReplySender::Officer,
        _ => return Err((StatusCode::BAD_REQUEST, "Invalid sender".into())),
    };

    let reply = Reply::new(req.case_id, EncryptedData(req.content), sent_by);

    service.add_reply(req.case_id, &reply).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(AddReplyResponse { reply_id: reply.id }))
}

async fn handover_case(
    State(service): State<Arc<RegistryService>>,
    Path(id): Path<Uuid>,
    Json(req): Json<HandoverCaseRequest>,
) -> Result<Json<HandoverCaseResponse>, (StatusCode, String)> {
    service.handover_case(id, req.new_officer_key).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(HandoverCaseResponse { handed_over: true }))
}

async fn close_case(
    State(service): State<Arc<RegistryService>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    service.close_case(id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::OK)
}

async fn get_mailbox(
    State(service): State<Arc<RegistryService>>,
    Path(case_handle_hex): Path<String>,
) -> Result<Json<MailboxResponse>, (StatusCode, String)> {
    let case_handle = CaseHandle::from_hex(&case_handle_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let mailbox = service.get_mailbox(&case_handle).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Mailbox not found".into()))?;

    Ok(Json(MailboxResponse {
        case_handle: mailbox.case_handle.to_hex(),
        messages: mailbox.messages.into_iter().map(|m| MailboxMessageResponse {
            id: m.id,
            direction: format!("{:?}", m.direction),
            sent_at: m.sent_at.to_rfc3339(),
            read_at: m.read_at.map(|t| t.to_rfc3339()),
        }).collect(),
        last_accessed: mailbox.last_accessed_at.map(|t| t.to_rfc3339()),
    }))
}

async fn check_nullifier(
    State(service): State<Arc<RegistryService>>,
    Path((domain, nullifier_hex)): Path<(String, String)>,
) -> Result<Json<CheckNullifierResponse>, (StatusCode, String)> {
    let domain = match domain.as_str() {
        "vote" => snex_core::registry::NullifierDomain::Vote,
        "report" => snex_core::registry::NullifierDomain::Report,
        "establishment" => snex_core::registry::NullifierDomain::Establishment,
        "rate_limit" => snex_core::registry::NullifierDomain::RateLimit,
        _ => return Err((StatusCode::BAD_REQUEST, "Invalid domain".into())),
    };

    let nullifier = Nullifier::from_hex(&nullifier_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let exists = service.check_nullifier(domain, &nullifier).await;

    Ok(Json(CheckNullifierResponse { exists }))
}

async fn get_admission_journal(
    State(service): State<Arc<RegistryService>>,
    Query(params): Query<AdmissionJournalQuery>,
) -> Result<Json<AdmissionJournalResponse>, (StatusCode, String)> {
    let epoch = params.epoch.map(Epoch).unwrap_or_else(Epoch::current);
    let tenant_id = params.tenant_id;

    let entries = service.get_admission_journal(epoch, tenant_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(AdmissionJournalResponse {
        entries: entries.into_iter().map(|e| AdmissionJournalEntryResponse {
            id: e.id,
            nullifier: e.nullifier.to_hex(),
            domain: format!("{:?}", e.domain),
            created_at: e.created_at.to_rfc3339(),
            confirmed: e.confirmed,
            tombstone: e.tombstone,
        }).collect(),
    }))
}

#[derive(Deserialize)]
pub struct AdmissionJournalQuery {
    pub epoch: Option<u64>,
    pub tenant_id: Option<Uuid>,
}

use std::sync::Arc;