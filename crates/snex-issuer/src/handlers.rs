use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use snex_core::{identity::Account, epoch::Epoch, error::{CoreError, Result}};
use snex_crypto::{
    bbs::BbsCredential,
    commitments::Commitment,
    nullifiers::OperationSecret,
};
use crate::service::IssuerService;

#[derive(Deserialize)]
pub struct CreateAccountRequest {
    pub email: String,
    pub display_name: String,
}

#[derive(Serialize)]
pub struct CreateAccountResponse {
    pub account: Account,
}

#[derive(Deserialize)]
pub struct StartVerificationRequest {
    pub provider_id: String,
    pub verification_ref: String,
}

#[derive(Serialize)]
pub struct StartVerificationResponse {
    pub record_id: Uuid,
}

#[derive(Deserialize)]
pub struct CompleteVerificationRequest {
    pub attestation: Vec<u8>,
    pub blinded_commitment: Vec<u8>,
    pub of_age: bool,
}

#[derive(Serialize)]
pub struct CompleteVerificationResponse {
    pub record_id: Uuid,
}

#[derive(Deserialize)]
pub struct RequestPersonCredentialRequest {
    pub blinded_commitment: Vec<u8>,
    pub attributes: Vec<Vec<u8>>,
}

#[derive(Serialize)]
pub struct RequestPersonCredentialResponse {
    pub credential: BbsCredential,
}

#[derive(Deserialize)]
pub struct RequestMembershipCredentialRequest {
    pub tenant_id: Uuid,
    pub blinded_commitment: Vec<u8>,
    pub attributes: Vec<Vec<u8>>,
    pub reporting_authorised: bool,
    pub voting_authorised: bool,
}

#[derive(Serialize)]
pub struct RequestMembershipCredentialResponse {
    pub credential: BbsCredential,
}

#[derive(Serialize)]
pub struct AdvanceIssueResponse {
    pub operation_secret: Vec<u8>,
}

#[derive(Serialize)]
pub struct EpochStateResponse {
    pub epoch: u64,
    pub issuance_cohort_open: bool,
    pub issuance_cohort_size: u32,
    pub minimum_cohort_size: u32,
    pub grace_active: bool,
}

pub fn router() -> Router<Arc<IssuerService>> {
    Router::new()
        .route("/accounts", post(create_account))
        .route("/accounts/:id/verification", post(start_verification))
        .route("/verification/:record_id", post(complete_verification))
        .route("/accounts/:id/credentials/person", post(request_person_credential))
        .route("/accounts/:id/credentials/membership", post(request_membership_credential))
        .route("/accounts/:id/credentials/advance", post(advance_issue_next_epoch))
        .route("/epoch", get(get_epoch_state))
        .route("/cohort/close", post(close_cohort))
        .route("/grace/activate", post(activate_grace))
}

async fn create_account(
    State(service): State<Arc<IssuerService>>,
    Json(req): Json<CreateAccountRequest>,
) -> Result<Json<CreateAccountResponse>, (StatusCode, String)> {
    let account = service.create_account(req.email, req.display_name).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(CreateAccountResponse { account }))
}

async fn start_verification(
    State(service): State<Arc<IssuerService>>,
    Path(id): Path<Uuid>,
    Json(req): Json<StartVerificationRequest>,
) -> Result<Json<StartVerificationResponse>, (StatusCode, String)> {
    let record = service.start_verification(id, req.provider_id, req.verification_ref).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(StartVerificationResponse { record_id: record.id }))
}

async fn complete_verification(
    State(service): State<Arc<IssuerService>>,
    Path(record_id): Path<Uuid>,
    Json(req): Json<CompleteVerificationRequest>,
) -> Result<Json<CompleteVerificationResponse>, (StatusCode, String)> {
    let commitment = Commitment::from_bytes(&req.blinded_commitment.try_into().map_err(|_| (StatusCode::BAD_REQUEST, "Invalid commitment".into()))?)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    
    let record = service.complete_verification(record_id, req.attestation, commitment, req.of_age).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(CompleteVerificationResponse { record_id: record.id }))
}

async fn request_person_credential(
    State(service): State<Arc<IssuerService>>,
    Path(id): Path<Uuid>,
    Json(req): Json<RequestPersonCredentialRequest>,
) -> Result<Json<RequestPersonCredentialResponse>, (StatusCode, String)> {
    let commitment = Commitment::from_bytes(&req.blinded_commitment.try_into().map_err(|_| (StatusCode::BAD_REQUEST, "Invalid commitment".into()))?)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    
    let credential = service.request_person_credential(id, commitment, req.attributes).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(RequestPersonCredentialResponse { credential }))
}

async fn request_membership_credential(
    State(service): State<Arc<IssuerService>>,
    Path(id): Path<Uuid>,
    Json(req): Json<RequestMembershipCredentialRequest>,
) -> Result<Json<RequestMembershipCredentialResponse>, (StatusCode, String)> {
    let commitment = Commitment::from_bytes(&req.blinded_commitment.try_into().map_err(|_| (StatusCode::BAD_REQUEST, "Invalid commitment".into()))?)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    
    let credential = service.request_membership_credential(
        id, req.tenant_id, commitment, req.attributes, 
        req.reporting_authorised, req.voting_authorised
    ).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(RequestMembershipCredentialResponse { credential }))
}

async fn advance_issue_next_epoch(
    State(service): State<Arc<IssuerService>>,
    Path(id): Path<Uuid>,
) -> Result<Json<AdvanceIssueResponse>, (StatusCode, String)> {
    let op_secret = service.advance_issue_next_epoch(id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(AdvanceIssueResponse { operation_secret: op_secret.0.to_vec() }))
}

async fn get_epoch_state(
    State(service): State<Arc<IssuerService>>,
) -> Result<Json<EpochStateResponse>, (StatusCode, String)> {
    let epoch_state = service.get_epoch_state().await;
    Ok(Json(EpochStateResponse {
        epoch: epoch_state.epoch.0,
        issuance_cohort_open: epoch_state.issuance_cohort_open,
        issuance_cohort_size: epoch_state.issuance_cohort_size,
        minimum_cohort_size: epoch_state.minimum_cohort_size,
        grace_active: epoch_state.grace_active,
    }))
}

async fn close_cohort(
    State(service): State<Arc<IssuerService>>,
) -> Result<StatusCode, (StatusCode, String)> {
    service.close_cohort().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::OK)
}

async fn activate_grace(
    State(service): State<Arc<IssuerService>>,
) -> Result<StatusCode, (StatusCode, String)> {
    service.activate_grace().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::OK)
}

use std::sync::Arc;