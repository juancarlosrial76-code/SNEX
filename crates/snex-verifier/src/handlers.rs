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
    pseudonym::{EstablishmentRequest, EpochConfirmation, PseudonymFunction},
    epoch::Epoch,
    error::{CoreError, Result},
};
use snex_crypto::{
    bbs::BbsCredential,
    commitments::Commitment,
    nullifiers::{Nullifier, Pseudonym, PairTag, OperationSecret},
};
use crate::service::VerifierService;

#[derive(Deserialize)]
pub struct EstablishmentRequestDto {
    pub tenant_id: Uuid,
    pub person_credential: BbsCredential,
    pub membership_credential: BbsCredential,
    pub commitment: Vec<u8>,
    pub commitment_key: Vec<u8>,
    pub establishment_nullifier: Vec<u8>,
    pub pair_tag: Vec<u8>,
    pub epoch: u64,
    pub lifetime_index: u32,
    pub zero_knowledge_proof: Vec<u8>,
}

#[derive(Serialize)]
pub struct EstablishmentResponse {
    pub accepted: bool,
    pub batch_pending: usize,
}

#[derive(Deserialize)]
pub struct EpochConfirmationRequest {
    pub pseudonym: Vec<u8>,
    pub tenant_id: Uuid,
    pub epoch: u64,
    pub person_credential: BbsCredential,
    pub membership_credential: BbsCredential,
    pub zero_knowledge_proof: Vec<u8>,
}

#[derive(Serialize)]
pub struct EpochConfirmationResponse {
    pub confirmed: bool,
}

#[derive(Serialize)]
pub struct SnapshotResponse {
    pub snapshot_id: Uuid,
    pub merkle_root: String,
    pub size: usize,
}

#[derive(Serialize)]
pub struct AnonymitySetResponse {
    pub tenant_id: Uuid,
    pub function: String,
    pub count: u32,
    pub build_up_mode: bool,
}

#[derive(Serialize)]
pub struct TerminateResponse {
    pub terminated: bool,
}

#[derive(Serialize)]
pub struct BlockResponse {
    pub blocked: bool,
}

pub fn router() -> Router<Arc<VerifierService>> {
    Router::new()
        .route("/establishment", post(process_establishment))
        .route("/epoch-confirmation", post(confirm_epoch))
        .route("/snapshots", post(create_snapshot))
        .route("/snapshots/:id", get(get_snapshot))
        .route("/anonymity-set/:tenant_id/:function", get(get_anonymity_set))
        .route("/build-up-mode/:tenant_id/:function", get(check_build_up_mode))
        .route("/pseudonym/:pseudonym/terminate", post(terminate_pseudonym))
        .route("/pseudonym/:pseudonym/block", post(block_pseudonym))
}

async fn process_establishment(
    State(service): State<Arc<VerifierService>>,
    Json(req): Json<EstablishmentRequestDto>,
) -> Result<Json<EstablishmentResponse>, (StatusCode, String)> {
    let commitment = Commitment::from_bytes(&req.commitment.try_into().map_err(|_| (StatusCode::BAD_REQUEST, "Invalid commitment".into()))?)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    
    let commitment_key = snex_crypto::commitments::CommitmentKey::from_bytes(
        &req.commitment_key[..33].try_into().unwrap(),
        &req.commitment_key[33..].try_into().unwrap(),
    ).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let establishment_nullifier = Nullifier::from_slice(&req.establishment_nullifier)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    
    let pair_tag = PairTag::from_slice(&req.pair_tag)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let request = EstablishmentRequest {
        tenant_id: req.tenant_id,
        person_credential: req.person_credential,
        membership_credential: req.membership_credential,
        commitment,
        commitment_key,
        establishment_nullifier,
        pair_tag,
        epoch: Epoch(req.epoch),
        lifetime_index: req.lifetime_index,
        zero_knowledge_proof: req.zero_knowledge_proof,
    };

    service.process_establishment(request).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let state = service.state.read().await;
    Ok(Json(EstablishmentResponse {
        accepted: true,
        batch_pending: state.batching_buffer.pending.len(),
    }))
}

async fn confirm_epoch(
    State(service): State<Arc<VerifierService>>,
    Json(req): Json<EpochConfirmationRequest>,
) -> Result<Json<EpochConfirmationResponse>, (StatusCode, String)> {
    let pseudonym = Pseudonym::from_slice(&req.pseudonym)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let confirmation = EpochConfirmation {
        pseudonym,
        tenant_id: req.tenant_id,
        epoch: Epoch(req.epoch),
        person_credential: req.person_credential,
        membership_credential: req.membership_credential,
        zero_knowledge_proof: req.zero_knowledge_proof,
    };

    service.confirm_epoch(confirmation).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(EpochConfirmationResponse { confirmed: true }))
}

async fn create_snapshot(
    State(service): State<Arc<VerifierService>>,
    Json(req): Json<CreateSnapshotRequest>,
) -> Result<Json<SnapshotResponse>, (StatusCode, String)> {
    let snapshot = service.create_snapshot(req.tenant_id, Epoch(req.epoch), req.ballot_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(SnapshotResponse {
        snapshot_id: snapshot.id,
        merkle_root: snapshot.merkle_root.to_hex(),
        size: snapshot.leaves.len(),
    }))
}

#[derive(Deserialize)]
pub struct CreateSnapshotRequest {
    pub tenant_id: Uuid,
    pub epoch: u64,
    pub ballot_id: Option<Uuid>,
}

async fn get_snapshot(
    State(service): State<Arc<VerifierService>>,
    Path(id): Path<Uuid>,
) -> Result<Json<snex_core::voting::Snapshot>, (StatusCode, String)> {
    let snapshot = service.get_snapshot(id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Snapshot not found".into()))?;
    Ok(Json(snapshot))
}

async fn get_anonymity_set(
    State(service): State<Arc<VerifierService>>,
    Path((tenant_id, function)): Path<(Uuid, String)>,
) -> Result<Json<AnonymitySetResponse>, (StatusCode, String)> {
    let function = function.parse::<PseudonymFunction>()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid function".into()))?;
    
    let count = service.get_anonymity_set(tenant_id, function).await;
    let build_up = service.check_build_up_mode(tenant_id, function).await;

    Ok(Json(AnonymitySetResponse {
        tenant_id,
        function: function.to_string(),
        count,
        build_up_mode: build_up,
    }))
}

async fn check_build_up_mode(
    State(service): State<Arc<VerifierService>>,
    Path((tenant_id, function)): Path<(Uuid, String)>,
) -> Result<Json<AnonymitySetResponse>, (StatusCode, String)> {
    let function = function.parse::<PseudonymFunction>()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid function".into()))?;
    
    let count = service.get_anonymity_set(tenant_id, function).await;
    let build_up = service.check_build_up_mode(tenant_id, function).await;

    Ok(Json(AnonymitySetResponse {
        tenant_id,
        function: function.to_string(),
        count,
        build_up_mode: build_up,
    }))
}

async fn terminate_pseudonym(
    State(service): State<Arc<VerifierService>>,
    Path(pseudonym_hex): Path<String>,
) -> Result<Json<TerminateResponse>, (StatusCode, String)> {
    let pseudonym = Pseudonym::from_hex(&pseudonym_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    service.terminate_pseudonym(pseudonym, Uuid::nil()).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(TerminateResponse { terminated: true }))
}

async fn block_pseudonym(
    State(service): State<Arc<VerifierService>>,
    Path(pseudonym_hex): Path<String>,
    Json(req): Json<BlockRequest>,
) -> Result<Json<BlockResponse>, (StatusCode, String)> {
    let pseudonym = Pseudonym::from_hex(&pseudonym_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    service.block_pseudonym(pseudonym, Uuid::nil(), req.reason).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(BlockResponse { blocked: true }))
}

#[derive(Deserialize)]
pub struct BlockRequest {
    pub reason: String,
}

use std::sync::Arc;