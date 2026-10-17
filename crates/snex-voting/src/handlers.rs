use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::Utc;
use snex_core::{
    voting::{Ballot, Vote, VoteValue, VoteTally, Snapshot, MerkleProof},
    epoch::Epoch,
    error::{CoreError, Result},
};
use snex_crypto::{
    nullifiers::{Nullifier, OperationSecret, Pseudonym},
    hashing::Hash,
};
use crate::service::VotingService;

#[derive(Deserialize)]
pub struct CreateBallotRequest {
    pub tenant_id: Uuid,
    pub title: String,
    pub description: String,
    pub opens_at: String,
    pub closes_at: String,
}

#[derive(Serialize)]
pub struct CreateBallotResponse {
    pub ballot: Ballot,
}

#[derive(Deserialize)]
pub struct CastVoteRequest {
    pub ballot_id: Uuid,
    pub operation_secret: Vec<u8>,
    pub vote_value: VoteValue,
    pub pseudonym: Vec<u8>,
    pub merkle_proof: MerkleProofDto,
    pub snapshot_leaf: SnapshotLeafDto,
}

#[derive(Serialize)]
pub struct CastVoteResponse {
    pub vote_id: Uuid,
    pub nullifier: String,
}

#[derive(Serialize)]
pub struct FinalizeBallotResponse {
    pub tally: VoteTally,
}

#[derive(Deserialize)]
pub struct MerkleProofDto {
    pub leaf_index: u32,
    pub siblings: Vec<String>,
    pub root: String,
}

#[derive(Deserialize)]
pub struct SnapshotLeafDto {
    pub pseudonym: String,
    pub reporting_authorised: bool,
    pub voting_authorised: bool,
    pub index: u32,
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
    pub count: u32,
}

pub fn router() -> Router<Arc<VotingService>> {
    Router::new()
        .route("/ballots", post(create_ballot))
        .route("/ballots/:id/vote", post(cast_vote))
        .route("/ballots/:id/finalize", post(finalize_ballot))
        .route("/ballots/:id/register", get(get_vote_register))
        .route("/snapshots/:id", get(get_snapshot))
        .route("/anonymity-set/:tenant_id", get(get_anonymity_set))
}

async fn create_ballot(
    State(service): State<Arc<VotingService>>,
    Json(req): Json<CreateBallotRequest>,
) -> std::result::Result<Json<CreateBallotResponse>, (StatusCode, String)> {
    let opens_at = chrono::DateTime::parse_from_rfc3339(&req.opens_at)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid opens_at".into()))?
        .with_timezone(&chrono::Utc);
    
    let closes_at = chrono::DateTime::parse_from_rfc3339(&req.closes_at)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid closes_at".into()))?
        .with_timezone(&chrono::Utc);

    let ballot = service.create_ballot(
        req.tenant_id,
        req.title,
        req.description,
        opens_at,
        closes_at,
    ).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(CreateBallotResponse { ballot }))
}

async fn cast_vote(
    State(service): State<Arc<VotingService>>,
    Path(ballot_id): Path<Uuid>,
    Json(req): Json<CastVoteRequest>,
) -> std::result::Result<Json<CastVoteResponse>, (StatusCode, String)> {
    let ballot = service.create_ballot(
        Uuid::nil(),
        "".into(),
        "".into(),
        Utc::now(),
        Utc::now() + chrono::Duration::hours(24),
    ).await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to get ballot".into()))?;
    
    let op_secret = OperationSecret::from_bytes(req.operation_secret.try_into().map_err(|_| (StatusCode::BAD_REQUEST, "Invalid operation secret".into()))?);
    
    let pseudonym = Pseudonym(
        req.pseudonym
            .try_into()
            .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid pseudonym".to_string()))?,
    );

    let merkle_proof = snex_core::voting::MerkleProof {
        leaf_index: req.merkle_proof.leaf_index,
        siblings: req.merkle_proof.siblings.iter().map(|s| Hash::from_hex(s).unwrap()).collect(),
        root: Hash::from_hex(&req.merkle_proof.root).unwrap(),
    };

    let snapshot_leaf = snex_core::voting::SnapshotLeaf {
        pseudonym: Pseudonym::from_hex(&req.snapshot_leaf.pseudonym).unwrap(),
        reporting_authorised: req.snapshot_leaf.reporting_authorised,
        voting_authorised: req.snapshot_leaf.voting_authorised,
        index: req.snapshot_leaf.index,
    };

    let vote = service.cast_vote(
        &ballot,
        &op_secret,
        req.vote_value,
        pseudonym,
        merkle_proof,
        snapshot_leaf,
    ).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(CastVoteResponse {
        vote_id: vote.id,
        nullifier: vote.nullifier.to_hex(),
    }))
}

async fn finalize_ballot(
    State(service): State<Arc<VotingService>>,
    Path(ballot_id): Path<Uuid>,
) -> std::result::Result<Json<FinalizeBallotResponse>, (StatusCode, String)> {
    let tally = service.finalize_ballot(ballot_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(FinalizeBallotResponse { tally }))
}

async fn get_vote_register(
    State(service): State<Arc<VotingService>>,
    Path(ballot_id): Path<Uuid>,
) -> std::result::Result<Json<snex_core::voting::VoteRegister>, (StatusCode, String)> {
    let register = service.get_vote_register(ballot_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Vote register not found".into()))?;
    Ok(Json(register))
}

async fn get_snapshot(
    State(service): State<Arc<VotingService>>,
    Path(id): Path<Uuid>,
) -> std::result::Result<Json<SnapshotResponse>, (StatusCode, String)> {
    let snapshot = service.get_snapshot(id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Snapshot not found".into()))?;
    
    Ok(Json(SnapshotResponse {
        snapshot_id: snapshot.id,
        merkle_root: snapshot.merkle_root.to_hex(),
        size: snapshot.leaves.len(),
    }))
}

async fn get_anonymity_set(
    State(service): State<Arc<VotingService>>,
    Path(tenant_id): Path<Uuid>,
) -> std::result::Result<Json<AnonymitySetResponse>, (StatusCode, String)> {
    let count = service.get_anonymity_set(tenant_id).await;
    Ok(Json(AnonymitySetResponse { tenant_id, count }))
}

use std::sync::Arc;