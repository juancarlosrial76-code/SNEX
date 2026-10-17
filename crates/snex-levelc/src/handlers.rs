use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post, delete},
    Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use snex_core::{
    levelc::{LevelCRoom, RoomRole},
};
use crate::service::LevelCService;

#[derive(Deserialize)]
pub struct CreateRoomRequest {
    pub tenant_id: Uuid,
    pub name: String,
    pub description: String,
    pub created_by: Uuid,
    pub rule_set: RoomRuleSetDto,
}

#[derive(Serialize)]
pub struct CreateRoomResponse {
    pub room: LevelCRoom,
}

#[derive(Deserialize, Serialize)]
pub struct RoomRuleSetDto {
    pub add_permission: PermissionRuleDto,
    pub remove_permission: PermissionRuleDto,
    pub external_join_permission: PermissionRuleDto,
    pub version: u32,
}

#[derive(Deserialize, Serialize)]
pub struct PermissionRuleDto {
    pub allowed_roles: Vec<String>,
    pub requires_approval: bool,
    pub approval_quorum: u32,
}

#[derive(Deserialize)]
pub struct AddMemberRequest {
    pub account_id: Uuid,
    pub device: MemberDeviceDto,
    pub added_by: Uuid,
}

#[derive(Deserialize)]
pub struct AddDeviceRequest {
    pub device: MemberDeviceDto,
}

#[derive(Deserialize, Serialize)]
pub struct MemberDeviceDto {
    pub device_id: Uuid,
    pub leaf_index: u32,
    pub signature_key: Vec<u8>,
    pub encryption_key: Vec<u8>,
}

#[derive(Deserialize)]
pub struct DeviceBackupRequest {
    pub account_id: Uuid,
    pub device_id: Uuid,
    pub recovery_phrase: String,
    pub mls_private_keys: Vec<u8>,
}

#[derive(Deserialize)]
pub struct RestoreBackupRequest {
    pub recovery_phrase: String,
}

#[derive(Serialize)]
pub struct RestoreBackupResponse {
    pub mls_private_keys: Vec<u8>,
}

#[derive(Deserialize)]
pub struct RecoveryBackupRequest {
    pub account_id: Uuid,
    pub recovery_phrase: String,
    pub backup_data: Vec<u8>,
}

#[derive(Deserialize)]
pub struct RestoreRecoveryRequest {
    pub recovery_phrase: String,
}

#[derive(Serialize)]
pub struct RestoreRecoveryResponse {
    pub backup_data: Vec<u8>,
}

pub fn router() -> Router<Arc<LevelCService>> {
    Router::new()
        .route("/rooms", post(create_room))
        .route("/rooms/:id", get(get_room))
        .route("/rooms/:id/members", post(add_member))
        .route("/rooms/:id/members/:account_id", delete(remove_member))
        .route("/rooms/:id/members/:account_id/devices", post(add_device))
        .route("/rooms/:id/members/:account_id/devices/:device_id", delete(remove_device))
        .route("/backups/device", post(create_device_backup))
        .route("/backups/device/:device_id", post(restore_device_backup))
        .route("/backups/recovery", post(create_recovery_backup))
        .route("/backups/recovery/:account_id", post(restore_recovery_backup))
        .route("/rooms/:id/verify-change/:version", get(verify_group_change))
        .route("/rooms/:id/freshness/:account_id/:lag", get(update_freshness))
}

async fn create_room(
    State(service): State<Arc<LevelCService>>,
    Json(req): Json<CreateRoomRequest>,
) -> std::result::Result<Json<CreateRoomResponse>, (StatusCode, String)> {
    let rule_set = snex_core::levelc::RoomRuleSet {
        add_permission: snex_core::levelc::PermissionRule {
            allowed_roles: req.rule_set.add_permission.allowed_roles.iter()
                .filter_map(|r| r.parse::<RoomRole>().ok())
                .collect(),
            requires_approval: req.rule_set.add_permission.requires_approval,
            approval_quorum: req.rule_set.add_permission.approval_quorum,
        },
        remove_permission: snex_core::levelc::PermissionRule {
            allowed_roles: req.rule_set.remove_permission.allowed_roles.iter()
                .filter_map(|r| r.parse::<RoomRole>().ok())
                .collect(),
            requires_approval: req.rule_set.remove_permission.requires_approval,
            approval_quorum: req.rule_set.remove_permission.approval_quorum,
        },
        external_join_permission: snex_core::levelc::PermissionRule {
            allowed_roles: req.rule_set.external_join_permission.allowed_roles.iter()
                .filter_map(|r| r.parse::<RoomRole>().ok())
                .collect(),
            requires_approval: req.rule_set.external_join_permission.requires_approval,
            approval_quorum: req.rule_set.external_join_permission.approval_quorum,
        },
        version: req.rule_set.version,
    };

    let room = service.create_room(
        req.tenant_id,
        req.name,
        req.description,
        req.created_by,
        rule_set,
    ).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(CreateRoomResponse { room }))
}

async fn get_room(
    State(service): State<Arc<LevelCService>>,
    Path(id): Path<Uuid>,
) -> std::result::Result<Json<LevelCRoom>, (StatusCode, String)> {
    let room = service.get_room(id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Room not found".into()))?;
    Ok(Json(room))
}

async fn add_member(
    State(service): State<Arc<LevelCService>>,
    Path(room_id): Path<Uuid>,
    Json(req): Json<AddMemberRequest>,
) -> std::result::Result<StatusCode, (StatusCode, String)> {
    let device = snex_core::levelc::MemberDevice {
        device_id: req.device.device_id,
        leaf_index: req.device.leaf_index,
        signature_key: req.device.signature_key,
        encryption_key: req.device.encryption_key,
        added_at: chrono::Utc::now(),
        last_sync_at: None,
    };

    service.add_member(room_id, req.account_id, device, req.added_by).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::OK)
}

async fn remove_member(
    State(service): State<Arc<LevelCService>>,
    Path((room_id, account_id)): Path<(Uuid, Uuid)>,
) -> std::result::Result<StatusCode, (StatusCode, String)> {
    service.remove_member(room_id, account_id, Uuid::nil()).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::OK)
}

async fn add_device(
    State(service): State<Arc<LevelCService>>,
    Path((room_id, account_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<AddDeviceRequest>,
) -> std::result::Result<StatusCode, (StatusCode, String)> {
    let device = snex_core::levelc::MemberDevice {
        device_id: req.device.device_id,
        leaf_index: req.device.leaf_index,
        signature_key: req.device.signature_key,
        encryption_key: req.device.encryption_key,
        added_at: chrono::Utc::now(),
        last_sync_at: None,
    };

    service.add_device(room_id, account_id, device).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::OK)
}

async fn remove_device(
    State(service): State<Arc<LevelCService>>,
    Path((room_id, account_id, device_id)): Path<(Uuid, Uuid, Uuid)>,
) -> std::result::Result<StatusCode, (StatusCode, String)> {
    service.remove_device(room_id, account_id, device_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::OK)
}

async fn create_device_backup(
    State(service): State<Arc<LevelCService>>,
    Json(req): Json<DeviceBackupRequest>,
) -> std::result::Result<StatusCode, (StatusCode, String)> {
    service.create_device_backup(
        req.account_id,
        req.device_id,
        &req.recovery_phrase,
        req.mls_private_keys,
    ).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::OK)
}

async fn restore_device_backup(
    State(service): State<Arc<LevelCService>>,
    Path(device_id): Path<Uuid>,
    Json(req): Json<RestoreBackupRequest>,
) -> std::result::Result<Json<RestoreBackupResponse>, (StatusCode, String)> {
    let keys = service.restore_device_backup(device_id, &req.recovery_phrase).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(RestoreBackupResponse { mls_private_keys: keys }))
}

async fn create_recovery_backup(
    State(service): State<Arc<LevelCService>>,
    Json(req): Json<RecoveryBackupRequest>,
) -> std::result::Result<StatusCode, (StatusCode, String)> {
    service.create_recovery_backup(req.account_id, &req.recovery_phrase, req.backup_data).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::OK)
}

async fn restore_recovery_backup(
    State(service): State<Arc<LevelCService>>,
    Path(account_id): Path<Uuid>,
    Json(req): Json<RestoreRecoveryRequest>,
) -> std::result::Result<Json<RestoreRecoveryResponse>, (StatusCode, String)> {
    let data = service.restore_recovery_backup(account_id, &req.recovery_phrase).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(RestoreRecoveryResponse { backup_data: data }))
}

async fn verify_group_change(
    State(service): State<Arc<LevelCService>>,
    Path((room_id, version)): Path<(Uuid, u32)>,
) -> std::result::Result<Json<bool>, (StatusCode, String)> {
    let valid = service.verify_group_change(room_id, version).await;
    Ok(Json(valid))
}

async fn update_freshness(
    State(service): State<Arc<LevelCService>>,
    Path((room_id, account_id, lag)): Path<(Uuid, Uuid, u64)>,
) -> std::result::Result<Json<bool>, (StatusCode, String)> {
    let fresh = service.update_freshness(room_id, account_id, lag).await;
    Ok(Json(fresh))
}

use std::sync::Arc;