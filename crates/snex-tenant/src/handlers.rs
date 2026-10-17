use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post, put, delete},
    Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use snex_core::{
    tenant::{Tenant, TenantMember, TenantRole, TenantConfiguration, TenantAuditEntry, AuditAction, Actor},
    error::{CoreError, Result},
};
use crate::service::TenantService;

#[derive(Deserialize)]
pub struct CreateTenantRequest {
    pub name: String,
    pub display_name: String,
}

#[derive(Serialize)]
pub struct CreateTenantResponse {
    pub tenant: Tenant,
}

#[derive(Deserialize)]
pub struct AddMemberRequest {
    pub account_id: Uuid,
    pub role: TenantRole,
}

#[derive(Serialize)]
pub struct AddMemberResponse {
    pub member: TenantMember,
}

#[derive(Deserialize)]
pub struct ChangeRoleRequest {
    pub role: TenantRole,
}

#[derive(Deserialize)]
pub struct UpdateConfigRequest {
    pub config: TenantConfiguration,
}

#[derive(Serialize)]
pub struct AuditLogResponse {
    pub entries: Vec<TenantAuditEntry>,
}

pub fn router() -> Router<Arc<TenantService>> {
    Router::new()
        .route("/tenants", post(create_tenant))
        .route("/tenants/:id", get(get_tenant))
        .route("/tenants/:id/activate", post(activate_tenant))
        .route("/tenants/:id/suspend", post(suspend_tenant))
        .route("/tenants/:id/terminate", post(terminate_tenant))
        .route("/tenants/:id/members", post(add_member))
        .route("/tenants/:id/members", get(get_members))
        .route("/tenants/:id/members/:account_id", delete(remove_member))
        .route("/tenants/:id/members/:account_id/role", put(change_member_role))
        .route("/tenants/:id/members/:account_id/reporting", post(authorise_reporting))
        .route("/tenants/:id/members/:account_id/voting", post(authorise_voting))
        .route("/tenants/:id/governance-keys", get(get_governance_keys))
        .route("/tenants/:id/config", get(get_config))
        .route("/tenants/:id/config", put(update_config))
        .route("/tenants/:id/audit", get(get_audit_log))
}

async fn create_tenant(
    State(service): State<Arc<TenantService>>,
    Json(req): Json<CreateTenantRequest>,
) -> Result<Json<CreateTenantResponse>, (StatusCode, String)> {
    let tenant = service.create_tenant(req.name, req.display_name).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(CreateTenantResponse { tenant }))
}

async fn get_tenant(
    State(service): State<Arc<TenantService>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Tenant>, (StatusCode, String)> {
    let tenant = service.get_tenant(id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Tenant not found".into()))?;
    Ok(Json(tenant))
}

async fn activate_tenant(
    State(service): State<Arc<TenantService>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    service.activate_tenant(id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::OK)
}

async fn suspend_tenant(
    State(service): State<Arc<TenantService>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    service.suspend_tenant(id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::OK)
}

async fn terminate_tenant(
    State(service): State<Arc<TenantService>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    service.terminate_tenant(id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::OK)
}

async fn add_member(
    State(service): State<Arc<TenantService>>,
    Path(tenant_id): Path<Uuid>,
    Json(req): Json<AddMemberRequest>,
) -> Result<Json<AddMemberResponse>, (StatusCode, String)> {
    let member = service.add_member(tenant_id, req.account_id, req.role).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(AddMemberResponse { member }))
}

async fn get_members(
    State(service): State<Arc<TenantService>>,
    Path(tenant_id): Path<Uuid>,
) -> Result<Json<Vec<TenantMember>>, (StatusCode, String)> {
    let members = service.get_members(tenant_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(members))
}

async fn remove_member(
    State(service): State<Arc<TenantService>>,
    Path((tenant_id, account_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, (StatusCode, String)> {
    service.remove_member(tenant_id, account_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::OK)
}

async fn change_member_role(
    State(service): State<Arc<TenantService>>,
    Path((tenant_id, account_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<ChangeRoleRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    service.change_member_role(tenant_id, account_id, req.role).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::OK)
}

async fn authorise_reporting(
    State(service): State<Arc<TenantService>>,
    Path((tenant_id, account_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, (StatusCode, String)> {
    service.authorise_reporting(tenant_id, account_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::OK)
}

async fn authorise_voting(
    State(service): State<Arc<TenantService>>,
    Path((tenant_id, account_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, (StatusCode, String)> {
    service.authorise_voting(tenant_id, account_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::OK)
}

async fn get_governance_keys(
    State(service): State<Arc<TenantService>>,
    Path(tenant_id): Path<Uuid>,
) -> Result<Json<Vec<snex_core::tenant::GovernanceKey>>, (StatusCode, String)> {
    let keys = service.get_governance_keys(tenant_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(keys))
}

async fn get_config(
    State(service): State<Arc<TenantService>>,
    Path(tenant_id): Path<Uuid>,
) -> Result<Json<TenantConfiguration>, (StatusCode, String)> {
    let config = service.get_configuration(tenant_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(config))
}

async fn update_config(
    State(service): State<Arc<TenantService>>,
    Path(tenant_id): Path<Uuid>,
    Json(req): Json<UpdateConfigRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    service.update_configuration(tenant_id, req.config).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::OK)
}

async fn get_audit_log(
    State(service): State<Arc<TenantService>>,
    Path(tenant_id): Path<Uuid>,
    Query(params): Query<AuditLogQuery>,
) -> Result<Json<AuditLogResponse>, (StatusCode, String)> {
    let entries = service.get_audit_log(tenant_id, params.limit).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(AuditLogResponse { entries }))
}

#[derive(Deserialize)]
pub struct AuditLogQuery {
    pub limit: Option<usize>,
}

use std::sync::Arc;