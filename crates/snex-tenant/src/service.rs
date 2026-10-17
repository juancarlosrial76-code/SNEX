use snex_core::{
    tenant::{Tenant, TenantMember, TenantRole, TenantStatus, MemberStatus, GovernanceKey, TenantConfiguration, TenantAuditEntry, AuditAction, Actor, RetentionConfig},
    error::{CoreError, Result},
};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use tracing::{info, warn};

pub struct TenantService {
    tenants: Arc<RwLock<HashMap<Uuid, Tenant>>>,
    members: Arc<RwLock<HashMap<Uuid, Vec<TenantMember>>>>,
    governance_keys: Arc<RwLock<HashMap<Uuid, Vec<GovernanceKey>>>>,
    audit_log: Arc<RwLock<Vec<TenantAuditEntry>>>,
    configs: Arc<RwLock<HashMap<Uuid, TenantConfiguration>>>,
}

impl TenantService {
    pub fn new() -> Self {
        Self {
            tenants: Arc::new(RwLock::new(HashMap::new())),
            members: Arc::new(RwLock::new(HashMap::new())),
            governance_keys: Arc::new(RwLock::new(HashMap::new())),
            audit_log: Arc::new(RwLock::new(Vec::new())),
            configs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn create_tenant(&self, name: String, display_name: String) -> Result<Tenant> {
        let mut tenants = self.tenants.write().await;
        let tenant = Tenant::new(name, display_name);
        tenants.insert(tenant.id, tenant.clone());
        
        let mut members = self.members.write().await;
        members.insert(tenant.id, Vec::new());
        
        let mut configs = self.configs.write().await;
        configs.insert(tenant.id, TenantConfiguration::default());
        
        self.log_audit(tenant.id, Actor::System, AuditAction::TenantCreated, serde_json::json!({"name": tenant.name}), None, None).await;
        
        info!("Tenant created: {} ({})", tenant.display_name, tenant.id);
        Ok(tenant)
    }

    pub async fn get_tenant(&self, tenant_id: Uuid) -> Result<Option<Tenant>> {
        let tenants = self.tenants.read().await;
        Ok(tenants.get(&tenant_id).cloned())
    }

    pub async fn activate_tenant(&self, tenant_id: Uuid) -> Result<()> {
        let mut tenants = self.tenants.write().await;
        if let Some(tenant) = tenants.get_mut(&tenant_id) {
            tenant.activate();
            self.log_audit(tenant_id, Actor::System, AuditAction::TenantCreated, serde_json::json!({}), None, None).await;
        }
        Ok(())
    }

    pub async fn suspend_tenant(&self, tenant_id: Uuid) -> Result<()> {
        let mut tenants = self.tenants.write().await;
        if let Some(tenant) = tenants.get_mut(&tenant_id) {
            tenant.suspend();
            self.log_audit(tenant_id, Actor::System, AuditAction::TenantSuspended, serde_json::json!({}), None, None).await;
        }
        Ok(())
    }

    pub async fn terminate_tenant(&self, tenant_id: Uuid) -> Result<()> {
        let mut tenants = self.tenants.write().await;
        if let Some(tenant) = tenants.get_mut(&tenant_id) {
            tenant.terminate();
            self.log_audit(tenant_id, Actor::System, AuditAction::TenantTerminated, serde_json::json!({}), None, None).await;
        }
        Ok(())
    }

    pub async fn add_member(&self, tenant_id: Uuid, account_id: Uuid, role: TenantRole) -> Result<TenantMember> {
        let mut members = self.members.write().await;
        let tenant_members = members.entry(tenant_id).or_default();
        
        if tenant_members.iter().any(|m| m.account_id == account_id) {
            return Err(CoreError::AlreadyExists("Member already exists".into()));
        }
        
        let mut member = TenantMember::new(tenant_id, account_id, role.clone());
        tenant_members.push(member.clone());
        
        self.log_audit(tenant_id, Actor::System, AuditAction::MemberAdded, serde_json::json!({"account_id": account_id, "role": role.to_string()}), None, None).await;
        
        Ok(member)
    }

    pub async fn remove_member(&self, tenant_id: Uuid, account_id: Uuid) -> Result<()> {
        let mut members = self.members.write().await;
        if let Some(tenant_members) = members.get_mut(&tenant_id) {
            tenant_members.retain(|m| m.account_id != account_id);
            self.log_audit(tenant_id, Actor::System, AuditAction::MemberRemoved, serde_json::json!({"account_id": account_id}), None, None).await;
        }
        Ok(())
    }

    pub async fn change_member_role(&self, tenant_id: Uuid, account_id: Uuid, role: TenantRole) -> Result<()> {
        let mut members = self.members.write().await;
        if let Some(tenant_members) = members.get_mut(&tenant_id) {
            if let Some(member) = tenant_members.iter_mut().find(|m| m.account_id == account_id) {
                member.role = role.clone();
                self.log_audit(tenant_id, Actor::System, AuditAction::MemberRoleChanged, serde_json::json!({"account_id": account_id, "role": role.to_string()}), None, None).await;
            }
        }
        Ok(())
    }

    pub async fn authorise_reporting(&self, tenant_id: Uuid, account_id: Uuid) -> Result<()> {
        let mut members = self.members.write().await;
        if let Some(tenant_members) = members.get_mut(&tenant_id) {
            if let Some(member) = tenant_members.iter_mut().find(|m| m.account_id == account_id) {
                member.authorise_reporting();
                self.log_audit(tenant_id, Actor::System, AuditAction::MemberReportingAuthorised, serde_json::json!({"account_id": account_id}), None, None).await;
            }
        }
        Ok(())
    }

    pub async fn authorise_voting(&self, tenant_id: Uuid, account_id: Uuid) -> Result<()> {
        let mut members = self.members.write().await;
        if let Some(tenant_members) = members.get_mut(&tenant_id) {
            if let Some(member) = tenant_members.iter_mut().find(|m| m.account_id == account_id) {
                member.authorise_voting();
                self.log_audit(tenant_id, Actor::System, AuditAction::MemberVotingAuthorised, serde_json::json!({"account_id": account_id}), None, None).await;
            }
        }
        Ok(())
    }

    pub async fn get_members(&self, tenant_id: Uuid) -> Result<Vec<TenantMember>> {
        let members = self.members.read().await;
        Ok(members.get(&tenant_id).cloned().unwrap_or_default())
    }

    pub async fn add_governance_key(&self, tenant_id: Uuid, governance_key: GovernanceKey) -> Result<()> {
        let mut keys = self.governance_keys.write().await;
        keys.entry(tenant_id).or_default().push(governance_key);
        self.log_audit(tenant_id, Actor::System, AuditAction::GovernanceKeyRotated, serde_json::json!({}), None, None).await;
        Ok(())
    }

    pub async fn get_governance_keys(&self, tenant_id: Uuid) -> Result<Vec<GovernanceKey>> {
        let keys = self.governance_keys.read().await;
        Ok(keys.get(&tenant_id).cloned().unwrap_or_default())
    }

    pub async fn get_configuration(&self, tenant_id: Uuid) -> Result<TenantConfiguration> {
        let configs = self.configs.read().await;
        Ok(configs.get(&tenant_id).cloned().unwrap_or_default())
    }

    pub async fn update_configuration(&self, tenant_id: Uuid, config: TenantConfiguration) -> Result<()> {
        let mut configs = self.configs.write().await;
        configs.insert(tenant_id, config.clone());
        self.log_audit(tenant_id, Actor::System, AuditAction::ConfigurationChanged, serde_json::to_value(&config).unwrap(), None, None).await;
        Ok(())
    }

    pub async fn get_audit_log(&self, tenant_id: Uuid, limit: Option<usize>) -> Result<Vec<TenantAuditEntry>> {
        let log = self.audit_log.read().await;
        let tenant_log: Vec<_> = log.iter()
            .filter(|e| e.tenant_id == tenant_id)
            .rev()
            .take(limit.unwrap_or(100))
            .cloned()
            .collect();
        Ok(tenant_log)
    }

    async fn log_audit(&self, tenant_id: Uuid, actor: Actor, action: AuditAction, details: serde_json::Value, batch_id: Option<Uuid>, epoch: Option<u64>) {
        let entry = TenantAuditEntry {
            id: Uuid::new_v4(),
            tenant_id,
            action,
            actor,
            timestamp: Utc::now(),
            details,
            batch_id,
            epoch,
        };
        let mut log = self.audit_log.write().await;
        log.push(entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snex_core::tenant::TenantRole;

    #[tokio::test]
    async fn test_tenant_service() {
        let service = TenantService::new();
        
        let tenant = service.create_tenant("test".into(), "Test Tenant".into()).await.unwrap();
        assert_eq!(tenant.status, snex_core::tenant::TenantStatus::PendingVerification);
        
        service.activate_tenant(tenant.id).await.unwrap();
        let tenant = service.get_tenant(tenant.id).await.unwrap().unwrap();
        assert_eq!(tenant.status, snex_core::tenant::TenantStatus::Active);
        
        service.add_member(tenant.id, Uuid::new_v4(), TenantRole::Member).await.unwrap();
        let members = service.get_members(tenant.id).await.unwrap();
        assert_eq!(members.len(), 1);
    }
}