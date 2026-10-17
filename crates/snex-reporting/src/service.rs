use snex_core::{
    reporting::{Report, Case, Reply, RateLimitWindow, ReportWindowSchedule, ReportingOffice, ExternalIntakeReport, ExternalVerificationLevel},
    epoch::Epoch,
    tenant::TenantRole,
    error::{CoreError, Result},
};
use snex_crypto::{
    nullifiers::{Nullifier, CaseHandle, OperationSecret, MailboxBaseSecret},
    key_hierarchy::Dek,
    encryption::EncryptedData,
};
use snex_registry::service::RegistryService;
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use std::sync::Arc;
use tracing::{info, warn};

pub struct ReportingService {
    registry: Arc<RegistryService>,
    config: snex_core::config::AppConfig,
}

impl ReportingService {
    pub fn new(registry: Arc<RegistryService>, config: snex_core::config::AppConfig) -> Self {
        Self { registry, config }
    }

    pub async fn submit_report(
        &self,
        tenant_id: Uuid,
        reporting_office_id: Uuid,
        operation_secret: &OperationSecret,
        report_window: u64,
        slot: u32,
        content: EncryptedData,
        case_key_wrapped: Vec<u8>,
    ) -> Result<(Report, Case)> {
        let rate_limit_tag = operation_secret.derive_report_nullifier(report_window, slot);
        
        let blocked = self.registry.is_blocked(snex_registry::state::NullifierDomain::Report, &rate_limit_tag).await;
        if blocked {
            return Err(CoreError::RateLimitExceeded);
        }
        
        let exists = self.registry.check_nullifier(snex_registry::state::NullifierDomain::Report, &rate_limit_tag).await;
        if exists {
            return Err(CoreError::DoubleReport);
        }
        
        let report = Report::new(tenant_id, reporting_office_id, rate_limit_tag, content, case_key_wrapped, Epoch::current());
        let case_key = Dek::generate();
        let case = snex_core::reporting::Case::new(
            &report,
            case_key,
            vec![],
            vec![],
            Uuid::new_v4(),
        );
        
        self.registry.register_report(&report, &case).await?;
        
        info!("Report submitted: {} for tenant {}", report.id, tenant_id);
        Ok((report, case))
    }

    pub async fn submit_reply(&self, case_id: Uuid, content: EncryptedData, sent_by: snex_core::reporting::ReplySender) -> Result<Reply> {
        let reply = Reply::new(case_id, content, sent_by);
        self.registry.add_reply(case_id, &reply).await?;
        Ok(reply)
    }

    pub async fn handover_case(&self, case_id: Uuid, new_officer_key: Vec<u8>) -> Result<()> {
        self.registry.handover_case(case_id, new_officer_key).await
    }

    pub async fn close_case(&self, case_id: Uuid) -> Result<()> {
        self.registry.close_case(case_id).await
    }

    pub async fn get_mailbox(&self, case_handle: &CaseHandle) -> Result<Option<snex_registry::state::Mailbox>> {
        self.registry.get_mailbox(case_handle).await
    }

    pub async fn check_rate_limit(&self, tenant_id: Uuid, operation_secret: &OperationSecret, window: u64) -> Result<bool> {
        let tag = operation_secret.derive_rate_limit_tag(window, tenant_id.as_bytes());
        let blocked = self.registry.is_blocked(snex_registry::state::NullifierDomain::RateLimit, &tag).await;
        let exists = self.registry.check_nullifier(snex_registry::state::NullifierDomain::RateLimit, &tag).await;
        Ok(!blocked && !exists)
    }

    pub async fn create_reporting_office(&self, tenant_id: Uuid, name: String) -> Result<ReportingOffice> {
        let office = ReportingOffice {
            id: Uuid::new_v4(),
            tenant_id,
            name,
            role_key_id: Uuid::new_v4(),
            case_key_rotation_days: 30,
            handover_period_hours: 24,
            active: true,
        };
        Ok(office)
    }

    pub async fn submit_external_intake(
        &self,
        tenant_id: Uuid,
        content: EncryptedData,
        proof_of_work: Vec<u8>,
    ) -> Result<ExternalIntakeReport> {
        let report = ExternalIntakeReport {
            id: Uuid::new_v4(),
            tenant_id,
            content,
            proof_of_work,
            submitted_at: Utc::now(),
            verification_level: ExternalVerificationLevel::ProofOfWork,
            assigned_office_id: None,
        };
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snex_core::config::AppConfig;
    use snex_crypto::nullifiers::OperationSecret;
    use sqlx::PgPool;

    #[tokio::test]
    async fn test_reporting_service() {
        let pool = PgPool::connect("postgresql://localhost/snex_test").await.unwrap();
        let registry_db = snex_registry::database::RegistryDatabase::new(pool);
        let registry = Arc::new(snex_registry::service::RegistryService::new(registry_db));
        let config = AppConfig::default();
        let service = ReportingService::new(registry, config);
        
        let op_secret = OperationSecret::generate();
        let content = snex_crypto::encryption::EncryptedData(vec![1,2,3]);
        
        let result = service.submit_report(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &op_secret,
            0,
            0,
            content,
            vec![],
        ).await;
        
        assert!(result.is_ok());
    }
}