use snex_reporting::service::ReportingService;
use snex_core::{
    reporting::{Report, Case, Reply, RateLimitWindow, ExternalIntakeReport, ExternalVerificationLevel, ReplySender},
    epoch::Epoch,
    error::CoreError,
};
use snex_crypto::{
    nullifiers::{Nullifier, OperationSecret, CaseHandle},
    key_hierarchy::Dek,
    encryption::EncryptedData,
};
use snex_registry::service::RegistryService;
use snex_registry::database::RegistryDatabase;
use snex_core::config::AppConfig;
use uuid::Uuid;
use chrono::Utc;
use sqlx::PgPool;

async fn setup_test_db() -> PgPool {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgresql://snex:snex@localhost:5432/snex_test".into());
    PgPool::connect(&database_url).await.unwrap()
}

async fn setup_services(pool: PgPool) -> (ReportingService, std::sync::Arc<RegistryService>) {
    let config = AppConfig::default();
    
    let registry_db = RegistryDatabase::new(pool.clone());
    let registry = std::sync::Arc::new(RegistryService::new(registry_db));
    registry.initialize().await.unwrap();
    
    let reporting = ReportingService::new(registry.clone(), config);
    
    (reporting, registry)
}

#[tokio::test]
async fn test_reporting_submit_report() {
    let pool = setup_test_db().await;
    let (reporting, _registry) = setup_services(pool).await;
    
    let tenant_id = Uuid::new_v4();
    let reporting_office_id = Uuid::new_v4();
    let op_secret = OperationSecret::generate();
    
    let (report, case) = reporting.submit_report(
        tenant_id,
        reporting_office_id,
        &op_secret,
        0,
        0,
        EncryptedData(vec![1,2,3]),
        vec![],
    ).await.unwrap();
    
    assert_eq!(report.tenant_id, tenant_id);
    assert_eq!(report.reporting_office_id, reporting_office_id);
    assert_eq!(report.status, snex_core::reporting::ReportStatus::Submitted);
    assert!(!report.case_handle.as_bytes().iter().all(|&b| b == 0));
    
    assert_eq!(case.report_id, report.id);
    assert_eq!(case.tenant_id, tenant_id);
    assert_eq!(case.status, snex_core::reporting::CaseStatus::Open);
}

#[tokio::test]
async fn test_reporting_rate_limit() {
    let pool = setup_test_db().await;
    let (reporting, _registry) = setup_services(pool).await;
    
    let tenant_id = Uuid::new_v4();
    let reporting_office_id = Uuid::new_v4();
    let op_secret = OperationSecret::generate();
    
    for slot in 0..3 {
        let (_, _) = reporting.submit_report(
            tenant_id,
            reporting_office_id,
            &op_secret,
            0,
            slot,
            EncryptedData(vec![1,2,3]),
            vec![],
        ).await.unwrap();
    }
    
    let result = reporting.submit_report(
        tenant_id,
        reporting_office_id,
        &op_secret,
        0,
        3,
        EncryptedData(vec![4,5,6]),
        vec![],
    ).await;
    
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), CoreError::RateLimitExceeded));
}

#[tokio::test]
async fn test_reporting_reply() {
    let pool = setup_test_db().await;
    let (reporting, _registry) = setup_services(pool).await;
    
    let tenant_id = Uuid::new_v4();
    let reporting_office_id = Uuid::new_v4();
    let op_secret = OperationSecret::generate();
    
    let (report, case) = reporting.submit_report(
        tenant_id,
        reporting_office_id,
        &op_secret,
        0,
        0,
        EncryptedData(vec![1,2,3]),
        vec![],
    ).await.unwrap();
    
    let reply = reporting.submit_reply(case.id, EncryptedData(vec![4,5,6]), ReplySender::Officer).await.unwrap();
    assert_eq!(reply.case_id, case.id);
    assert_eq!(reply.sent_by, ReplySender::Officer);
    
    let reporter_reply = reporting.submit_reply(case.id, EncryptedData(vec![7,8,9]), ReplySender::Reporter).await.unwrap();
    assert_eq!(reporter_reply.sent_by, ReplySender::Reporter);
}

#[tokio::test]
async fn test_reporting_case_handover() {
    let pool = setup_test_db().await;
    let (reporting, _registry) = setup_services(pool).await;
    
    let tenant_id = Uuid::new_v4();
    let reporting_office_id = Uuid::new_v4();
    let op_secret = OperationSecret::generate();
    
    let (_, case) = reporting.submit_report(
        tenant_id,
        reporting_office_id,
        &op_secret,
        0,
        0,
        EncryptedData(vec![1,2,3]),
        vec![],
    ).await.unwrap();
    
    reporting.handover_case(case.id, vec![10,11,12]).await.unwrap();
}

#[tokio::test]
async fn test_reporting_case_closure() {
    let pool = setup_test_db().await;
    let (reporting, _registry) = setup_services(pool).await;
    
    let tenant_id = Uuid::new_v4();
    let reporting_office_id = Uuid::new_v4();
    let op_secret = OperationSecret::generate();
    
    let (_, case) = reporting.submit_report(
        tenant_id,
        reporting_office_id,
        &op_secret,
        0,
        0,
        EncryptedData(vec![1,2,3]),
        vec![],
    ).await.unwrap();
    
    reporting.close_case(case.id).await.unwrap();
}

#[tokio::test]
async fn test_reporting_mailbox_access() {
    let pool = setup_test_db().await;
    let (reporting, _registry) = setup_services(pool).await;
    
    let tenant_id = Uuid::new_v4();
    let reporting_office_id = Uuid::new_v4();
    let op_secret = OperationSecret::generate();
    
    let (report, _) = reporting.submit_report(
        tenant_id,
        reporting_office_id,
        &op_secret,
        0,
        0,
        EncryptedData(vec![1,2,3]),
        vec![],
    ).await.unwrap();
    
    let mailbox = reporting.get_mailbox(&report.case_handle).await.unwrap().unwrap();
    assert_eq!(mailbox.case_handle, report.case_handle);
    assert!(mailbox.messages.is_empty());
}

#[tokio::test]
async fn test_reporting_external_intake() {
    let pool = setup_test_db().await;
    let (reporting, _registry) = setup_services(pool).await;
    
    let tenant_id = Uuid::new_v4();
    
    let ext_report = reporting.submit_external_intake(
        tenant_id,
        EncryptedData(vec![1,2,3]),
        vec![100,101,102],
    ).await.unwrap();
    
    assert_eq!(ext_report.tenant_id, tenant_id);
    assert_eq!(ext_report.verification_level, ExternalVerificationLevel::ProofOfWork);
    assert!(!ext_report.proof_of_work.is_empty());
}

#[tokio::test]
async fn test_reporting_rate_limit_window() {
    let mut window = RateLimitWindow::new(0, Uuid::new_v4(), 3);
    let op_secret = OperationSecret::generate();
    let tag = op_secret.derive_rate_limit_tag(0, b"tenant");
    
    for i in 0..3 {
        window.check_and_consume(&tag).unwrap();
    }
    
    assert!(window.check_and_consume(&tag).is_err());
}

#[tokio::test]
async fn test_reporting_window_schedule() {
    let schedule = snex_core::reporting::ReportWindowSchedule::default();
    let window_start = schedule.current_window_start();
    assert_eq!(schedule.window_for_timestamp(window_start + 3600), window_start);
    assert_eq!(schedule.window_for_timestamp(window_start + 24 * 3600), window_start + 24 * 3600);
}

#[tokio::test]
async fn test_reporting_office_creation() {
    let pool = setup_test_db().await;
    let (reporting, _registry) = setup_services(pool).await;
    
    let tenant_id = Uuid::new_v4();
    let office = reporting.create_reporting_office(tenant_id, "Compliance Office".into()).await.unwrap();
    
    assert_eq!(office.tenant_id, tenant_id);
    assert_eq!(office.name, "Compliance Office");
    assert!(office.active);
}