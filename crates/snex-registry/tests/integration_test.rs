use snex_registry::{service::RegistryService, state::{RegistryState, NullifierDomain, NullifierEntry, LeaseToken}, database::RegistryDatabase};
use snex_core::{voting::{Vote, VoteValue}, reporting::{Report, Case, Reply}, epoch::Epoch, error::CoreError};
use snex_crypto::{
    nullifiers::{Nullifier, OperationSecret, CaseHandle, MailboxAccess},
    key_hierarchy::Dek,
    encryption::EncryptedData,
    hashing::Hash,
};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use sqlx::PgPool;

async fn setup_test_db() -> PgPool {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgresql://snex:snex@localhost:5432/snex_test".into());
    PgPool::connect(&database_url).await.unwrap()
}

#[tokio::test]
async fn test_registry_vote_registration() {
    let pool = setup_test_db().await;
    let db = RegistryDatabase::new(pool.clone());
    let service = RegistryService::new(db);
    
    let op_secret = OperationSecret::generate();
    let ballot_id = Uuid::new_v4();
    let nullifier = op_secret.derive_vote_nullifier(ballot_id.as_bytes());
    
    let vote = Vote::new(
        ballot_id,
        nullifier,
        VoteValue::Yes,
        snex_crypto::nullifiers::Pseudonym([1u8; 32]),
        vec![],
    );
    
    service.register_vote(&vote).await.unwrap();
    
    let register = service.get_vote_register(ballot_id).await.unwrap().unwrap();
    assert_eq!(register.entries.len(), 1);
    assert!(register.entries.contains_key(&nullifier));
}

#[tokio::test]
async fn test_registry_double_vote_rejection() {
    let pool = setup_test_db().await;
    let db = RegistryDatabase::new(pool.clone());
    let service = RegistryService::new(db);
    
    let op_secret = OperationSecret::generate();
    let ballot_id = Uuid::new_v4();
    let nullifier = op_secret.derive_vote_nullifier(ballot_id.as_bytes());
    
    let vote1 = Vote::new(ballot_id, nullifier, VoteValue::Yes, snex_crypto::nullifiers::Pseudonym([1u8; 32]), vec![]);
    service.register_vote(&vote1).await.unwrap();
    
    let vote2 = Vote::new(ballot_id, nullifier, VoteValue::No, snex_crypto::nullifiers::Pseudonym([2u8; 32]), vec![]);
    let result = service.register_vote(&vote2).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), CoreError::DoubleVote));
}

#[tokio::test]
async fn test_registry_vote_finalization() {
    let pool = setup_test_db().await;
    let db = RegistryDatabase::new(pool.clone());
    let service = RegistryService::new(db);
    
    let ballot_id = Uuid::new_v4();
    let op_secret = OperationSecret::generate();
    let nullifier = op_secret.derive_vote_nullifier(ballot_id.as_bytes());
    
    let vote = Vote::new(ballot_id, nullifier, VoteValue::Yes, snex_crypto::nullifiers::Pseudonym([1u8; 32]), vec![]);
    service.register_vote(&vote).await.unwrap();
    
    service.finalize_vote_register(ballot_id).await.unwrap();
    
    let register = service.get_vote_register(ballot_id).await.unwrap().unwrap();
    assert!(register.finalized);
    assert!(register.anchored_at.is_some());
}

#[tokio::test]
async fn test_registry_report_registration() {
    let pool = setup_test_db().await;
    let db = RegistryDatabase::new(pool.clone());
    let service = RegistryService::new(db);
    
    let op_secret = OperationSecret::generate();
    let tenant_id = Uuid::new_v4();
    let rate_limit_tag = op_secret.derive_report_nullifier(0, 0);
    
    let report = Report::new(
        tenant_id,
        Uuid::new_v4(),
        rate_limit_tag,
        EncryptedData(vec![1,2,3]),
        vec![],
        Epoch::current(),
    );
    
    let case = snex_core::reporting::Case::new(
        &report,
        Dek::generate(),
        vec![],
        vec![],
        Uuid::new_v4(),
    );
    
    service.register_report(&report, &case).await.unwrap();
    
    let exists = service.check_nullifier(snex_registry::state::NullifierDomain::Report, &rate_limit_tag).await;
    assert!(exists);
}

#[tokio::test]
async fn test_registry_double_report_rejection() {
    let pool = setup_test_db().await;
    let db = RegistryDatabase::new(pool.clone());
    let service = RegistryService::new(db);
    
    let op_secret = OperationSecret::generate();
    let tenant_id = Uuid::new_v4();
    let rate_limit_tag = op_secret.derive_report_nullifier(0, 0);
    
    let report1 = Report::new(tenant_id, Uuid::new_v4(), rate_limit_tag, EncryptedData(vec![1]), vec![], Epoch::current());
    let case1 = snex_core::reporting::Case::new(&report1, Dek::generate(), vec![], vec![], Uuid::new_v4());
    service.register_report(&report1, &case1).await.unwrap();
    
    let report2 = Report::new(tenant_id, Uuid::new_v4(), rate_limit_tag, EncryptedData(vec![2]), vec![], Epoch::current());
    let case2 = snex_core::reporting::Case::new(&report2, Dek::generate(), vec![], vec![], Uuid::new_v4());
    
    let result = service.register_report(&report2, &case2).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), CoreError::DoubleReport));
}

#[tokio::test]
async fn test_registry_reply_handling() {
    let pool = setup_test_db().await;
    let db = RegistryDatabase::new(pool.clone());
    let service = RegistryService::new(db);
    
    let op_secret = OperationSecret::generate();
    let tenant_id = Uuid::new_v4();
    let rate_limit_tag = op_secret.derive_report_nullifier(0, 0);
    
    let report = Report::new(tenant_id, Uuid::new_v4(), rate_limit_tag, EncryptedData(vec![1]), vec![], Epoch::current());
    let case = snex_core::reporting::Case::new(&report, Dek::generate(), vec![], vec![], Uuid::new_v4());
    service.register_report(&report, &case).await.unwrap();
    
    let reply = Reply::new(case.id, EncryptedData(vec![4,5,6]), snex_core::reporting::ReplySender::Officer);
    service.add_reply(case.id, &reply).await.unwrap();
    
    let mailbox = service.get_mailbox(&report.case_handle).await.unwrap().unwrap();
    assert_eq!(mailbox.messages.len(), 1);
    assert_eq!(mailbox.messages[0].content.0, vec![4,5,6]);
}

#[tokio::test]
async fn test_registry_case_handover() {
    let pool = setup_test_db().await;
    let db = RegistryDatabase::new(pool.clone());
    let service = RegistryService::new(db);
    
    let op_secret = OperationSecret::generate();
    let tenant_id = Uuid::new_v4();
    let rate_limit_tag = op_secret.derive_report_nullifier(0, 0);
    
    let report = Report::new(tenant_id, Uuid::new_v4(), rate_limit_tag, EncryptedData(vec![1]), vec![], Epoch::current());
    let case = snex_core::reporting::Case::new(&report, Dek::generate(), vec![], vec![], Uuid::new_v4());
    service.register_report(&report, &case).await.unwrap();
    
    service.handover_case(case.id, vec![7,8,9]).await.unwrap();
    
    let mailbox = service.get_mailbox(&report.case_handle).await.unwrap().unwrap();
    assert_eq!(mailbox.case_handle, report.case_handle);
}

#[tokio::test]
async fn test_registry_case_closure() {
    let pool = setup_test_db().await;
    let db = RegistryDatabase::new(pool.clone());
    let service = RegistryService::new(db);
    
    let op_secret = OperationSecret::generate();
    let tenant_id = Uuid::new_v4();
    let rate_limit_tag = op_secret.derive_report_nullifier(0, 0);
    
    let report = Report::new(tenant_id, Uuid::new_v4(), rate_limit_tag, EncryptedData(vec![1]), vec![], Epoch::current());
    let case = snex_core::reporting::Case::new(&report, Dek::generate(), vec![], vec![], Uuid::new_v4());
    service.register_report(&report, &case).await.unwrap();
    
    service.close_case(case.id).await.unwrap();
    
    let state = service.state.read().await;
    let closed_case = state.cases.get(&case.id).unwrap();
    assert_eq!(closed_case.status, snex_core::reporting::CaseStatus::Closed);
    assert!(closed_case.closed_at.is_some());
}

#[tokio::test]
async fn test_registry_block_list() {
    let pool = setup_test_db().await;
    let db = RegistryDatabase::new(pool.clone());
    let service = RegistryService::new(db);
    
    let op_secret = OperationSecret::generate();
    let nullifier = op_secret.derive_vote_nullifier(b"ballot1");
    
    let blocked = service.is_blocked(snex_registry::state::NullifierDomain::Vote, &nullifier).await;
    assert!(!blocked);
    
    service.add_to_block_list(snex_registry::state::NullifierDomain::Vote, nullifier).await;
    
    let blocked = service.is_blocked(snex_registry::state::NullifierDomain::Vote, &nullifier).await;
    assert!(blocked);
}

#[tokio::test]
async fn test_registry_termination_list() {
    let pool = setup_test_db().await;
    let db = RegistryDatabase::new(pool.clone());
    let service = RegistryService::new(db);
    
    let tenant_id = Uuid::new_v4();
    let epoch = Epoch::current();
    let pseudonym_hash = Hash([42u8; 32]);
    
    let terminated = service.is_terminated(tenant_id, &pseudonym_hash).await;
    assert!(!terminated);
    
    service.add_termination(tenant_id, pseudonym_hash, epoch, 0).await;
    
    let terminated = service.is_terminated(tenant_id, &pseudonym_hash).await;
    assert!(terminated);
}

#[tokio::test]
async fn test_registry_lease_fencing() {
    let pool = setup_test_db().await;
    let db = RegistryDatabase::new(pool.clone());
    let service = RegistryService::new(db);
    
    let instance_id = Uuid::new_v4();
    let acquired = service.state.write().await.acquire_lease(instance_id, 30);
    assert!(acquired);
    
    let token = service.get_current_lease_token().await.unwrap();
    assert_eq!(token.instance_id, instance_id);
    assert_eq!(token.fencing_token, 1);
    
    let valid = service.check_fencing_token(1);
    assert!(valid);
    
    let valid = service.check_fencing_token(2);
    assert!(!valid);
}

#[tokio::test]
async fn test_registry_admission_journal() {
    let pool = setup_test_db().await;
    let db = RegistryDatabase::new(pool.clone());
    let service = RegistryService::new(db);
    
    let op_secret = OperationSecret::generate();
    let nullifier = op_secret.derive_vote_nullifier(b"ballot1");
    
    let vote = Vote::new(Uuid::new_v4(), nullifier, VoteValue::Yes, snex_crypto::nullifiers::Pseudonym([1u8; 32]), vec![]);
    service.register_vote(&vote).await.unwrap();
    
    let journal = service.get_admission_journal(Epoch::current(), None).await.unwrap();
    assert!(!journal.is_empty());
    assert!(journal.iter().any(|e| e.nullifier == nullifier));
}