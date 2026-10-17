use snex_issuer::{service::IssuerService, state::IssuerState, database::IssuerDatabase};
use snex_core::{config::AppConfig, identity::Account, epoch::Epoch, error::CoreError};
use snex_crypto::{
    bbs::{BbsSecretKey, BbsPublicKey, BbsCredential, blind_issue},
    commitments::{CommitmentKey, Commitment, PedersenCommitment, BlindedCommitment},
    nullifiers::{OperationSecret, PseudonymSecret},
    key_hierarchy::MasterKey,
    hashing::Hash,
};
use uuid::Uuid;
use chrono::Utc;
use sqlx::PgPool;

async fn setup_test_db() -> PgPool {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgresql://snex:snex@localhost:5432/snex_test".into());
    PgPool::connect(&database_url).await.unwrap()
}

#[tokio::test]
async fn test_issuer_create_account() {
    let pool = setup_test_db().await;
    let config = AppConfig::default();
    let master_key = MasterKey::generate();
    let issuer_sk = BbsSecretKey::generate();
    
    let state = IssuerState::new(config.clone(), master_key, issuer_sk);
    let db = IssuerDatabase::new(pool.clone());
    let service = IssuerService { state: std::sync::Arc::new(tokio::sync::RwLock::new(state)), database: db, config };
    
    let account = service.create_account("test@example.com".into(), "Test User".into()).await.unwrap();
    assert!(!account.id.is_nil());
    assert_eq!(account.email, "test@example.com");
    assert_eq!(account.display_name, "Test User");
}

#[tokio::test]
async fn test_issuer_verification_flow() {
    let pool = setup_test_db().await;
    let config = AppConfig::default();
    let master_key = MasterKey::generate();
    let issuer_sk = BbsSecretKey::generate();
    
    let state = IssuerState::new(config.clone(), master_key, issuer_sk);
    let db = IssuerDatabase::new(pool.clone());
    let service = IssuerService { state: std::sync::Arc::new(tokio::sync::RwLock::new(state)), database: db, config };
    
    let account = service.create_account("verify@example.com".into(), "Verify User".into()).await.unwrap();
    
    let record = service.start_verification(account.id, "provider1".into(), "ref123".into()).await.unwrap();
    assert_eq!(record.account_id, account.id);
    assert_eq!(record.provider_id, "provider1");
    
    let commitment_key = CommitmentKey::generate();
    let value = snex_crypto::commitments::random_scalar();
    let blinding = snex_crypto::commitments::random_blinding();
    let pc = PedersenCommitment::new(value, blinding);
    let commitment = pc.commit(&commitment_key);
    
    let completed = service.complete_verification(
        record.id,
        vec![1,2,3,4],
        commitment,
        true,
    ).await.unwrap();
    
    assert_eq!(completed.status, snex_core::identity::VerificationStatus::Verified);
    assert!(completed.of_age_attribute);
    assert!(completed.attestation.is_some());
    assert!(completed.blinded_commitment.is_some());
}

#[tokio::test]
async fn test_issuer_person_credential() {
    let pool = setup_test_db().await;
    let config = AppConfig::default();
    let master_key = MasterKey::generate();
    let issuer_sk = BbsSecretKey::generate();
    
    let state = IssuerState::new(config.clone(), master_key, issuer_sk);
    let db = IssuerDatabase::new(pool.clone());
    let service = IssuerService { state: std::sync::Arc::new(tokio::sync::RwLock::new(state)), database: db, config };
    
    let account = service.create_account("cred@example.com".into(), "Cred User".into()).await.unwrap();
    
    let commitment_key = CommitmentKey::generate();
    let value = snex_crypto::commitments::random_scalar();
    let blinding = snex_crypto::commitments::random_blinding();
    let pc = PedersenCommitment::new(value, blinding);
    let commitment = pc.commit(&commitment_key);
    
    let credential = service.request_person_credential(
        account.id,
        commitment,
        vec![b"attr1".to_vec()],
    ).await.unwrap();
    
    assert_eq!(credential.epoch, Epoch::current().0);
    assert_eq!(credential.schema_id, "SNEX_PersonCredential_v1");
}

#[tokio::test]
async fn test_issuer_membership_credential() {
    let pool = setup_test_db().await;
    let config = AppConfig::default();
    let master_key = MasterKey::generate();
    let issuer_sk = BbsSecretKey::generate();
    
    let state = IssuerState::new(config.clone(), master_key, issuer_sk);
    let db = IssuerDatabase::new(pool.clone());
    let service = IssuerService { state: std::sync::Arc::new(tokio::sync::RwLock::new(state)), database: db, config };
    
    let tenant_id = Uuid::new_v4();
    let governance_sk = BbsSecretKey::generate();
    let governance_pk = governance_sk.public_key();
    
    let mut state = service.state.write().await;
    state.add_governance_key(tenant_id, snex_core::tenant::GovernanceKey {
        tenant_id,
        version: 1,
        public_key: governance_pk.key,
        threshold: 2,
        total_shares: 3,
        created_at: Utc::now(),
        rotated_at: None,
        active: true,
    });
    drop(state);
    
    let account = service.create_account("member@example.com".into(), "Member User".into()).await.unwrap();
    
    let commitment_key = CommitmentKey::generate();
    let value = snex_crypto::commitments::random_scalar();
    let blinding = snex_crypto::commitments::random_blinding();
    let pc = PedersenCommitment::new(value, blinding);
    let commitment = pc.commit(&commitment_key);
    
    let credential = service.request_membership_credential(
        account.id,
        tenant_id,
        commitment,
        vec![],
        true,
        true,
    ).await.unwrap();
    
    assert_eq!(credential.epoch, Epoch::current().0);
    assert_eq!(credential.schema_id, "SNEX_MembershipCredential_v1");
}

#[tokio::test]
async fn test_issuer_advance_issuance() {
    let pool = setup_test_db().await;
    let config = AppConfig::default();
    let master_key = MasterKey::generate();
    let issuer_sk = BbsSecretKey::generate();
    
    let state = IssuerState::new(config.clone(), master_key, issuer_sk);
    let db = IssuerDatabase::new(pool.clone());
    let service = IssuerService { state: std::sync::Arc::new(tokio::sync::RwLock::new(state)), database: db, config };
    
    let account = service.create_account("advance@example.com".into(), "Advance User".into()).await.unwrap();
    
    let op_secret = service.advance_issue_next_epoch(account.id).await.unwrap();
    assert!(!op_secret.0.iter().all(|&b| b == 0));
}

#[tokio::test]
async fn test_issuer_epoch_rotation() {
    let pool = setup_test_db().await;
    let config = AppConfig::default();
    let master_key = MasterKey::generate();
    let issuer_sk = BbsSecretKey::generate();
    
    let state = IssuerState::new(config.clone(), master_key, issuer_sk);
    let db = IssuerDatabase::new(pool.clone());
    let service = IssuerService { state: std::sync::Arc::new(tokio::sync::RwLock::new(state)), database: db, config };
    
    let epoch_state = service.get_epoch_state().await;
    assert_eq!(epoch_state.epoch, Epoch::current());
    
    let cohort = service.get_issuance_cohort().await;
    assert_eq!(cohort.epoch, Epoch::current());
    assert!(!cohort.closed);
}

#[tokio::test]
async fn test_issuer_grace_activation() {
    let pool = setup_test_db().await;
    let config = AppConfig::default();
    let master_key = MasterKey::generate();
    let issuer_sk = BbsSecretKey::generate();
    
    let state = IssuerState::new(config.clone(), master_key, issuer_sk);
    let db = IssuerDatabase::new(pool.clone());
    let service = IssuerService { state: std::sync::Arc::new(tokio::sync::RwLock::new(state)), database: db, config };
    
    service.activate_grace().await.unwrap();
    
    let epoch_state = service.get_epoch_state().await;
    assert!(epoch_state.grace_active);
    assert!(epoch_state.grace_deadline.is_some());
}

#[tokio::test]
async fn test_issuer_cohort_close() {
    let pool = setup_test_db().await;
    let config = AppConfig::default();
    let master_key = MasterKey::generate();
    let issuer_sk = BbsSecretKey::generate();
    
    let state = IssuerState::new(config.clone(), master_key, issuer_sk);
    let db = IssuerDatabase::new(pool.clone());
    let service = IssuerService { state: std::sync::Arc::new(tokio::sync::RwLock::new(state)), database: db, config };
    
    service.close_cohort().await.unwrap();
    
    let cohort = service.get_issuance_cohort().await;
    assert!(cohort.closed);
    assert!(cohort.closed_at.is_some());
}