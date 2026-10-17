use snex_verifier::{service::VerifierService, state::VerifierState, database::VerifierDatabase};
use snex_core::{config::AppConfig, epoch::Epoch, pseudonym::PseudonymFunction, error::CoreError};
use snex_crypto::{
    bbs::{BbsSecretKey, BbsPublicKey, BbsCredential},
    commitments::{CommitmentKey, Commitment, PedersenCommitment},
    nullifiers::{OperationSecret, PseudonymSecret, Pseudonym, Nullifier},
    hashing::Hash,
};
use uuid::Uuid;
use chrono::Utc;
use sqlx::PgPool;

async fn setup_test_db() -> PgPool {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgresql://snex:snex@localhost:5432/snex_test".into());
    PgPool::connect(&database_url).await.unwrap()
}

fn create_test_credentials(epoch: u64) -> (BbsCredential, BbsCredential, Commitment, CommitmentKey) {
    let issuer_sk = BbsSecretKey::generate();
    let issuer_pk = issuer_sk.public_key();
    
    let commitment_key = CommitmentKey::generate();
    let value = snex_crypto::commitments::random_scalar();
    let blinding = snex_crypto::commitments::random_blinding();
    let pc = PedersenCommitment::new(value, blinding);
    let commitment = pc.commit(&commitment_key);
    
    let (person_cred, _) = snex_crypto::bbs::blind_issue(&issuer_sk, &commitment, &[b"attr1".to_vec()], epoch).unwrap();
    let (membership_cred, _) = snex_crypto::bbs::blind_issue(&issuer_sk, &commitment, &[b"reporting".to_vec(), b"voting".to_vec()], epoch).unwrap();
    
    (person_cred, membership_cred, commitment, commitment_key)
}

#[tokio::test]
async fn test_verifier_establishment() {
    let pool = setup_test_db().await;
    let config = AppConfig::default();
    
    let db = VerifierDatabase::new(pool.clone());
    let service = VerifierService::new(config.clone(), db);
    
    let epoch = Epoch::current();
    let (person_cred, membership_cred, commitment, commitment_key) = create_test_credentials(epoch.0);
    
    let op_secret = OperationSecret::generate();
    let establishment_nullifier = op_secret.derive_establishment_nullifier(epoch.0, b"tenant", 0);
    let pair_tag = op_secret.derive_pair_tag(epoch.0, b"tenant");
    
    let mut state = service.state.write().await;
    state.add_issuer_key(epoch.0, BbsPublicKey { key: vec![0u8; 96] });
    state.add_governance_key(Uuid::new_v4(), BbsPublicKey { key: vec![0u8; 96] });
    drop(state);
    
    let tenant_id = Uuid::new_v4();
    let req = snex_core::pseudonym::EstablishmentRequest {
        tenant_id,
        person_credential: person_cred,
        membership_credential: membership_cred,
        commitment,
        commitment_key,
        establishment_nullifier,
        pair_tag,
        epoch,
        lifetime_index: 0,
        zero_knowledge_proof: vec![],
        received_at: Utc::now(),
    };
    
    service.process_establishment(req).await.unwrap();
    
    let state = service.state.read().await;
    assert_eq!(state.batching_buffer.pending.len(), 1);
}

#[tokio::test]
async fn test_verifier_batch_release() {
    let pool = setup_test_db().await;
    let config = AppConfig::default();
    
    let db = VerifierDatabase::new(pool.clone());
    let service = VerifierService::new(config.clone(), db);
    
    let mut state = service.state.write().await;
    state.add_issuer_key(1, BbsPublicKey { key: vec![0u8; 96] });
    state.add_governance_key(Uuid::new_v4(), BbsPublicKey { key: vec![0u8; 96] });
    drop(state);
    
    let epoch = Epoch(1);
    let tenant_id = Uuid::new_v4();
    
    for i in 0..8 {
        let (person_cred, membership_cred, commitment, commitment_key) = create_test_credentials(1);
        let op_secret = OperationSecret::generate();
        
        let req = snex_core::pseudonym::EstablishmentRequest {
            tenant_id,
            person_credential: person_cred,
            membership_credential: membership_cred,
            commitment,
            commitment_key,
            establishment_nullifier: op_secret.derive_establishment_nullifier(1, b"tenant", i),
            pair_tag: op_secret.derive_pair_tag(1, b"tenant"),
            epoch,
            lifetime_index: i,
            zero_knowledge_proof: vec![],
            received_at: Utc::now(),
        };
        
        let mut state = service.state.write().await;
        state.batching_buffer.add(req).unwrap();
        drop(state);
    }
    
    let mut state = service.state.write().await;
    let batch = state.release_batch();
    assert!(batch.is_some());
    assert_eq!(batch.unwrap().establishments.len(), 8);
}

#[tokio::test]
async fn test_verifier_epoch_confirmation() {
    let pool = setup_test_db().await;
    let config = AppConfig::default();
    
    let db = VerifierDatabase::new(pool.clone());
    let service = VerifierService::new(config.clone(), db);
    
    let mut state = service.state.write().await;
    state.add_issuer_key(2, BbsPublicKey { key: vec![0u8; 96] });
    state.add_governance_key(Uuid::new_v4(), BbsPublicKey { key: vec![0u8; 96] });
    drop(state);
    
    let pseudo_secret = PseudonymSecret::generate();
    let pseudonym = pseudo_secret.derive_pseudonym(b"tenant", 0);
    let epoch = Epoch(2);
    let tenant_id = Uuid::new_v4();
    
    let (person_cred, membership_cred, _, _) = create_test_credentials(2);
    
    let confirmation = snex_core::pseudonym::EpochConfirmation {
        pseudonym,
        tenant_id,
        epoch,
        person_credential: person_cred,
        membership_credential: membership_cred,
        zero_knowledge_proof: vec![],
    };
    
    service.confirm_epoch(confirmation).await.unwrap();
    
    let state = service.state.read().await;
    assert_eq!(state.epoch_confirmations.len(), 1);
}

#[tokio::test]
async fn test_verifier_snapshot_creation() {
    let pool = setup_test_db().await;
    let config = AppConfig::default();
    
    let db = VerifierDatabase::new(pool.clone());
    let service = VerifierService::new(config.clone(), db);
    
    let epoch = Epoch::current();
    let tenant_id = Uuid::new_v4();
    
    let mut state = service.state.write().await;
    state.add_issuer_key(epoch.0, BbsPublicKey { key: vec![0u8; 96] });
    state.add_governance_key(tenant_id, BbsPublicKey { key: vec![0u8; 96] });
    drop(state);
    
    let snapshot = service.create_snapshot(tenant_id, epoch, None).await.unwrap();
    assert!(!snapshot.id.is_nil());
    assert_eq!(snapshot.tenant_id, tenant_id);
    assert_eq!(snapshot.epoch, epoch);
}

#[tokio::test]
async fn test_verifier_anonymity_set() {
    let pool = setup_test_db().await;
    let config = AppConfig::default();
    
    let db = VerifierDatabase::new(pool.clone());
    let service = VerifierService::new(config.clone(), db);
    
    let tenant_id = Uuid::new_v4();
    let epoch = Epoch::current();
    
    let mut state = service.state.write().await;
    state.add_issuer_key(epoch.0, BbsPublicKey { key: vec![0u8; 96] });
    state.add_governance_key(tenant_id, BbsPublicKey { key: vec![0u8; 96] });
    drop(state);
    
    for i in 0..5 {
        let (person_cred, membership_cred, commitment, commitment_key) = create_test_credentials(epoch.0);
        let op_secret = OperationSecret::generate();
        
        let req = snex_core::pseudonym::EstablishmentRequest {
            tenant_id,
            person_credential: person_cred,
            membership_credential: membership_cred,
            commitment,
            commitment_key,
            establishment_nullifier: op_secret.derive_establishment_nullifier(epoch.0, b"tenant", i),
            pair_tag: op_secret.derive_pair_tag(epoch.0, b"tenant"),
            epoch,
            lifetime_index: i,
            zero_knowledge_proof: vec![],
            received_at: Utc::now(),
        };
        
        let mut state = service.state.write().await;
        state.batching_buffer.add(req).unwrap();
        drop(state);
    }
    
    let mut state = service.state.write().await;
    if let Some(batch) = state.release_batch() {
        state.activate_registrations(&batch).unwrap();
    }
    drop(state);
    
    let count = service.get_anonymity_set(tenant_id, PseudonymFunction::Voting).await;
    assert_eq!(count, 5);
}

#[tokio::test]
async fn test_verifier_build_up_mode() {
    let pool = setup_test_db().await;
    let config = AppConfig::default();
    
    let db = VerifierDatabase::new(pool.clone());
    let service = VerifierService::new(config.clone(), db);
    
    let tenant_id = Uuid::new_v4();
    let epoch = Epoch::current();
    
    let mut state = service.state.write().await;
    state.add_issuer_key(epoch.0, BbsPublicKey { key: vec![0u8; 96] });
    state.add_governance_key(tenant_id, BbsPublicKey { key: vec![0u8; 96] });
    drop(state);
    
    let count = service.get_anonymity_set(tenant_id, PseudonymFunction::Voting).await;
    assert_eq!(count, 0);
    
    let build_up = service.check_build_up_mode(tenant_id, PseudonymFunction::Voting).await;
    assert!(build_up);
}

#[tokio::test]
async fn test_verifier_termination() {
    let pool = setup_test_db().await;
    let config = AppConfig::default();
    
    let db = VerifierDatabase::new(pool.clone());
    let service = VerifierService::new(config.clone(), db);
    
    let pseudo_secret = PseudonymSecret::generate();
    let pseudonym = pseudo_secret.derive_pseudonym(b"tenant", 0);
    let tenant_id = Uuid::new_v4();
    
    service.terminate_pseudonym(pseudonym, tenant_id).await.unwrap();
    
    let terminated = service.is_terminated(pseudonym).await;
    assert!(terminated);
}

#[tokio::test]
async fn test_verifier_blocking() {
    let pool = setup_test_db().await;
    let config = AppConfig::default();
    
    let db = VerifierDatabase::new(pool.clone());
    let service = VerifierService::new(config.clone(), db);
    
    let pseudo_secret = PseudonymSecret::generate();
    let pseudonym = pseudo_secret.derive_pseudonym(b"tenant", 0);
    let tenant_id = Uuid::new_v4();
    
    service.block_pseudonym(pseudonym, tenant_id, "abuse detected".into()).await.unwrap();
}