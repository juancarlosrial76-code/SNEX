use snex_voting::service::VotingService;
use snex_core::{
    voting::{Ballot, Vote, VoteValue, VoteTally, Snapshot, MerkleProof, SnapshotLeaf},
    epoch::Epoch,
    pseudonym::PseudonymFunction,
    error::CoreError,
};
use snex_crypto::{
    nullifiers::{Nullifier, OperationSecret, Pseudonym, PseudonymSecret},
    hashing::Hash,
};
use snex_registry::service::RegistryService;
use snex_registry::database::RegistryDatabase;
use snex_verifier::service::VerifierService;
use snex_verifier::database::VerifierDatabase;
use snex_core::config::AppConfig;
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use sqlx::PgPool;

async fn setup_test_db() -> PgPool {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgresql://snex:snex@localhost:5432/snex_test".into());
    PgPool::connect(&database_url).await.unwrap()
}

async fn setup_services(pool: PgPool) -> (VotingService, std::sync::Arc<VerifierService>, std::sync::Arc<RegistryService>) {
    let config = AppConfig::default();
    
    let registry_db = RegistryDatabase::new(pool.clone());
    let registry = std::sync::Arc::new(RegistryService::new(registry_db));
    registry.initialize().await.unwrap();
    
    let verifier_db = VerifierDatabase::new(pool.clone());
    let verifier = std::sync::Arc::new(VerifierService::new(config.clone(), verifier_db));
    verifier.initialize().await.unwrap();
    
    let mut verifier_state = verifier.state.write().await;
    verifier_state.add_issuer_key(Epoch::current().0, snex_crypto::bbs::BbsPublicKey { key: vec![0u8; 96] });
    verifier_state.add_governance_key(Uuid::new_v4(), snex_crypto::bbs::BbsPublicKey { key: vec![0u8; 96] });
    drop(verifier_state);
    
    let voting = VotingService::new(registry.clone(), verifier.clone(), config);
    
    (voting, verifier, registry)
}

#[tokio::test]
async fn test_voting_ballot_creation() {
    let pool = setup_test_db().await;
    let (voting, _verifier, _registry) = setup_services(pool).await;
    
    let tenant_id = Uuid::new_v4();
    let ballot = voting.create_ballot(
        tenant_id,
        "Test Ballot".into(),
        "Description".into(),
        Utc::now() + Duration::hours(1),
        Utc::now() + Duration::hours(25),
    ).await.unwrap();
    
    assert!(!ballot.id.is_nil());
    assert_eq!(ballot.tenant_id, tenant_id);
    assert_eq!(ballot.title, "Test Ballot");
    assert_eq!(ballot.tier, snex_core::voting::BallotTier::Tier1Consultative);
}

#[tokio::test]
async fn test_voting_cast_vote() {
    let pool = setup_test_db().await;
    let (voting, _verifier, _registry) = setup_services(pool).await;
    
    let tenant_id = Uuid::new_v4();
    let ballot = voting.create_ballot(
        tenant_id,
        "Vote Ballot".into(),
        "Description".into(),
        Utc::now() + Duration::hours(1),
        Utc::now() + Duration::hours(25),
    ).await.unwrap();
    
    let op_secret = OperationSecret::generate();
    let pseudo_secret = PseudonymSecret::generate();
    let pseudonym = pseudo_secret.derive_pseudonym(b"tenant", 0);
    let nullifier = op_secret.derive_vote_nullifier(ballot.id.as_bytes());
    
    let mut snapshot = Snapshot::new(tenant_id, Epoch::current(), Some(ballot.id));
    snapshot.add_leaf(SnapshotLeaf {
        pseudonym,
        reporting_authorised: true,
        voting_authorised: true,
        index: 0,
    });
    snapshot.build_merkle_root().unwrap();
    
    let proof = snapshot.generate_proof(0).unwrap();
    
    let vote = voting.cast_vote(
        &ballot,
        &op_secret,
        VoteValue::Yes,
        pseudonym,
        proof,
        snapshot.leaves[0].clone(),
    ).await.unwrap();
    
    assert_eq!(vote.vote_value, VoteValue::Yes);
    assert_eq!(vote.nullifier, nullifier);
    assert_eq!(vote.ballot_id, ballot.id);
}

#[tokio::test]
async fn test_voting_double_vote_rejection() {
    let pool = setup_test_db().await;
    let (voting, _verifier, _registry) = setup_services(pool).await;
    
    let tenant_id = Uuid::new_v4();
    let ballot = voting.create_ballot(
        tenant_id,
        "Double Vote Test".into(),
        "Description".into(),
        Utc::now() + Duration::hours(1),
        Utc::now() + Duration::hours(25),
    ).await.unwrap();
    
    let op_secret = OperationSecret::generate();
    let pseudo_secret = PseudonymSecret::generate();
    let pseudonym = pseudo_secret.derive_pseudonym(b"tenant", 0);
    let nullifier = op_secret.derive_vote_nullifier(ballot.id.as_bytes());
    
    let mut snapshot = Snapshot::new(tenant_id, Epoch::current(), Some(ballot.id));
    snapshot.add_leaf(SnapshotLeaf {
        pseudonym,
        reporting_authorised: true,
        voting_authorised: true,
        index: 0,
    });
    snapshot.build_merkle_root().unwrap();
    
    let proof = snapshot.generate_proof(0).unwrap();
    
    voting.cast_vote(&ballot, &op_secret, VoteValue::Yes, pseudonym, proof.clone(), snapshot.leaves[0].clone()).await.unwrap();
    
    let result = voting.cast_vote(&ballot, &op_secret, VoteValue::No, pseudonym, proof, snapshot.leaves[0].clone()).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), CoreError::DoubleVote));
}

#[tokio::test]
async fn test_voting_finalize_ballot() {
    let pool = setup_test_db().await;
    let (voting, _verifier, _registry) = setup_services(pool).await;
    
    let tenant_id = Uuid::new_v4();
    let ballot = voting.create_ballot(
        tenant_id,
        "Finalize Test".into(),
        "Description".into(),
        Utc::now() + Duration::hours(1),
        Utc::now() + Duration::hours(25),
    ).await.unwrap();
    
    let op_secret = OperationSecret::generate();
    let pseudo_secret = PseudonymSecret::generate();
    let pseudonym = pseudo_secret.derive_pseudonym(b"tenant", 0);
    
    let mut snapshot = Snapshot::new(tenant_id, Epoch::current(), Some(ballot.id));
    snapshot.add_leaf(SnapshotLeaf {
        pseudonym,
        reporting_authorised: true,
        voting_authorised: true,
        index: 0,
    });
    snapshot.build_merkle_root().unwrap();
    
    let proof = snapshot.generate_proof(0).unwrap();
    
    for value in [VoteValue::Yes, VoteValue::No, VoteValue::Abstain] {
        let op_secret = OperationSecret::generate();
        let nullifier = op_secret.derive_vote_nullifier(ballot.id.as_bytes());
        
        let mut snap = Snapshot::new(tenant_id, Epoch::current(), Some(ballot.id));
        snap.add_leaf(SnapshotLeaf {
            pseudonym: Pseudonym(op_secret.derive_vote_nullifier(b"tenant").0),
            reporting_authorised: true,
            voting_authorised: true,
            index: 0,
        });
        snap.build_merkle_root().unwrap();
        let p = snap.generate_proof(0).unwrap();
        
        voting.cast_vote(&ballot, &op_secret, value, pseudonym, p, snap.leaves[0].clone()).await.unwrap();
    }
    
    let tally = voting.finalize_ballot(ballot.id).await.unwrap();
    assert_eq!(tally.total, 3);
    assert_eq!(tally.yes, 1);
    assert_eq!(tally.no, 1);
    assert_eq!(tally.abstain, 1);
}

#[tokio::test]
async fn test_voting_anonymity_set() {
    let pool = setup_test_db().await;
    let (voting, _verifier, _registry) = setup_services(pool).await;
    
    let tenant_id = Uuid::new_v4();
    let count = voting.get_anonymity_set(tenant_id).await;
    assert_eq!(count, 0);
}

#[tokio::test]
async fn test_voting_snapshot_verification() {
    let pool = setup_test_db().await;
    let (voting, _verifier, _registry) = setup_services(pool).await;
    
    let tenant_id = Uuid::new_v4();
    let epoch = Epoch::current();
    
    let pseudo_secret = PseudonymSecret::generate();
    
    let mut snapshot = Snapshot::new(tenant_id, epoch, None);
    for i in 0..4 {
        let pseudonym = pseudo_secret.derive_pseudonym(b"tenant", i);
        snapshot.add_leaf(SnapshotLeaf {
            pseudonym,
            reporting_authorised: true,
            voting_authorised: true,
            index: i,
        });
    }
    snapshot.build_merkle_root().unwrap();
    
    let proof = snapshot.generate_proof(0).unwrap();
    let valid = snapshot.verify_proof(&proof, &snapshot.leaves[0]);
    assert!(valid);
    
    let invalid_proof = MerkleProof {
        leaf_index: 1,
        siblings: proof.siblings,
        root: proof.root,
    };
    let valid = snapshot.verify_proof(&invalid_proof, &snapshot.leaves[0]);
    assert!(!valid);
}