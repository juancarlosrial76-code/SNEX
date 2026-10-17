use snex_core::{
    identity::{Account, AccountSecrets, CredentialPair, VerificationRecord, PersonCredential, MembershipCredential},
    epoch::Epoch,
    pseudonym::{PseudonymRegistration, EstablishmentRequest, BatchingBuffer, EpochConfirmation, PseudonymFunction, PseudonymCounter, TerminatedPseudonym},
    voting::{Ballot, Vote, VoteRegister, VoteValue, VoteTally, Snapshot, SnapshotLeaf, MerkleProof},
    reporting::{Report, Case, Reply, RateLimitWindow, ReportWindowSchedule, ReportingOffice},
    tenant::{Tenant, TenantMember, TenantRole, TenantStatus, MemberStatus, GovernanceKey, TenantConfiguration},
    config::AppConfig,
    error::CoreError,
};
use snex_crypto::{
    bbs::{BbsSecretKey, BbsPublicKey, BbsCredential, blind_issue, CanonicalCredentialProfile},
    commitments::{CommitmentKey, Commitment, PedersenCommitment, BlindedCommitment},
    nullifiers::{OperationSecret, PseudonymSecret, Pseudonym, Nullifier, CaseHandle, MailboxBaseSecret},
    key_hierarchy::{MasterKey, KeyHierarchy, Dek, RetentionClass},
    hash::Hash,
    encryption::EncryptedData,
};
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use std::collections::HashMap;

#[test]
fn test_full_lifecycle_account_creation() {
    let account = Account::new("alice@example.com".into(), "Alice".into());
    assert_eq!(account.status, snex_core::identity::AccountStatus::PendingVerification);
    assert!(!account.of_age_flag);
    
    let mut account = account;
    account.set_passkey(vec![1,2,3,4]);
    assert!(account.passkey_credential_id.is_some());
    
    let phrase_hash = Hash([42u8; 32]);
    account.set_backup_phrase(phrase_hash);
    assert_eq!(account.backup_phrase_hash, Some(phrase_hash));
}

#[test]
fn test_full_lifecycle_verification() {
    let mut account = Account::new("bob@example.com".into(), "Bob".into());
    
    let record = VerificationRecord {
        id: Uuid::new_v4(),
        account_id: account.id,
        provider_id: "provider1".into(),
        verification_process_ref: "ref123".into(),
        status: snex_core::identity::VerificationStatus::Pending,
        attestation: None,
        blinded_commitment: None,
        of_age_attribute: false,
        requested_at: Utc::now(),
        completed_at: None,
        expires_at: None,
    };
    
    assert_eq!(record.status, snex_core::identity::VerificationStatus::Pending);
}

#[test]
fn test_full_lifecycle_credential_issuance() {
    let issuer_sk = BbsSecretKey::generate();
    let issuer_pk = issuer_sk.public_key();
    
    let commitment_key = CommitmentKey::generate();
    let value = snex_crypto::commitments::random_scalar();
    let blinding = snex_crypto::commitments::random_blinding();
    let pc = PedersenCommitment::new(value, blinding);
    let commitment = pc.commit(&commitment_key);
    
    let (credential, _sig) = blind_issue(&issuer_sk, &commitment, &[b"attr1".to_vec()], 1).unwrap();
    
    assert_eq!(credential.epoch, 1);
    assert_eq!(credential.issuer, issuer_pk);
    assert!(credential.verify(&issuer_pk).unwrap());
}

#[test]
fn test_full_lifecycle_pseudonym_establishment() {
    let pseudo_secret = PseudonymSecret::generate();
    let op_secret = OperationSecret::generate();
    
    let pseudonym = pseudo_secret.derive_pseudonym(b"tenant1", 0);
    let establishment_nullifier = op_secret.derive_establishment_nullifier(1, b"tenant1", 0);
    let pair_tag = op_secret.derive_pair_tag(1, b"tenant1");
    
    let reg = PseudonymRegistration::new(
        Uuid::new_v4(),
        pseudonym,
        Epoch(1),
        0,
        establishment_nullifier,
        pair_tag,
        true,
        true,
    );
    
    assert_eq!(reg.state, snex_core::pseudonym::PseudonymState::Provisional);
    assert!(!reg.is_active());
    
    let mut reg = reg;
    reg.activate();
    assert_eq!(reg.state, snex_core::pseudonym::PseudonymState::Active);
    assert!(reg.is_active());
    assert!(reg.authorises(PseudonymFunction::Reporting));
    assert!(reg.authorises(PseudonymFunction::Voting));
}

#[test]
fn test_full_lifecycle_batching_buffer() {
    let mut buffer = BatchingBuffer::new(3, 10, 72, 2);
    
    for i in 0..3 {
        let op_secret = OperationSecret::generate();
        let req = EstablishmentRequest {
            tenant_id: Uuid::new_v4(),
            person_credential: create_test_person_credential(),
            membership_credential: create_test_membership_credential(),
            commitment: create_test_commitment(),
            commitment_key: CommitmentKey::generate(),
            establishment_nullifier: op_secret.derive_establishment_nullifier(1, b"tenant", i),
            pair_tag: op_secret.derive_pair_tag(1, b"tenant"),
            epoch: Epoch(1),
            lifetime_index: i,
            zero_knowledge_proof: vec![],
        };
        buffer.add(req).unwrap();
    }
    
    assert!(buffer.can_release());
    let batch = buffer.release(3).unwrap();
    assert_eq!(batch.establishments.len(), 3);
}

#[test]
fn test_full_lifecycle_epoch_confirmation() {
    let pseudo_secret = PseudonymSecret::generate();
    let pseudonym = pseudo_secret.derive_pseudonym(b"tenant1", 0);
    
    let confirmation = EpochConfirmation {
        pseudonym,
        tenant_id: Uuid::new_v4(),
        epoch: Epoch(2),
        person_credential: create_test_person_credential(),
        membership_credential: create_test_membership_credential(),
        zero_knowledge_proof: vec![],
    };
    
    assert_eq!(confirmation.epoch.0, 2);
}

#[test]
fn test_full_lifecycle_voting() {
    let mut ballot = Ballot::new(
        Uuid::new_v4(),
        "Test Ballot".into(),
        "Description".into(),
        Utc::now() + Duration::hours(1),
        Utc::now() + Duration::hours(25),
        Epoch::current(),
        snex_core::voting::BallotTier::Tier1Consultative,
    );
    
    assert_eq!(ballot.status, snex_core::voting::BallotStatus::Upcoming);
    
    ballot.open();
    assert_eq!(ballot.status, snex_core::voting::BallotStatus::Open);
    
    let op_secret = OperationSecret::generate();
    let pseudo_secret = PseudonymSecret::generate();
    let pseudonym = pseudo_secret.derive_pseudonym(b"tenant", 0);
    let nullifier = op_secret.derive_vote_nullifier(ballot.id.as_bytes());
    
    let mut snapshot = Snapshot::new(ballot.tenant_id, Epoch::current(), Some(ballot.id));
    snapshot.add_leaf(SnapshotLeaf {
        pseudonym,
        reporting_authorised: true,
        voting_authorised: true,
        index: 0,
    });
    snapshot.build_merkle_root().unwrap();
    
    let vote = Vote::new(
        ballot.id,
        nullifier,
        VoteValue::Yes,
        pseudonym,
        vec![],
    );
    
    let mut register = VoteRegister::new(ballot.id);
    register.add_vote(&vote).unwrap();
    
    let tally = register.tally();
    assert_eq!(tally.yes, 1);
    assert_eq!(tally.total, 1);
    
    ballot.close();
    register.finalize();
    assert!(register.finalized);
}

#[test]
fn test_full_lifecycle_reporting() {
    let op_secret = OperationSecret::generate();
    let rate_limit_tag = op_secret.derive_report_nullifier(0, 0);
    
    let report = Report::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        rate_limit_tag,
        EncryptedData(vec![1,2,3]),
        vec![],
        Epoch::current(),
    );
    
    assert_eq!(report.status, snex_core::reporting::ReportStatus::Submitted);
    assert!(!report.case_handle.as_bytes().iter().all(|&b| b == 0));
    
    let case_key = Dek::generate();
    let mut case = Case::new(&report, case_key, vec![], vec![], Uuid::new_v4());
    assert_eq!(case.status, snex_core::reporting::CaseStatus::Open);
    
    case.handover(vec![]);
    assert_eq!(case.status, snex_core::reporting::CaseStatus::HandedOver);
    
    case.close();
    assert_eq!(case.status, snex_core::reporting::CaseStatus::Closed);
}

#[test]
fn test_full_lifecycle_rate_limiting() {
    let mut window = RateLimitWindow::new(0, Uuid::new_v4(), 3);
    let op_secret = OperationSecret::generate();
    let tag = op_secret.derive_rate_limit_tag(0, b"tenant");
    
    for i in 0..3 {
        window.check_and_consume(&tag).unwrap();
    }
    
    assert!(window.check_and_consume(&tag).is_err());
}

#[test]
fn test_full_lifecycle_tenant_management() {
    let mut tenant = Tenant::new("test-tenant".into(), "Test Tenant".into());
    assert_eq!(tenant.status, TenantStatus::PendingVerification);
    
    tenant.activate();
    assert_eq!(tenant.status, TenantStatus::Active);
    
    let member = TenantMember::new(tenant.id, Uuid::new_v4(), TenantRole::Member);
    assert!(!member.reporting_authorised);
    
    let mut member = member;
    member.authorise_reporting();
    member.authorise_voting();
    member.verify();
    assert!(member.reporting_authorised);
    assert!(member.voting_authorised);
    assert_eq!(member.status, MemberStatus::Active);
}

#[test]
fn test_full_lifecycle_snapshot_merkle() {
    let mut snapshot = Snapshot::new(Uuid::new_v4(), Epoch::current(), None);
    let pseudo_secret = PseudonymSecret::generate();
    
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
    assert_ne!(snapshot.merkle_root.as_bytes(), &[0u8; 32]);
    
    let proof = snapshot.generate_proof(0).unwrap();
    assert!(snapshot.verify_proof(&proof, &snapshot.leaves[0]));
}

#[test]
fn test_full_lifecycle_pseudonym_counters() {
    let mut counters: HashMap<PseudonymFunction, u32> = HashMap::new();
    
    *counters.entry(PseudonymFunction::Reporting).or_insert(0) += 1;
    *counters.entry(PseudonymFunction::Voting).or_insert(0) += 1;
    
    assert_eq!(counters.get(&PseudonymFunction::Reporting), Some(&1));
    assert_eq!(counters.get(&PseudonymFunction::Voting), Some(&1));
}

#[test]
fn test_full_lifecycle_termination() {
    let pseudo_secret = PseudonymSecret::generate();
    let op_secret = OperationSecret::generate();
    
    let reg = PseudonymRegistration::new(
        Uuid::new_v4(),
        pseudo_secret.derive_pseudonym(b"tenant", 0),
        Epoch(1),
        0,
        op_secret.derive_establishment_nullifier(1, b"tenant", 0),
        op_secret.derive_pair_tag(1, b"tenant"),
        true,
        true,
    );
    
    let terminated = TerminatedPseudonym::from_registration(&reg);
    assert_eq!(terminated.tenant_id, reg.tenant_id);
    assert_eq!(terminated.lifetime_index, 0);
}

#[test]
fn test_full_lifecycle_key_hierarchy() {
    let master = MasterKey::generate();
    let mut hierarchy = KeyHierarchy::new(master);
    
    let kek = hierarchy.get_or_create_kek("tenant1");
    let dek = hierarchy.get_or_create_dek("tenant1", "user123");
    
    let plaintext = b"Hello, World!";
    let encrypted = dek.encrypt(plaintext, b"aad").unwrap();
    let decrypted = dek.decrypt(&encrypted, b"aad").unwrap();
    assert_eq!(plaintext, decrypted.as_slice());
    
    let wrapped = kek.wrap_dek(&dek);
    let unwrapped = kek.unwrap_dek(&wrapped).unwrap();
    assert_eq!(dek.0.as_ref(), unwrapped.0.as_ref());
}

#[test]
fn test_full_lifecycle_retention() {
    let master = MasterKey::generate();
    let mut engine = snex_core::retention::RetentionEngine::new(master, 1000);
    
    engine.register_data(
        "user123".into(),
        RetentionClass::RA,
        Some(Uuid::new_v4()),
        Some("person_key_1".into()),
    ).unwrap();
    
    let record = engine.records.get("user123").unwrap();
    assert_eq!(record.retention_class, RetentionClass::RA);
    assert_eq!(record.state, snex_core::retention::DeletionState::Active);
    
    engine.request_deletion("user123", "admin".into(), 100).unwrap();
    let record = engine.records.get("user123").unwrap();
    assert_eq!(record.state, snex_core::retention::DeletionState::RemovedFromApplication);
}

#[test]
fn test_full_lifecycle_anchoring() {
    let mut chain = snex_core::anchoring::AuditChain::new();
    
    chain.append("test".into(), "action".into(), serde_json::json!({}), None, None).unwrap();
    chain.append("test".into(), "action2".into(), serde_json::json!({}), None, None).unwrap();
    
    assert_eq!(chain.length, 2);
    assert!(chain.verify().unwrap());
    
    chain.add_anchor("test-service".into(), vec![]);
    assert_eq!(chain.anchored_hashes.len(), 1);
}

#[test]
fn test_full_lifecycle_level_c() {
    let mut room = snex_core::levelc::LevelCRoom::new(
        Uuid::new_v4(),
        "Board Room".into(),
        "Confidential discussions".into(),
        Uuid::new_v4(),
        snex_core::levelc::RoomRuleSet::default(),
    );
    
    assert!(room.active);
    assert_eq!(room.members.len(), 0);
    
    let device = snex_core::levelc::MemberDevice {
        device_id: Uuid::new_v4(),
        leaf_index: 0,
        signature_key: vec![1,2,3],
        encryption_key: vec![4,5,6],
        added_at: Utc::now(),
        last_sync_at: None,
    };
    
    room.add_member(Uuid::new_v4(), device, Uuid::new_v4()).unwrap();
    assert_eq!(room.members.len(), 1);
}

#[test]
fn test_full_lifecycle_backup_recovery() {
    let account_id = Uuid::new_v4();
    let recovery_phrase = "test recovery phrase with many words for testing purposes only";
    
    let backup = snex_core::levelc::RecoveryPhraseBackup::new(
        account_id,
        recovery_phrase,
        b"MLS private keys".to_vec(),
    ).unwrap();
    
    let restored = backup.restore(recovery_phrase).unwrap();
    assert_eq!(restored, b"MLS private keys");
}

#[test]
fn test_counter_model_double_vote() {
    let op_secret = OperationSecret::generate();
    let pseudo_secret = PseudonymSecret::generate();
    let pseudonym = pseudo_secret.derive_pseudonym(b"tenant", 0);
    let nullifier = op_secret.derive_vote_nullifier(b"ballot1");
    
    let mut register = VoteRegister::new(Uuid::new_v4());
    
    let vote1 = Vote::new(Uuid::new_v4(), nullifier, VoteValue::Yes, pseudonym, vec![]);
    register.add_vote(&vote1).unwrap();
    
    let vote2 = Vote::new(Uuid::new_v4(), nullifier, VoteValue::No, pseudonym, vec![]);
    assert!(register.add_vote(&vote2).is_err());
}

#[test]
fn test_counter_model_double_report() {
    let op_secret = OperationSecret::generate();
    let rate_limit_tag = op_secret.derive_report_nullifier(0, 0);
    
    let mut window = RateLimitWindow::new(0, Uuid::new_v4(), 1);
    window.check_and_consume(&rate_limit_tag).unwrap();
    
    assert!(window.check_and_consume(&rate_limit_tag).is_err());
}

#[test]
fn test_counter_model_batch_stuffing() {
    let mut buffer = BatchingBuffer::new(3, 10, 72, 2);
    
    for i in 0..5 {
        let op_secret = OperationSecret::generate();
        let req = EstablishmentRequest {
            tenant_id: Uuid::new_v4(),
            person_credential: create_test_person_credential(),
            membership_credential: create_test_membership_credential(),
            commitment: create_test_commitment(),
            commitment_key: CommitmentKey::generate(),
            establishment_nullifier: op_secret.derive_establishment_nullifier(1, b"tenant", i),
            pair_tag: op_secret.derive_pair_tag(1, b"tenant"),
            epoch: Epoch(1),
            lifetime_index: i,
            zero_knowledge_proof: vec![],
        };
        buffer.add(req).unwrap();
    }
    
    let batch = buffer.release(3).unwrap();
    assert_eq!(batch.establishments.len(), 3);
}

#[test]
fn test_counter_model_revocation_latency() {
    let epoch = Epoch::current();
    let next_epoch = epoch.next();
    
    let pseudo_secret = PseudonymSecret::generate();
    let op_secret_current = OperationSecret::generate();
    let op_secret_next = OperationSecret::generate();
    
    let nullifier_current = op_secret_current.derive_vote_nullifier(b"ballot1");
    let nullifier_next = op_secret_next.derive_vote_nullifier(b"ballot1");
    
    assert_ne!(nullifier_current, nullifier_next);
}

fn create_test_person_credential() -> BbsCredential {
    BbsCredential {
        schema_id: "test".into(),
        issuer: BbsPublicKey { key: vec![0u8; 96] },
        subject: vec![],
        attributes: vec![],
        signature: snex_crypto::bbs::BbsSignature { signature: vec![0u8; 112] },
        epoch: 1,
        issued_at: 0,
        expires_at: 0,
    }
}

fn create_test_membership_credential() -> BbsCredential {
    BbsCredential {
        schema_id: "test".into(),
        issuer: BbsPublicKey { key: vec![0u8; 96] },
        subject: vec![],
        attributes: vec![b"reporting".to_vec(), b"voting".to_vec()],
        signature: snex_crypto::bbs::BbsSignature { signature: vec![0u8; 112] },
        epoch: 1,
        issued_at: 0,
        expires_at: 0,
    }
}

fn create_test_commitment() -> Commitment {
    let key = CommitmentKey::generate();
    let pc = PedersenCommitment::new(
        snex_crypto::commitments::random_scalar(),
        snex_crypto::commitments::random_blinding(),
    );
    pc.commit(&key)
}