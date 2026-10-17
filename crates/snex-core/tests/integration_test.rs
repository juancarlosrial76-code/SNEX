use snex_core::{
    epoch::Epoch,
    pseudonym::{PseudonymRegistration, BatchingBuffer, EstablishmentRequest, EpochConfirmation, PseudonymFunction, PseudonymCounter, TerminatedPseudonym, PseudonymState},
    voting::{Ballot, Vote, VoteRegister, VoteValue, VoteTally, Snapshot, SnapshotLeaf, MerkleProof},
    reporting::{Report, Case, Reply, RateLimitWindow, ReportWindowSchedule, ReportingOffice},
    tenant::{Tenant, TenantMember, TenantRole, TenantStatus, MemberStatus, GovernanceKey, TenantConfiguration},
    identity::{Account, AccountSecrets, VerificationRecord, PersonCredential, MembershipCredential},
    config::AppConfig,
    retention::{RetentionEngine, RetentionRecord, LegalHold, DeletionState, RetentionClass, BackupRegime, RetentionPolicy},
    anchoring::{AuditChain, AnchorConfig, SecurityCriticalEvent, SecurityCriticalEventType},
    levelc::{LevelCRoom, RoomRuleSet, RoomRole, MemberDevice, LevelCConfig, RecoveryPhraseBackup},
    error::CoreError,
};
use snex_crypto::{
    bbs::{BbsSecretKey, BbsPublicKey, BbsCredential, blind_issue, CanonicalCredentialProfile},
    commitments::{CommitmentKey, Commitment, PedersenCommitment, BlindedCommitment},
    nullifiers::{OperationSecret, PseudonymSecret, Pseudonym, Nullifier, CaseHandle, MailboxBaseSecret, RecoveryCode},
    key_hierarchy::{MasterKey, KeyHierarchy, Dek, WrappedDek, BackupWrappingKey},
    hash::Hash,
    encryption::{X25519KeyPair, Ed25519KeyPair, EncryptedData, MlKem768KeyPair, MlKem1024KeyPair, MlDsaKeyPair, hybrid_key_exchange, sign_with_both, verify_with_both, HybridSignature},
    kdf::{derive_key_argon2id, generate_salt, recovery_phrase_to_seed},
};
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use std::collections::HashMap;

#[test]
fn test_tenant_lifecycle() {
    let mut tenant = Tenant::new("test-tenant".into(), "Test Tenant".into());
    assert_eq!(tenant.status, TenantStatus::PendingVerification);
    
    tenant.activate();
    assert_eq!(tenant.status, TenantStatus::Active);
    
    tenant.suspend();
    assert_eq!(tenant.status, TenantStatus::Suspended);
    
    tenant.terminate();
    assert_eq!(tenant.status, TenantStatus::Terminated);
    
    assert!(!tenant.can_use_anonymous_functions());
    tenant.reporting_enabled = true;
    assert!(tenant.can_use_anonymous_functions());
}

#[test]
fn test_member_lifecycle() {
    let tenant_id = Uuid::new_v4();
    let account_id = Uuid::new_v4();
    
    let mut member = TenantMember::new(tenant_id, account_id, TenantRole::Member);
    assert_eq!(member.status, MemberStatus::Pending);
    assert!(!member.reporting_authorised);
    
    member.authorise_reporting();
    member.authorise_voting();
    member.verify();
    
    assert!(member.reporting_authorised);
    assert!(member.voting_authorised);
    assert_eq!(member.status, MemberStatus::Active);
    
    member.leave();
    assert_eq!(member.status, MemberStatus::Left);
}

#[test]
fn test_governance_key() {
    let governance_key = GovernanceKey {
        tenant_id: Uuid::new_v4(),
        version: 1,
        public_key: vec![0u8; 96],
        threshold: 2,
        total_shares: 3,
        created_at: Utc::now(),
        rotated_at: None,
        active: true,
    };
    
    assert!(governance_key.active);
    assert_eq!(governance_key.threshold, 2);
    assert_eq!(governance_key.total_shares, 3);
}

#[test]
fn test_epoch_calculations() {
    let epoch = Epoch::current();
    assert_eq!(epoch.start_timestamp() + snex_core::epoch::EPOCH_DURATION_SECONDS as u64, epoch.end_timestamp());
    assert_eq!(epoch.next().0, epoch.0 + 1);
    assert_eq!(epoch.previous().unwrap().0, epoch.0 - 1);
}

#[test]
fn test_credential_lifetime() {
    let epoch = Epoch::current();
    let lifetime = snex_core::epoch::CredentialLifetime::new(epoch, false);
    
    assert!(lifetime.is_valid_in_epoch(epoch));
    assert!(lifetime.is_valid_in_epoch(epoch.next()));
    assert!(lifetime.is_valid_in_epoch(epoch.next().next()));
    assert!(!lifetime.is_valid_in_epoch(epoch.next().next().next()));
    
    let advance_lifetime = snex_core::epoch::CredentialLifetime::new(epoch, true);
    assert!(advance_lifetime.is_governing_for(epoch.next(), true));
    assert!(!advance_lifetime.is_governing_for(epoch, true));
}

#[test]
fn test_pseudonym_registration() {
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
    
    assert_eq!(reg.state, PseudonymState::Provisional);
    assert!(!reg.is_active());
    
    let mut reg = reg;
    reg.activate();
    assert_eq!(reg.state, PseudonymState::Active);
    assert!(reg.is_active());
    assert!(reg.authorises(PseudonymFunction::Reporting));
    assert!(reg.authorises(PseudonymFunction::Voting));
}

#[test]
fn test_batching_buffer() {
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
fn test_ballot_lifecycle() {
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
    ballot.close();
    assert_eq!(ballot.status, snex_core::voting::BallotStatus::Closed);
    ballot.publish();
    assert_eq!(ballot.status, snex_core::voting::BallotStatus::Published);
}

#[test]
fn test_vote_register() {
    let op_secret = OperationSecret::generate();
    let pseudo_secret = PseudonymSecret::generate();
    let pseudonym = pseudo_secret.derive_pseudonym(b"tenant", 0);
    let nullifier = op_secret.derive_vote_nullifier(b"ballot1");
    
    let mut register = VoteRegister::new(Uuid::new_v4());
    
    let vote = Vote::new(Uuid::new_v4(), nullifier, VoteValue::Yes, pseudonym, vec![]);
    register.add_vote(&vote).unwrap();
    
    let tally = register.tally();
    assert_eq!(tally.yes, 1);
    assert_eq!(tally.total, 1);
    
    let vote2 = Vote::new(Uuid::new_v4(), nullifier, VoteValue::No, pseudonym, vec![]);
    assert!(register.add_vote(&vote2).is_err());
}

#[test]
fn test_snapshot_merkle_tree() {
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
fn test_reporting_flow() {
    let op_secret = OperationSecret::generate();
    let rate_limit_tag = op_secret.derive_report_nullifier(0, 0);
    
    let report = Report::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        rate_limit_tag,
        EncryptedData(vec![]),
        vec![],
        Epoch::current(),
    );
    
    assert_eq!(report.status, snex_core::reporting::ReportStatus::Submitted);
    
    let case_key = Dek::generate();
    let mut case = Case::new(&report, case_key, vec![], vec![], Uuid::new_v4());
    assert_eq!(case.status, snex_core::reporting::CaseStatus::Open);
    
    case.handover(vec![]);
    assert_eq!(case.status, snex_core::reporting::CaseStatus::HandedOver);
    
    case.close();
    assert_eq!(case.status, snex_core::reporting::CaseStatus::Closed);
}

#[test]
fn test_rate_limiting() {
    let mut window = RateLimitWindow::new(0, Uuid::new_v4(), 3);
    let op_secret = OperationSecret::generate();
    let tag = op_secret.derive_rate_limit_tag(0, b"tenant");
    
    for i in 0..3 {
        window.check_and_consume(&tag).unwrap();
    }
    
    assert!(window.check_and_consume(&tag).is_err());
}

#[test]
fn test_report_window_schedule() {
    let schedule = ReportWindowSchedule::default();
    let window_start = schedule.current_window_start();
    assert_eq!(schedule.window_for_timestamp(window_start + 3600), window_start);
    assert_eq!(schedule.window_for_timestamp(window_start + 24 * 3600), window_start + 24 * 3600);
}

#[test]
fn test_account_secrets() {
    let secrets = AccountSecrets::generate();
    assert_eq!(secrets.operation_secrets.len(), 1);
    assert!(secrets.next_epoch_secret.is_none());
    
    secrets.add_operation_secret(OperationSecret::generate(), secrets.current_epoch + 1);
    assert!(secrets.next_epoch_secret.is_some());
}

#[test]
fn test_retention_policies() {
    let policy = RetentionPolicy::default_for_class(RetentionClass::RA);
    assert_eq!(policy.backup_regime, BackupRegime::Regime1);
    assert_eq!(policy.retention_period_days, 14);
    
    let policy = RetentionPolicy::default_for_class(RetentionClass::RC);
    assert_eq!(policy.backup_regime, BackupRegime::Regime1);
    assert_eq!(policy.retention_period_days, 0);
    assert!(policy.legal_hold_exempt);
}

#[test]
fn test_retention_engine() {
    let master = MasterKey::generate();
    let mut engine = RetentionEngine::new(master, 1000);
    
    engine.register_data(
        "user123".into(),
        RetentionClass::RA,
        Some(Uuid::new_v4()),
        Some("person_key_1".into()),
    ).unwrap();
    
    engine.request_deletion("user123", "admin".into(), 100).unwrap();
    let record = engine.records.get("user123").unwrap();
    assert_eq!(record.state, DeletionState::RemovedFromApplication);
}

#[test]
fn test_legal_hold() {
    let master = MasterKey::generate();
    let mut engine = RetentionEngine::new(master, 1000);
    
    engine.register_data("user123".into(), RetentionClass::RA, Some(Uuid::new_v4()), Some("person_key_1".into())).unwrap();
    engine.place_legal_hold("user123", "investigation".into(), "legal".into(), 30, None).unwrap();
    
    assert!(engine.check_legal_hold("user123").unwrap());
    
    let hold_id = engine.records.get("user123").unwrap().legal_holds[0].id;
    engine.lift_legal_hold("user123", hold_id).unwrap();
    
    assert!(!engine.check_legal_hold("user123").unwrap());
}

#[test]
fn test_audit_chain() {
    let mut chain = AuditChain::new();
    chain.append("test".into(), "action".into(), serde_json::json!({}), None, None).unwrap();
    chain.append("test".into(), "action2".into(), serde_json::json!({}), None, None).unwrap();
    
    assert_eq!(chain.length, 2);
    assert!(chain.verify().unwrap());
    
    chain.add_anchor("test-service".into(), vec![]);
    assert_eq!(chain.anchored_hashes.len(), 1);
}

#[test]
fn test_security_critical_event() {
    let event = SecurityCriticalEvent {
        id: Uuid::new_v4(),
        event_type: SecurityCriticalEventType::KeyGeneration,
        timestamp: Utc::now(),
        data: serde_json::json!({}),
        anchored: false,
    };
    
    assert_eq!(event.event_type, SecurityCriticalEventType::KeyGeneration);
}

#[test]
fn test_level_c_room() {
    let mut room = LevelCRoom::new(
        Uuid::new_v4(),
        "Board Room".into(),
        "Confidential discussions".into(),
        Uuid::new_v4(),
        RoomRuleSet::default(),
    );
    
    assert!(room.active);
    assert_eq!(room.members.len(), 0);
    
    let device = MemberDevice {
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
fn test_recovery_backup() {
    let account_id = Uuid::new_v4();
    let recovery_phrase = "test recovery phrase with many words for testing purposes only";
    
    let backup = RecoveryPhraseBackup::new(account_id, recovery_phrase, b"MLS private keys".to_vec()).unwrap();
    let restored = backup.restore(recovery_phrase).unwrap();
    
    assert_eq!(restored, b"MLS private keys");
}

#[test]
fn test_config_defaults() {
    let config = AppConfig::default();
    assert_eq!(config.server.port, 8080);
    assert_eq!(config.issuer.epoch_duration_days, 180);
    assert_eq!(config.verifier.minimum_anonymity_set, 30);
    assert!(config.crypto.pq_wrapper_enabled);
}

#[test]
fn test_key_hierarchy() {
    let master = MasterKey::generate();
    let mut hierarchy = KeyHierarchy::new(master);
    
    let kek = hierarchy.get_or_create_kek("tenant1");
    let dek = hierarchy.get_or_create_dek("tenant1", "user123");
    
    let plaintext = b"Hello, World!";
    let encrypted = dek.encrypt(plaintext, b"aad").unwrap();
    let decrypted = dek.decrypt(&encrypted, b"aad").unwrap();
    assert_eq!(plaintext, decrypted.as_slice());
}

#[test]
fn test_dek_wrapping() {
    let master = MasterKey::generate();
    let kek = master.derive_kek(b"test");
    let dek = Dek::generate();
    
    let wrapped = kek.wrap_dek(&dek);
    let unwrapped = kek.unwrap_dek(&wrapped).unwrap();
    assert_eq!(dek.0.as_ref(), unwrapped.0.as_ref());
}

#[test]
fn test_backup_wrapping_key() {
    let master = MasterKey::generate();
    let bwk = master.derive_backup_wrapping_key(1);
    let data = b"backup data";
    
    let wrapped = bwk.wrap(data).unwrap();
    let unwrapped = bwk.unwrap(&wrapped).unwrap();
    assert_eq!(data, unwrapped.as_slice());
}

#[test]
fn test_x25519_dh() {
    let alice = X25519KeyPair::generate();
    let bob = X25519KeyPair::generate();
    let shared1 = alice.diffie_hellman(&bob.public);
    let shared2 = bob.diffie_hellman(&alice.public);
    assert_eq!(shared1, shared2);
}

#[test]
fn test_ed25519_sign_verify() {
    let kp = Ed25519KeyPair::generate();
    let msg = b"test message";
    let sig = kp.sign(msg);
    kp.verify(msg, &sig).unwrap();
}

#[test]
fn test_ml_kem_768() {
    let kp = MlKem768KeyPair::generate().unwrap();
    let (ct, ss1) = kp.encapsulate().unwrap();
    let ss2 = kp.decapsulate(&ct).unwrap();
    assert_eq!(ss1, ss2);
}

#[test]
fn test_ml_kem_1024() {
    let kp = MlKem1024KeyPair::generate().unwrap();
    let (ct, ss1) = kp.encapsulate().unwrap();
    let ss2 = kp.decapsulate(&ct).unwrap();
    assert_eq!(ss1, ss2);
}

#[test]
fn test_ml_dsa() {
    let kp = MlDsaKeyPair::generate().unwrap();
    let msg = b"test message";
    let sig = kp.sign(msg).unwrap();
    let valid = MlDsaKeyPair::verify(&kp.public, msg, &sig).unwrap();
    assert!(valid);
}

#[test]
fn test_hybrid_key_exchange() {
    let alice_x25519 = X25519KeyPair::generate();
    let alice_mlkem = MlKem768KeyPair::generate().unwrap();
    let bob_x25519 = X25519KeyPair::generate();
    let bob_mlkem = MlKem768KeyPair::generate().unwrap();
    
    let alice_shared = hybrid_key_exchange(
        &alice_x25519, &alice_mlkem,
        &bob_x25519.public, &bob_mlkem.public
    ).unwrap();
    
    let bob_shared = hybrid_key_exchange(
        &bob_x25519, &bob_mlkem,
        &alice_x25519.public, &alice_mlkem.public
    ).unwrap();
    
    assert_eq!(alice_shared, bob_shared);
}

#[test]
fn test_hybrid_signature() {
    let ed_kp = Ed25519KeyPair::generate();
    let ml_kp = MlDsaKeyPair::generate().unwrap();
    let msg = b"test message";
    
    let sig = sign_with_both(&ed_kp, &ml_kp, msg).unwrap();
    let valid = verify_with_both(&ed_kp.public, &ml_kp.public, msg, &sig).unwrap();
    assert!(valid);
}

#[test]
fn test_argon2id() {
    let password = b"test password";
    let salt = generate_salt();
    let key1 = derive_key_argon2id(password, &salt).unwrap();
    let key2 = derive_key_argon2id(password, &salt).unwrap();
    assert_eq!(key1, key2);
    
    let salt2 = generate_salt();
    let key3 = derive_key_argon2id(password, &salt2).unwrap();
    assert_ne!(key1, key3);
}

#[test]
fn test_recovery_phrase() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = recovery_phrase_to_seed(phrase).unwrap();
    assert_eq!(seed.len(), 32);
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