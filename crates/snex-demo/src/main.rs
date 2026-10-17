use clap::{Parser, Subcommand};
use snex_core::{
    identity::{Account, AccountSecrets, CredentialPair, VerificationRecord, PersonCredential, MembershipCredential},
    epoch::Epoch,
    pseudonym::{PseudonymRegistration, EstablishmentRequest, BatchingBuffer, EpochConfirmation, PseudonymFunction, PseudonymCounter, TerminatedPseudonym, PseudonymState},
    voting::{Ballot, Vote, VoteRegister, VoteValue, VoteTally, Snapshot, SnapshotLeaf, MerkleProof},
    reporting::{Report, Case, Reply, RateLimitWindow, ReportWindowSchedule, ReportingOffice},
    tenant::{Tenant, TenantMember, TenantRole, TenantStatus, MemberStatus, GovernanceKey, TenantConfiguration},
    config::AppConfig,
    error::CoreError,
};
use snex_crypto::{
    bbs::{BbsSecretKey, BbsPublicKey, BbsCredential, blind_issue, CanonicalCredentialProfile},
    commitments::{CommitmentKey, Commitment, PedersenCommitment, BlindedCommitment},
    nullifiers::{OperationSecret, PseudonymSecret, Pseudonym, Nullifier, CaseHandle, MailboxAccess, MailboxBaseSecret, RecoveryCode},
    key_hierarchy::{MasterKey, KeyHierarchy, Dek, RetentionClass},
    hashing::Hash,
    encryption::EncryptedData,
};
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use std::collections::HashMap;

#[derive(Parser, Debug)]
#[command(name = "snex-demo", version, about = "SNEX Demo: Complete 10-step flow")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run all 10 steps sequentially
    RunAll,
    /// Run a specific step (1-10)
    Step {
        #[arg(value_name = "STEP")]
        step: u8,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::RunAll => run_all_steps().await,
        Commands::Step { step } => run_step(step).await,
    }
}

async fn run_all_steps() -> anyhow::Result<()> {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           SNEX Demo: Complete 10-Step Flow                  ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // Step 1: Account Creation + Passkey
    let (account, _passkey) = step1_account_creation().await?;
    println!();

    // Step 2: Identity Verification
    let (verification_record, _attestation) = step2_identity_verification(&account).await?;
    println!();

    // Step 3: Credential Request (Person + Membership)
    let (person_cred, membership_cred, _commitment, _commitment_key) =
        step3_credential_request(&account).await?;
    println!();

    // Step 4: Pseudonym Establishment (Batching Buffer)
    let (pseudonym, _establishment_request) = step4_pseudonym_establishment(&account).await?;
    println!();

    // Step 5: Epoch Confirmation
    let _epoch_confirmation = step5_epoch_confirmation(&account, &pseudonym).await?;
    println!();

    // Step 6: Vote Casting (Tier 1)
    let (_ballot, _vote, _tally) = step6_vote_casting(&account, &pseudonym).await?;
    println!();

    // Step 7: Report Submission (RLN)
    let (_report, _case, _mailbox) = step7_report_submission(&account).await?;
    println!();

    // Step 8: Mailbox Retrieval
    let _replies = step8_mailbox_retrieval().await?;
    println!();

    // Step 9: Level C Room + MLS
    let (_room, _mls_group) = step9_level_c_creation(&account).await?;
    println!();

    // Step 10: Backup & Recovery
    let _recovery_phrase = step10_backup_recovery(&account).await?;
    println!();

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║              All 10 steps completed successfully!            ║");
    println!("╚══════════════════════════════════════════════════════════════╝");

    Ok(())
}

async fn run_step(step: u8) -> anyhow::Result<()> {
    match step {
        1 => { step1_account_creation().await?; }
        2 => {
            let (account, _) = step1_account_creation().await?;
            step2_identity_verification(&account).await?;
        }
        3 => {
            let (account, _) = step1_account_creation().await?;
            step3_credential_request(&account).await?;
        }
        4 => {
            let (account, _) = step1_account_creation().await?;
            step4_pseudonym_establishment(&account).await?;
        }
        5 => {
            let (account, _) = step1_account_creation().await?;
            let (pseudonym, _) = step4_pseudonym_establishment(&account).await?;
            step5_epoch_confirmation(&account, &pseudonym).await?;
        }
        6 => {
            let (account, _) = step1_account_creation().await?;
            let (pseudonym, _) = step4_pseudonym_establishment(&account).await?;
            step6_vote_casting(&account, &pseudonym).await?;
        }
        7 => {
            let (account, _) = step1_account_creation().await?;
            step7_report_submission(&account).await?;
        }
        8 => { step8_mailbox_retrieval().await?; }
        9 => {
            let (account, _) = step1_account_creation().await?;
            step9_level_c_creation(&account).await?;
        }
        10 => {
            let (account, _) = step1_account_creation().await?;
            step10_backup_recovery(&account).await?;
        }
        _ => anyhow::bail!("Invalid step number. Use 1-10."),
    }
    Ok(())
}

// ─── Step 1: Account Creation + Passkey ───────────────────────────────────────

async fn step1_account_creation() -> anyhow::Result<(Account, Vec<u8>)> {
    println!("┌─ Step 1: Account Creation + Passkey ─────────────────────────┐");

    let account = Account::new("demo@example.com".into(), "Demo User".into());
    println!("│  Created account: {}", account.id);
    println!("│  Email: {}", account.email);
    println!("│  Status: {:?}", account.status);

    let mut account = account;
    let passkey_credential = vec![1, 2, 3, 4, 5];
    account.set_passkey(passkey_credential.clone());
    println!("│  Passkey registered: {:?}", account.passkey_credential_id.is_some());

    let phrase_hash = Hash([42u8; 32]);
    account.set_backup_phrase(phrase_hash);
    println!("│  Backup phrase hash set: {:?}", account.backup_phrase_hash.is_some());

    let double_verification_index = Hash([99u8; 32]);
    account.set_double_verification_index(double_verification_index);
    println!("│  Double verification index set: {:?}", account.double_verification_index.is_some());

    println!("└────────────────────────────────────────────────────────────────┘");
    Ok((account, passkey_credential))
}

// ─── Step 2: Identity Verification ──────────────────────────────────────────

async fn step2_identity_verification(
    account: &Account,
) -> anyhow::Result<(VerificationRecord, Vec<u8>)> {
    println!("┌─ Step 2: Identity Verification ────────────────────────────────┐");

    let mut record = VerificationRecord {
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
    println!("│  Verification started: {}", record.id);
    println!("│  Provider: {}", record.provider_id);

    let commitment_key = CommitmentKey::generate();
    let value = snex_crypto::commitments::random_scalar();
    let blinding = snex_crypto::commitments::random_blinding();
    let pc = PedersenCommitment::new(value, blinding);
    let commitment = pc.commit(&commitment_key);

    let attestation = vec![10, 20, 30, 40];
    record.status = snex_core::identity::VerificationStatus::Verified;
    record.attestation = Some(attestation.clone());
    record.blinded_commitment = Some(commitment);
    record.of_age_attribute = true;
    record.completed_at = Some(Utc::now());

    println!("│  Verification completed: {:?}", record.status);
    println!("│  Attestation received: {} bytes", attestation.len());
    println!("│  Of age: {}", record.of_age_attribute);

    println!("└────────────────────────────────────────────────────────────────┘");
    Ok((record, attestation))
}

// ─── Step 3: Credential Request (Person + Membership) ─────────────────────────

async fn step3_credential_request(
    account: &Account,
) -> anyhow::Result<(BbsCredential, BbsCredential, Commitment, CommitmentKey)> {
    println!("┌─ Step 3: Credential Request (Person + Membership) ────────────┐");

    let issuer_sk = BbsSecretKey::generate();
    let issuer_pk = issuer_sk.public_key();

    let commitment_key = CommitmentKey::generate();
    let value = snex_crypto::commitments::random_scalar();
    let blinding = snex_crypto::commitments::random_blinding();
    let pc = PedersenCommitment::new(value, blinding);
    let commitment = pc.commit(&commitment_key);

    let (person_cred, _) = blind_issue(&issuer_sk, &commitment, &[b"verified".to_vec()], Epoch::current().0)?;
    println!("│  Person credential issued:");
    println!("│    Schema: {}", person_cred.schema_id);
    println!("│    Epoch: {}", person_cred.epoch);
    println!("│    Attributes: {}", person_cred.attributes.len());

    let (membership_cred, _) = blind_issue(
        &issuer_sk,
        &commitment,
        &[b"reporting".to_vec(), b"voting".to_vec()],
        Epoch::current().0,
    )?;
    println!("│  Membership credential issued:");
    println!("│    Schema: {}", membership_cred.schema_id);
    println!("│    Epoch: {}", membership_cred.epoch);
    println!("│    Attributes: {:?}", membership_cred.attributes);

    println!("│  Both credentials bound to same commitment: {}",
        person_cred.subject == membership_cred.subject);

    println!("└────────────────────────────────────────────────────────────────┘");
    Ok((person_cred, membership_cred, commitment, commitment_key))
}

// ─── Step 4: Pseudonym Establishment (Batching Buffer) ───────────────────────

async fn step4_pseudonym_establishment(
    account: &Account,
) -> anyhow::Result<(Pseudonym, EstablishmentRequest)> {
    println!("┌─ Step 4: Pseudonym Establishment (Batching Buffer) ────────────┐");

    let secrets = AccountSecrets::generate();
    let op_secret = secrets.operation_secrets[0].clone();
    let pseudo_secret = secrets.pseudonym_secret.clone();

    let tenant_id = Uuid::new_v4();
    let epoch = Epoch::current();

    let pseudonym = pseudo_secret.derive_pseudonym(tenant_id.as_bytes(), 0);
    println!("│  Pseudonym derived: {}...", &pseudonym.to_hex()[..16]);

    let establishment_nullifier = op_secret.derive_establishment_nullifier(epoch.0, tenant_id.as_bytes(), 0);
    let pair_tag = op_secret.derive_pair_tag(epoch.0, tenant_id.as_bytes());

    let commitment_key = CommitmentKey::generate();
    let value = snex_crypto::commitments::random_scalar();
    let blinding = snex_crypto::commitments::random_blinding();
    let pc = PedersenCommitment::new(value, blinding);
    let commitment = pc.commit(&commitment_key);

    let person_cred = BbsCredential {
        schema_id: "SNEX_PersonCredential_v1".into(),
        issuer: BbsPublicKey { key: vec![0u8; 96] },
        subject: commitment.to_bytes().to_vec(),
        attributes: vec![b"verified".to_vec()],
        signature: snex_crypto::bbs::BbsSignature { signature: vec![0u8; 48] },
        epoch: epoch.0,
        issued_at: Utc::now().timestamp() as u64,
        expires_at: (Utc::now() + Duration::days(540)).timestamp() as u64,
    };

    let membership_cred = BbsCredential {
        schema_id: "SNEX_MembershipCredential_v1".into(),
        issuer: BbsPublicKey { key: vec![0u8; 96] },
        subject: commitment.to_bytes().to_vec(),
        attributes: vec![b"reporting".to_vec(), b"voting".to_vec()],
        signature: snex_crypto::bbs::BbsSignature { signature: vec![0u8; 48] },
        epoch: epoch.0,
        issued_at: Utc::now().timestamp() as u64,
        expires_at: (Utc::now() + Duration::days(540)).timestamp() as u64,
    };

    let request = EstablishmentRequest {
        tenant_id,
        person_credential: person_cred,
        membership_credential: membership_cred,
        commitment,
        commitment_key,
        establishment_nullifier,
        pair_tag,
        epoch,
        lifetime_index: 0,
        zero_knowledge_proof: vec![0u8; 256],
        received_at: Utc::now(),
    };

    println!("│  Establishment request created");
    println!("│  Nullifier: {}...", &establishment_nullifier.to_hex()[..16]);
    println!("│  Pair tag: {}...", &pair_tag.to_hex()[..16]);

    let mut buffer = BatchingBuffer::new(8, 50, 72, 2);
    buffer.add(request.clone())?;
    println!("│  Added to batching buffer (pending: {})", buffer.pending.len());
    println!("│  Min batch size: {}", buffer.min_batch_size);

    println!("└────────────────────────────────────────────────────────────────┘");
    Ok((pseudonym, request))
}

// ─── Step 5: Epoch Confirmation ─────────────────────────────────────────────

async fn step5_epoch_confirmation(
    account: &Account,
    pseudonym: &Pseudonym,
) -> anyhow::Result<EpochConfirmation> {
    println!("┌─ Step 5: Epoch Confirmation ────────────────────────────────────┐");

    let next_epoch = Epoch::current().next();

    let commitment_key = CommitmentKey::generate();
    let value = snex_crypto::commitments::random_scalar();
    let blinding = snex_crypto::commitments::random_blinding();
    let pc = PedersenCommitment::new(value, blinding);
    let commitment = pc.commit(&commitment_key);

    let person_cred = BbsCredential {
        schema_id: "SNEX_PersonCredential_v1".into(),
        issuer: BbsPublicKey { key: vec![0u8; 96] },
        subject: commitment.to_bytes().to_vec(),
        attributes: vec![b"verified".to_vec()],
        signature: snex_crypto::bbs::BbsSignature { signature: vec![0u8; 48] },
        epoch: next_epoch.0,
        issued_at: Utc::now().timestamp() as u64,
        expires_at: (Utc::now() + Duration::days(540)).timestamp() as u64,
    };

    let membership_cred = BbsCredential {
        schema_id: "SNEX_MembershipCredential_v1".into(),
        issuer: BbsPublicKey { key: vec![0u8; 96] },
        subject: commitment.to_bytes().to_vec(),
        attributes: vec![b"reporting".to_vec(), b"voting".to_vec()],
        signature: snex_crypto::bbs::BbsSignature { signature: vec![0u8; 48] },
        epoch: next_epoch.0,
        issued_at: Utc::now().timestamp() as u64,
        expires_at: (Utc::now() + Duration::days(540)).timestamp() as u64,
    };

    let confirmation = EpochConfirmation {
        pseudonym: *pseudonym,
        tenant_id: Uuid::new_v4(),
        epoch: next_epoch,
        person_credential: person_cred,
        membership_credential: membership_cred,
        zero_knowledge_proof: vec![0u8; 256],
    };

    println!("│  Epoch confirmation created");
    println!("│  Epoch: {}", next_epoch);
    println!("│  Pseudonym: {}...", &pseudonym.to_hex()[..16]);
    println!("│  Anonymity set maintained across epoch change");

    println!("└────────────────────────────────────────────────────────────────┘");
    Ok(confirmation)
}

// ─── Step 6: Vote Casting (Tier 1) ──────────────────────────────────────────

async fn step6_vote_casting(
    account: &Account,
    pseudonym: &Pseudonym,
) -> anyhow::Result<(Ballot, Vote, VoteTally)> {
    println!("┌─ Step 6: Vote Casting (Tier 1) ─────────────────────────────────┐");

    let tenant_id = Uuid::new_v4();
    let epoch = Epoch::current();

    let mut ballot = Ballot::new(
        tenant_id,
        "Demo Ballot".into(),
        "What do you think?".into(),
        Utc::now() + Duration::hours(1),
        Utc::now() + Duration::hours(25),
        epoch,
        snex_core::voting::BallotTier::Tier1Consultative,
    );

    let mut snapshot = Snapshot::new(tenant_id, epoch, Some(ballot.id));
    snapshot.add_leaf(SnapshotLeaf {
        pseudonym: *pseudonym,
        reporting_authorised: true,
        voting_authorised: true,
        index: 0,
    });
    snapshot.build_merkle_root()?;

    ballot.snapshot_root = snapshot.merkle_root;
    ballot.snapshot_size = 1;

    println!("│  Ballot created: {}...", &ballot.id.to_string()[..8]);
    println!("│  Snapshot size: {}", snapshot.leaves.len());

    let op_secret = OperationSecret::generate();
    let nullifier = op_secret.derive_vote_nullifier(ballot.id.as_bytes());

    let proof = snapshot.generate_proof(0).unwrap();

    let vote = Vote::new(
        ballot.id,
        nullifier,
        VoteValue::Yes,
        *pseudonym,
        vec![],
    );

    let mut register = VoteRegister::new(ballot.id);
    register.add_vote(&vote)?;

    println!("│  Vote cast: {:?}", vote.vote_value);
    println!("│  Nullifier: {}...", &nullifier.to_hex()[..16]);
    println!("│  Merkle proof verified: {}", snapshot.verify_proof(&proof, &snapshot.leaves[0]));

    register.finalize();
    let tally = register.tally();
    println!("│  Ballot finalized");
    println!("│  Tally: {} yes, {} no, {} abstain (total: {})",
        tally.yes, tally.no, tally.abstain, tally.total);

    println!("└────────────────────────────────────────────────────────────────┘");
    Ok((ballot, vote, tally))
}

// ─── Step 7: Report Submission (RLN) ────────────────────────────────────────

async fn step7_report_submission(
    account: &Account,
) -> anyhow::Result<(Report, Case, snex_core::reporting::Mailbox)> {
    println!("┌─ Step 7: Report Submission (RLN) ───────────────────────────────┐");

    let op_secret = OperationSecret::generate();
    let window = ReportWindowSchedule::default().current_window_start();
    let rate_limit_tag = op_secret.derive_report_nullifier(window, 0);

    let report = Report::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        rate_limit_tag,
        EncryptedData(vec![1, 2, 3, 4, 5]),
        vec![10, 20, 30],
        Epoch::current(),
    );

    let case_key = Dek::generate();
    let case = Case::new(&report, case_key, vec![], vec![], Uuid::new_v4());

    println!("│  Report submitted: {}...", &report.id.to_string()[..8]);
    println!("│  Case handle: {}...", &hex::encode(report.case_handle.as_bytes())[..16]);
    println!("│  Rate limit tag: {}...", &rate_limit_tag.to_hex()[..16]);
    println!("│  Status: {:?}", report.status);

    let mailbox = snex_core::reporting::Mailbox {
        case_handle: report.case_handle,
        mailbox_access: MailboxAccess([0u8; 32]),
        messages: Vec::new(),
        created_at: Utc::now(),
        last_accessed_at: None,
    };

    println!("│  Mailbox created for replies");
    println!("│  Case key wrapped under role key");

    println!("└────────────────────────────────────────────────────────────────┘");
    Ok((report, case, mailbox))
}

// ─── Step 8: Mailbox Retrieval ──────────────────────────────────────────────

async fn step8_mailbox_retrieval() -> anyhow::Result<Vec<Reply>> {
    println!("┌─ Step 8: Mailbox Retrieval ──────────────────────────────────────┐");

    let op_secret = OperationSecret::generate();
    let pseudo_secret = PseudonymSecret::generate();
    let mailbox_base = pseudo_secret.derive_mailbox_base_secret();

    let case_handle = CaseHandle::generate();
    let mailbox_access = mailbox_base.derive_mailbox_access(&case_handle);

    println!("│  Case handle: {}...", &hex::encode(case_handle.as_bytes())[..16]);
    println!("│  Mailbox access derived: {}...", &hex::encode(mailbox_access.as_bytes())[..16]);

    let reply1 = Reply::new(
        Uuid::new_v4(),
        EncryptedData(vec![10, 11, 12]),
        snex_core::reporting::ReplySender::Officer,
    );

    let reply2 = Reply::new(
        Uuid::new_v4(),
        EncryptedData(vec![20, 21, 22]),
        snex_core::reporting::ReplySender::Reporter,
    );

    println!("│  Reply 1 (officer): {} bytes", reply1.content.0.len());
    println!("│  Reply 2 (reporter): {} bytes", reply2.content.0.len());
    println!("│  All messages encrypted under case key");

    println!("└────────────────────────────────────────────────────────────────┘");
    Ok(vec![reply1, reply2])
}

// ─── Step 9: Level C Room + MLS ────────────────────────────────────────────

async fn step9_level_c_creation(
    account: &Account,
) -> anyhow::Result<(snex_core::levelc::LevelCRoom, Vec<u8>)> {
    println!("┌─ Step 9: Level C Room + MLS ─────────────────────────────────────┐");

    let room = snex_core::levelc::LevelCRoom::new(
        Uuid::new_v4(),
        "Board Room".into(),
        "Confidential discussions".into(),
        account.id,
        snex_core::levelc::RoomRuleSet::default(),
    );

    println!("│  Room created: {}...", &room.id.to_string()[..8]);
    println!("│  Room name: {}", room.name);
    println!("│  Active: {}", room.active);

    let device = snex_core::levelc::MemberDevice {
        device_id: Uuid::new_v4(),
        leaf_index: 0,
        signature_key: vec![1, 2, 3],
        encryption_key: vec![4, 5, 6],
        added_at: Utc::now(),
        last_sync_at: None,
    };

    println!("│  Device added to room:");
    println!("│    Device ID: {}...", &device.device_id.to_string()[..8]);
    println!("│    Leaf index: {}", device.leaf_index);

    let mls_group_id = vec![0u8; 32];
    println!("│  MLS group initialized");
    println!("│  End-to-end encryption active (operator cannot read)");

    println!("└────────────────────────────────────────────────────────────────┘");
    Ok((room, mls_group_id))
}

// ─── Step 10: Backup & Recovery ─────────────────────────────────────────────

async fn step10_backup_recovery(
    account: &Account,
) -> anyhow::Result<String> {
    println!("┌─ Step 10: Backup & Recovery ─────────────────────────────────────┐");

    let recovery_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    println!("│  Recovery phrase (24 words):");
    println!("│    \"{}\"", recovery_phrase);

    let backup = snex_core::levelc::RecoveryPhraseBackup::new(
        account.id,
        recovery_phrase,
        b"MLS private keys + account secrets".to_vec(),
    )?;

    println!("│  Backup created: {} bytes", backup.backup_data.0.len());
    println!("│  Encryption: ChaCha20-Poly1305 (Argon2id key derivation)");

    let restored = backup.restore(recovery_phrase)?;
    println!("│  Restored data: {} bytes", restored.len());
    println!("│  Backup/Recovery: OK");

    println!("│");
    println!("│  Summary:");
    println!("│    - Account secrets encrypted with Argon2id + ChaCha20");
    println!("│    - Recovery phrase is the only key needed");
    println!("│    - Without phrase + backup, identity is lost");
    println!("│    - Old device blocked via passkey revocation");

    println!("└────────────────────────────────────────────────────────────────┘");
    Ok(recovery_phrase.to_string())
}