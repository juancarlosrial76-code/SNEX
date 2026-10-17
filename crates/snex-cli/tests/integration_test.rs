use snex_cli::{commands::Cli, config::AppConfig};
use snex_crypto::{
    nullifiers::{OperationSecret, PseudonymSecret, RecoveryCode},
    kdf::generate_salt,
    encryption::EncryptedData,
};
use uuid::Uuid;
use tempfile::tempdir;

#[test]
fn test_cli_config_show() {
    let config = AppConfig::default();
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("config.toml");
    
    snex_cli::config::save_config(&config, &config_path).unwrap();
    
    let loaded = snex_cli::config::load_config(Some(&config_path)).unwrap();
    assert_eq!(loaded.server.port, 8080);
    assert_eq!(loaded.issuer.epoch_duration_days, 180);
}

#[test]
fn test_cli_config_init() {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("new_config.toml");
    
    let config = AppConfig::default();
    snex_cli::config::save_config(&config, &config_path).unwrap();
    
    assert!(config_path.exists());
    let content = std::fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("server"));
    assert!(content.contains("database"));
    assert!(content.contains("crypto"));
}

#[test]
fn test_backup_generate_recovery_phrase() {
    let phrase = snex_client::backup::BackupManager::generate_recovery_phrase();
    let words: Vec<&str> = phrase.split_whitespace().collect();
    assert_eq!(words.len(), 24);
}

#[test]
fn test_backup_account_creation() {
    let account_id = Uuid::new_v4();
    let pseudo_secret = PseudonymSecret::generate();
    let op_secret = OperationSecret::generate();
    let mailbox_base = snex_crypto::nullifiers::MailboxBaseSecret([0u8; 32].into());
    let recovery = RecoveryCode::generate();
    
    let backup = snex_client::backup::BackupManager::create_account_backup(
        account_id,
        &pseudo_secret,
        &[op_secret],
        &mailbox_base,
        &recovery,
    ).unwrap();
    
    assert_eq!(backup.account_id, account_id);
    assert!(!backup.encrypted_data.0.is_empty());
    assert_eq!(backup.salt.len(), 16);
}

#[test]
fn test_backup_account_restore() {
    let account_id = Uuid::new_v4();
    let pseudo_secret = PseudonymSecret::generate();
    let op_secret = OperationSecret::generate();
    let mailbox_base = snex_crypto::nullifiers::MailboxBaseSecret([0u8; 32].into());
    let recovery = RecoveryCode::generate();
    
    let backup = snex_client::backup::BackupManager::create_account_backup(
        account_id,
        &pseudo_secret,
        &[op_secret],
        &mailbox_base,
        &recovery,
    ).unwrap();
    
    let phrase = snex_client::backup::BackupManager::generate_recovery_phrase();
    let restored = snex_client::backup::BackupManager::restore_account_backup(&backup, &phrase);
    
    assert!(restored.is_ok());
}

#[test]
fn test_cli_commands_parsing() {
    let cli = Cli::try_parse_from(["snex", "config", "show"]).unwrap();
    assert!(matches!(cli.command, snex_cli::commands::Commands::Config { action: snex_cli::commands::ConfigAction::Show }));
    
    let cli = Cli::try_parse_from(["snex", "config", "init", "--path", "test.toml"]).unwrap();
    assert!(matches!(cli.command, snex_cli::commands::Commands::Config { action: snex_cli::commands::ConfigAction::Init { .. } }));
    
    let cli = Cli::try_parse_from(["snex", "account", "create", "--email", "test@test.com", "--display-name", "Test"]).unwrap();
    assert!(matches!(cli.command, snex_cli::commands::Commands::Account { action: snex_cli::commands::AccountAction::Create { .. } }));
}

#[test]
fn test_credential_manager() {
    let secrets = snex_core::identity::AccountSecrets::generate();
    let manager = snex_client::credentials::CredentialManager::new(secrets);
    
    let pseudonym = manager.derive_pseudonym(b"tenant1", 0);
    assert!(!pseudonym.as_bytes().iter().all(|&b| b == 0));
    
    let epoch = snex_core::epoch::Epoch::current();
    let est_nullifier = manager.derive_establishment_nullifier(epoch, b"tenant1", 0);
    assert!(est_nullifier.is_some());
    
    let ballot_id = b"ballot1";
    let vote_nullifier = manager.derive_vote_nullifier(ballot_id);
    assert!(vote_nullifier.is_some());
}

#[test]
fn test_proof_generator() {
    use snex_client::proofs::ProofGenerator;
    use snex_crypto::{
        bbs::BbsCredential,
        commitments::Commitment,
        nullifiers::{OperationSecret, PairTag},
    };
    use snex_core::epoch::Epoch;
    use uuid::Uuid;
    
    let op_secret = OperationSecret::generate();
    let establishment_nullifier = op_secret.derive_establishment_nullifier(1, b"tenant", 0);
    let pair_tag = op_secret.derive_pair_tag(1, b"tenant");
    
    let person_cred = BbsCredential {
        schema_id: "test".into(),
        issuer: snex_crypto::bbs::BbsPublicKey { key: vec![0u8; 96] },
        subject: vec![],
        attributes: vec![],
        signature: snex_crypto::bbs::BbsSignature { signature: vec![0u8; 112] },
        epoch: 1,
        issued_at: 0,
        expires_at: 0,
    };
    
    let membership_cred = BbsCredential {
        schema_id: "test".into(),
        issuer: snex_crypto::bbs::BbsPublicKey { key: vec![0u8; 96] },
        subject: vec![],
        attributes: vec![b"reporting".to_vec(), b"voting".to_vec()],
        signature: snex_crypto::bbs::BbsSignature { signature: vec![0u8; 112] },
        epoch: 1,
        issued_at: 0,
        expires_at: 0,
    };
    
    let commitment_key = snex_crypto::commitments::CommitmentKey::generate();
    let value = snex_crypto::commitments::random_scalar();
    let blinding = snex_crypto::commitments::random_blinding();
    let pc = snex_crypto::commitments::PedersenCommitment::new(value, blinding);
    let commitment = pc.commit(&commitment_key);
    
    let req = ProofGenerator::generate_establishment_proof(
        &person_cred,
        &membership_cred,
        &commitment,
        &commitment_key,
        Epoch(1),
        b"tenant",
        0,
    ).unwrap();
    
    assert_eq!(req.tenant_id, Uuid::from_slice(b"tenant").unwrap());
    assert_eq!(req.epoch, Epoch(1));
    assert_eq!(req.lifetime_index, 0);
}