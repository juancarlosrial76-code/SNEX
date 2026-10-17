use snex_core::{
    levelc::RecoveryPhraseBackup,
    error::{CoreError, Result},
};
use snex_crypto::{
    nullifiers::{RecoveryCode, MailboxBaseSecret, PseudonymSecret},
    kdf::{recovery_phrase_to_seed, derive_key_argon2id, generate_salt},
    encryption::EncryptedData,
};
use uuid::Uuid;
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, Zeroizing};

pub struct BackupManager;

impl BackupManager {
    pub fn create_recovery_backup(
        account_id: Uuid,
        recovery_phrase: &str,
        backup_data: Vec<u8>,
    ) -> Result<RecoveryPhraseBackup> {
        RecoveryPhraseBackup::new(account_id, recovery_phrase, backup_data)
    }

    pub fn restore_recovery_backup(
        backup: &RecoveryPhraseBackup,
        recovery_phrase: &str,
    ) -> Result<Vec<u8>> {
        backup.restore(recovery_phrase)
    }

    pub fn generate_recovery_phrase() -> String {
        let words = [
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse",
            "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act",
        ];
        let mut phrase = Vec::new();
        for _ in 0..24 {
            let idx = rand::random::<usize>() % words.len();
            phrase.push(words[idx]);
        }
        phrase.join(" ")
    }

    pub fn create_account_backup(
        account_id: Uuid,
        recovery_phrase: &str,
        pseudonym_secret: &PseudonymSecret,
        operation_secrets: &[snex_crypto::nullifiers::OperationSecret],
        mailbox_base_secret: &MailboxBaseSecret,
        recovery_code: &RecoveryCode,
    ) -> Result<AccountBackup> {
        let seed = recovery_phrase_to_seed(recovery_phrase)?;
        
        let salt = generate_salt();
        let backup_key = derive_key_argon2id(seed.as_ref(), &salt)?;
        
        let mut data = Vec::new();
        data.extend_from_slice(pseudonym_secret.as_bytes());
        for op_secret in operation_secrets {
            data.extend_from_slice(op_secret.as_bytes());
        }
        data.extend_from_slice(mailbox_base_secret.0.as_ref());
        data.extend_from_slice(recovery_code.as_bytes());
        
        let dek = snex_crypto::key_hierarchy::Dek(Zeroizing::new(backup_key));
        let encrypted = dek.encrypt_chacha(&data, &salt)?;
        
        Ok(AccountBackup {
            account_id,
            encrypted_data: encrypted,
            salt,
            created_at: chrono::Utc::now(),
        })
    }

    pub fn restore_account_backup(
        backup: &AccountBackup,
        recovery_phrase: &str,
    ) -> Result<AccountBackupData> {
        let seed = recovery_phrase_to_seed(recovery_phrase)?;
        let backup_key = derive_key_argon2id(seed.as_ref(), &backup.salt)?;
        
        let dek = snex_crypto::key_hierarchy::Dek(Zeroizing::new(backup_key));
        let decrypted = dek.decrypt_chacha(&backup.encrypted_data, &backup.salt)?;
        
        if decrypted.len() < 96 {
            return Err(CoreError::InvalidParameter("Invalid backup data".into()));
        }
        
        let mut offset = 0;
        let pseudonym_secret = snex_crypto::nullifiers::PseudonymSecret::from_bytes(
            decrypted[offset..offset+32].try_into().unwrap()
        );
        offset += 32;
        
        let mut operation_secrets = Vec::new();
        while offset + 96 <= decrypted.len() {
            let secret = snex_crypto::nullifiers::OperationSecret::from_bytes(
                decrypted[offset..offset+32].try_into().unwrap()
            );
            operation_secrets.push(secret);
            offset += 32;
        }
        
        let mailbox_base_secret = snex_crypto::nullifiers::MailboxBaseSecret(
            Zeroizing::new(decrypted[offset..offset+32].try_into().unwrap())
        );
        offset += 32;
        
        let recovery_code = snex_crypto::nullifiers::RecoveryCode(
            decrypted[offset..offset+32].try_into().unwrap()
        );
        
        Ok(AccountBackupData {
            pseudonym_secret,
            operation_secrets,
            mailbox_base_secret,
            recovery_code,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountBackup {
    pub account_id: Uuid,
    pub encrypted_data: EncryptedData,
    pub salt: [u8; 16],
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Zeroize, Serialize, Deserialize)]
pub struct AccountBackupData {
    pub pseudonym_secret: snex_crypto::nullifiers::PseudonymSecret,
    pub operation_secrets: Vec<snex_crypto::nullifiers::OperationSecret>,
    pub mailbox_base_secret: MailboxBaseSecret,
    pub recovery_code: RecoveryCode,
}

#[cfg(test)]
mod tests {
    use super::*;
    use snex_crypto::nullifiers::{PseudonymSecret, OperationSecret, MailboxBaseSecret, RecoveryCode};

    #[test]
    fn test_backup_manager() {
        let account_id = Uuid::new_v4();
        let pseudo_secret = PseudonymSecret::generate();
        let op_secret = OperationSecret::generate();
        let mailbox_base = MailboxBaseSecret([0u8; 32].into());
        let recovery = RecoveryCode::generate();
        let phrase = BackupManager::generate_recovery_phrase();
        
        let backup = BackupManager::create_account_backup(
            account_id,
            &phrase,
            &pseudo_secret,
            &[op_secret],
            &mailbox_base,
            &recovery,
        ).unwrap();
        
        let restored = BackupManager::restore_account_backup(&backup, &phrase).unwrap();
        
        assert_eq!(restored.pseudonym_secret.as_bytes(), pseudo_secret.as_bytes());
    }
}