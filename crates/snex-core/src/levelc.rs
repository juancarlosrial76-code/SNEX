use snex_crypto::encryption::EncryptedData;
use crate::{tenant::TenantRole, error::{CoreError, Result}};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use strum::{EnumString, Display, AsRefStr};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LevelCRoom {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub created_by: Uuid,
    pub rule_set: RoomRuleSet,
    pub mls_group_id: Vec<u8>,
    pub mls_epoch: u64,
    pub members: HashMap<Uuid, RoomMember>,
    pub active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoomRuleSet {
    pub add_permission: PermissionRule,
    pub remove_permission: PermissionRule,
    pub external_join_permission: PermissionRule,
    pub version: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionRule {
    pub allowed_roles: Vec<TenantRole>,
    pub requires_approval: bool,
    pub approval_quorum: u32,
}

impl Default for RoomRuleSet {
    fn default() -> Self {
        Self {
            add_permission: PermissionRule {
                allowed_roles: vec![TenantRole::Owner, TenantRole::Admin],
                requires_approval: true,
                approval_quorum: 2,
            },
            remove_permission: PermissionRule {
                allowed_roles: vec![TenantRole::Owner, TenantRole::Admin],
                requires_approval: false,
                approval_quorum: 1,
            },
            external_join_permission: PermissionRule {
                allowed_roles: vec![TenantRole::Owner],
                requires_approval: true,
                approval_quorum: 2,
            },
            version: 1,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoomMember {
    pub account_id: Uuid,
    pub devices: Vec<MemberDevice>,
    pub added_at: DateTime<Utc>,
    pub added_by: Uuid,
    pub role: RoomRole,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, EnumString, Display, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum RoomRole {
    Member,
    Admin,
    Owner,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberDevice {
    pub device_id: Uuid,
    pub leaf_index: u32,
    pub signature_key: Vec<u8>,
    pub encryption_key: Vec<u8>,
    pub added_at: DateTime<Utc>,
    pub last_sync_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MLSState {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub tree_hash: Vec<u8>,
    pub confirmed_transcript_hash: Vec<u8>,
    pub interim_transcript_hash: Vec<u8>,
    pub extensions: Vec<u8>,
    pub confirmed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceBackup {
    pub account_id: Uuid,
    pub device_id: Uuid,
    pub recovery_phrase_hash: Vec<u8>,
    pub mls_private_keys: EncryptedData,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LevelCConfig {
    pub minors_blocked: bool,
    pub key_package_retention_days: u32,
    pub max_freshness_lag_seconds: u64,
    pub allowed_ciphersuites: Vec<u16>,
    pub require_post_quantum: bool,
}

impl Default for LevelCConfig {
    fn default() -> Self {
        Self {
            minors_blocked: true,
            key_package_retention_days: 90,
            max_freshness_lag_seconds: 3600,
            allowed_ciphersuites: vec![0x0001, 0x0002],
            require_post_quantum: false,
        }
    }
}

impl LevelCRoom {
    pub fn new(tenant_id: Uuid, name: String, description: String, created_by: Uuid, rule_set: RoomRuleSet) -> Self {
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            name,
            description,
            created_at: Utc::now(),
            created_by,
            rule_set,
            mls_group_id: Vec::new(),
            mls_epoch: 0,
            members: HashMap::new(),
            active: true,
        }
    }

    pub fn add_member(&mut self, account_id: Uuid, device: MemberDevice, added_by: Uuid) -> Result<()> {
        if !self.can_add(added_by) {
            return Err(CoreError::PermissionDenied("Cannot add member".into()));
        }
        
        let member = RoomMember {
            account_id,
            devices: vec![device],
            added_at: Utc::now(),
            added_by,
            role: RoomRole::Member,
        };
        
        self.members.insert(account_id, member);
        Ok(())
    }

    pub fn remove_member(&mut self, account_id: Uuid, removed_by: Uuid) -> Result<()> {
        if !self.can_remove(removed_by) {
            return Err(CoreError::PermissionDenied("Cannot remove member".into()));
        }
        
        self.members.remove(&account_id);
        Ok(())
    }

    pub fn add_device(&mut self, account_id: Uuid, device: MemberDevice) -> Result<()> {
        if let Some(member) = self.members.get_mut(&account_id) {
            member.devices.push(device);
            Ok(())
        } else {
            Err(CoreError::NotFound("Member not found".into()))
        }
    }

    pub fn remove_device(&mut self, account_id: Uuid, device_id: Uuid) -> Result<()> {
        if let Some(member) = self.members.get_mut(&account_id) {
            member.devices.retain(|d| d.device_id != device_id);
            Ok(())
        } else {
            Err(CoreError::NotFound("Member not found".into()))
        }
    }

    fn can_add(&self, actor: Uuid) -> bool {
        self.members.get(&actor).map(|m| {
            self.rule_set.add_permission.allowed_roles.contains(&m.role)
        }).unwrap_or(false)
    }

    fn can_remove(&self, actor: Uuid) -> bool {
        self.members.get(&actor).map(|m| {
            self.rule_set.remove_permission.allowed_roles.contains(&m.role)
        }).unwrap_or(false)
    }

    pub fn verify_group_change(&self, proposed_rule_version: u32) -> bool {
        proposed_rule_version == self.rule_set.version
    }

    pub fn update_freshness(&mut self, account_id: Uuid, lag_seconds: u64) -> bool {
        lag_seconds <= self.config().max_freshness_lag_seconds
    }

    fn config(&self) -> LevelCConfig {
        LevelCConfig::default()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryPhraseBackup {
    pub account_id: Uuid,
    pub recovery_phrase_hash: Vec<u8>,
    pub backup_data: EncryptedData,
    pub created_at: DateTime<Utc>,
}

impl RecoveryPhraseBackup {
    pub fn new(account_id: Uuid, recovery_phrase: &str, backup_data: Vec<u8>) -> Result<Self> {
        let salt = b"SNEX Recovery Backup v1";
        let phrase_hash = snex_crypto::kdf::derive_key_argon2id(recovery_phrase.as_bytes(), salt)?;
        
        let dek = snex_crypto::key_hierarchy::Dek::generate();
        let encrypted = dek.encrypt_chacha(&backup_data, salt)?;
        
        Ok(Self {
            account_id,
            recovery_phrase_hash: phrase_hash.to_vec(),
            backup_data: encrypted,
            created_at: Utc::now(),
        })
    }

    pub fn restore(&self, recovery_phrase: &str) -> Result<Vec<u8>> {
        let salt = b"SNEX Recovery Backup v1";
        let phrase_hash = snex_crypto::kdf::derive_key_argon2id(recovery_phrase.as_bytes(), salt)?;
        
        if phrase_hash.as_ref() != self.recovery_phrase_hash.as_slice() {
            return Err(CoreError::InvalidParameter("Invalid recovery phrase".into()));
        }
        
        let dek = snex_crypto::key_hierarchy::Dek::generate();
        let decrypted = dek.decrypt_chacha(&self.backup_data, salt)?;
        
        Ok(decrypted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snex_crypto::nullifiers::OperationSecret;

    #[test]
    fn test_level_c_room() {
        let tenant_id = Uuid::new_v4();
        let mut room = LevelCRoom::new(
            tenant_id,
            "Board Room".into(),
            "Confidential discussions".into(),
            Uuid::new_v4(),
            RoomRuleSet::default(),
        );
        
        assert!(room.active);
        assert_eq!(room.members.len(), 0);
    }

    #[test]
    fn test_recovery_backup() {
        let account_id = Uuid::new_v4();
        let backup = RecoveryPhraseBackup::new(
            account_id,
            "test recovery phrase with many words",
            b"MLS private keys".to_vec(),
        ).unwrap();
        
        let restored = backup.restore("test recovery phrase with many words").unwrap();
        assert_eq!(restored, b"MLS private keys");
    }
}