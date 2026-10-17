use snex_core::{
    levelc::{LevelCRoom, RoomRuleSet, RoomRole, MemberDevice, LevelCConfig, RecoveryPhraseBackup, MLSGroupState},
    tenant::TenantRole,
    error::{CoreError, Result},
};
use snex_crypto::{
    encryption::{X25519KeyPair, Ed25519KeyPair, EncryptedData},
    nullifiers::CaseHandle,
    kdf::derive_key_argon2id,
};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{OpenMlsProvider, random::OpenMlsRand, crypto::OpenMlsCrypto, types::HpkeKeyPair};
use std::collections::HashMap;

pub struct LevelCService {
    rooms: Arc<RwLock<HashMap<Uuid, MLSRoom>>>,
    device_backups: Arc<RwLock<HashMap<Uuid, snex_core::levelc::DeviceBackup>>>,
    recovery_backups: Arc<RwLock<HashMap<Uuid, RecoveryPhraseBackup>>>,
    config: LevelCConfig,
    provider: OpenMlsRustCrypto,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MLSRoom {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub created_by: Uuid,
    pub rule_set: RoomRuleSet,
    pub mls_group_id: Vec<u8>,
    pub mls_epoch: u64,
    pub members: HashMap<Uuid, MLSMember>,
    pub active: bool,
    pub group: Option<MlsGroup>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MLSMember {
    pub account_id: Uuid,
    pub credential: Credential,
    pub key_package: KeyPackage,
    pub added_at: DateTime<Utc>,
    pub added_by: Uuid,
    pub role: RoomRole,
    pub leaf_index: u32,
}

impl MLSRoom {
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
            group: None,
        }
    }

    pub fn add_member(&mut self, account_id: Uuid, member: MLSMember, added_by: Uuid) -> Result<()> {
        if !self.can_add(added_by) {
            return Err(CoreError::PermissionDenied("Cannot add member".into()));
        }
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
}

impl LevelCService {
    pub fn new(config: LevelCConfig) -> Self {
        let provider = OpenMlsRustCrypto::default();
        Self {
            rooms: Arc::new(RwLock::new(HashMap::new())),
            device_backups: Arc::new(RwLock::new(HashMap::new())),
            recovery_backups: Arc::new(RwLock::new(HashMap::new())),
            config,
            provider,
        }
    }

    pub async fn create_room(
        &self,
        tenant_id: Uuid,
        name: String,
        description: String,
        created_by: Uuid,
        rule_set: RoomRuleSet,
    ) -> Result<MLSRoom> {
        let room = MLSRoom::new(tenant_id, name, description, created_by, rule_set);
        let mut rooms = self.rooms.write().await;
        rooms.insert(room.id, room.clone());
        info!("Level C room created: {} for tenant {}", room.id, tenant_id);
        Ok(room)
    }

    pub async fn get_room(&self, room_id: Uuid) -> Result<Option<MLSRoom>> {
        let rooms = self.rooms.read().await;
        Ok(rooms.get(&room_id).cloned())
    }

    pub async fn add_member(
        &self,
        room_id: Uuid,
        account_id: Uuid,
        member: MLSMember,
        added_by: Uuid,
    ) -> Result<()> {
        let mut rooms = self.rooms.write().await;
        let room = rooms.get_mut(&room_id)
            .ok_or(CoreError::NotFound("Room not found".into()))?;
        
        room.add_member(account_id, member, added_by)?;
        Ok(())
    }

    pub async fn remove_member(
        &self,
        room_id: Uuid,
        account_id: Uuid,
        removed_by: Uuid,
    ) -> Result<()> {
        let mut rooms = self.rooms.write().await;
        let room = rooms.get_mut(&room_id)
            .ok_or(CoreError::NotFound("Room not found".into()))?;
        
        room.remove_member(account_id, removed_by)?;
        Ok(())
    }

    pub async fn create_mls_group(
        &self,
        room_id: Uuid,
        creator_account_id: Uuid,
        creator_credential: Credential,
        creator_key_package: KeyPackage,
    ) -> Result<MlsGroup> {
        let mut rooms = self.rooms.write().await;
        let room = rooms.get_mut(&room_id)
            .ok_or(CoreError::NotFound("Room not found".into()))?;
        
        let group_config = MlsGroupConfig::default();
        let mut group = MlsGroup::new(
            &self.provider,
            &group_config,
            creator_credential,
            creator_key_package,
        )?;
        
        room.group = Some(group.clone());
        room.mls_group_id = group.group_id().as_slice().to_vec();
        room.mls_epoch = group.epoch().as_u64();
        
        Ok(group)
    }

    pub async fn add_member_to_mls_group(
        &self,
        room_id: Uuid,
        member_credential: Credential,
        member_key_package: KeyPackage,
    ) -> Result<()> {
        let mut rooms = self.rooms.write().await;
        let room = rooms.get_mut(&room_id)
            .ok_or(CoreError::NotFound("Room not found".into()))?;
        
        if let Some(group) = &mut room.group {
            let (_message, _welcome, _group_info) = group.add_members(
                &self.provider,
                &[member_credential],
                &[member_key_package],
            )?;
            room.mls_epoch = group.epoch().as_u64();
        }
        Ok(())
    }

    pub async fn remove_member_from_mls_group(
        &self,
        room_id: Uuid,
        removed_by: Uuid,
        leaf_index: u32,
    ) -> Result<()> {
        let mut rooms = self.rooms.write().await;
        let room = rooms.get_mut(&room_id)
            .ok_or(CoreError::NotFound("Room not found".into()))?;
        
        if let Some(group) = &mut room.group {
            let _message = group.remove_member(&self.provider, removed_by, leaf_index)?;
            room.mls_epoch = group.epoch().as_u64();
        }
        Ok(())
    }

    pub async fn encrypt_message(
        &self,
        room_id: Uuid,
        sender_account_id: Uuid,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let mut rooms = self.rooms.write().await;
        let room = rooms.get_mut(&room_id)
            .ok_or(CoreError::NotFound("Room not found".into()))?;
        
        if let Some(group) = &mut room.group {
            let message = group.create_message(&self.provider, plaintext, Credential::basic(vec![]))?;
            Ok(message.to_bytes()?)
        } else {
            Err(CoreError::InvalidStateTransition("MLS group not initialized".into()))
        }
    }

    pub async fn decrypt_message(
        &self,
        room_id: Uuid,
        receiver_account_id: Uuid,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let mut rooms = self.rooms.write().await;
        let room = rooms.get_mut(&room_id)
            .ok_or(CoreError::NotFound("Room not found".into()))?;
        
        if let Some(group) = &mut room.group {
            let mls_message = MlsMessageIn::from_bytes(ciphertext)?;
            let decrypted = group.decrypt_message(&self.provider, mls_message)?;
            Ok(decrypted.to_vec())
        } else {
            Err(CoreError::InvalidStateTransition("MLS group not initialized".into()))
        }
    }

    pub async fn create_device_backup(
        &self,
        account_id: Uuid,
        device_id: Uuid,
        recovery_phrase: &str,
        mls_private_keys: Vec<u8>,
    ) -> Result<()> {
        let salt = b"SNEX MLS Backup v1";
        let phrase_hash = derive_key_argon2id(recovery_phrase.as_bytes(), salt)?;
        
        let dek = snex_crypto::key_hierarchy::Dek::generate();
        let encrypted = dek.encrypt_chacha(&mls_private_keys, salt)?;
        
        let backup = snex_core::levelc::DeviceBackup {
            account_id,
            device_id,
            recovery_phrase_hash: phrase_hash.to_vec(),
            mls_private_keys: encrypted,
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::days(self.config.key_package_retention_days as i64)),
        };
        
        let mut backups = self.device_backups.write().await;
        backups.insert(device_id, backup);
        Ok(())
    }

    pub async fn restore_device_backup(
        &self,
        device_id: Uuid,
        recovery_phrase: &str,
    ) -> Result<Vec<u8>> {
        let backups = self.device_backups.read().await;
        let backup = backups.get(&device_id)
            .ok_or(CoreError::NotFound("Backup not found".into()))?;
        
        let salt = b"SNEX MLS Backup v1";
        let phrase_hash = derive_key_argon2id(recovery_phrase.as_bytes(), salt)?;
        
        if phrase_hash.as_ref() != backup.recovery_phrase_hash.as_slice() {
            return Err(CoreError::InvalidParameter("Invalid recovery phrase".into()));
        }
        
        let dek = snex_crypto::key_hierarchy::Dek::generate();
        let decrypted = dek.decrypt_chacha(&backup.mls_private_keys, salt)?;
        
        Ok(decrypted)
    }

    pub async fn create_recovery_backup(
        &self,
        account_id: Uuid,
        recovery_phrase: &str,
        backup_data: Vec<u8>,
    ) -> Result<()> {
        let backup = RecoveryPhraseBackup::new(account_id, recovery_phrase, backup_data)?;
        let mut backups = self.recovery_backups.write().await;
        backups.insert(account_id, backup);
        Ok(())
    }

    pub async fn restore_recovery_backup(
        &self,
        account_id: Uuid,
        recovery_phrase: &str,
    ) -> Result<Vec<u8>> {
        let backups = self.recovery_backups.read().await;
        let backup = backups.get(&account_id)
            .ok_or(CoreError::NotFound("Recovery backup not found".into()))?;
        
        backup.restore(recovery_phrase)
    }

    pub async fn verify_group_change(&self, room_id: Uuid, proposed_rule_version: u32) -> bool {
        let rooms = self.rooms.read().await;
        if let Some(room) = rooms.get(&room_id) {
            room.verify_group_change(proposed_rule_version)
        } else {
            false
        }
    }

    pub async fn update_freshness(&self, room_id: Uuid, account_id: Uuid, lag_seconds: u64) -> bool {
        let rooms = self.rooms.read().await;
        if let Some(room) = rooms.get(&room_id) {
            // Check if the group state is fresh enough
            if let Some(group) = &room.group {
                let epoch = group.epoch().as_u64();
                // In real implementation, check against max_freshness_lag_seconds
                epoch > 0
            } else {
                false
            }
        } else {
            false
        }
    }
}

use std::collections::HashMap;