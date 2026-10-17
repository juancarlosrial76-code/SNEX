use snex_core::{
    levelc::{LevelCRoom, RoomRuleSet, MemberDevice, LevelCConfig, RecoveryPhraseBackup},
    error::{CoreError, Result},
};
use snex_crypto::kdf::derive_key_argon2id;
use uuid::Uuid;
use chrono::Utc;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;
use openmls::prelude::*;
use openmls::prelude::tls_codec::Deserialize as _;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::signatures::Signer;
use std::collections::HashMap;

/// Serialized output of an MLS commit that the caller must distribute:
/// the commit goes to existing members, the welcome to newly added members.
#[derive(Clone, Debug)]
pub struct MlsCommitOutput {
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
}

fn mls_err(e: impl std::fmt::Display) -> CoreError {
    CoreError::Mls(e.to_string())
}

pub struct LevelCService {
    rooms: Arc<RwLock<HashMap<Uuid, LevelCRoom>>>,
    groups: Arc<RwLock<HashMap<Uuid, MlsGroup>>>,
    device_backups: Arc<RwLock<HashMap<Uuid, snex_core::levelc::DeviceBackup>>>,
    recovery_backups: Arc<RwLock<HashMap<Uuid, RecoveryPhraseBackup>>>,
    config: LevelCConfig,
    provider: OpenMlsRustCrypto,
}

impl LevelCService {
    pub fn new(config: LevelCConfig) -> Self {
        let provider = OpenMlsRustCrypto::default();
        Self {
            rooms: Arc::new(RwLock::new(HashMap::new())),
            groups: Arc::new(RwLock::new(HashMap::new())),
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
    ) -> Result<LevelCRoom> {
        let room = LevelCRoom::new(tenant_id, name, description, created_by, rule_set);
        let mut rooms = self.rooms.write().await;
        rooms.insert(room.id, room.clone());
        info!("Level C room created: {} for tenant {}", room.id, tenant_id);
        Ok(room)
    }

    pub async fn get_room(&self, room_id: Uuid) -> Result<Option<LevelCRoom>> {
        let rooms = self.rooms.read().await;
        Ok(rooms.get(&room_id).cloned())
    }

    pub async fn add_member(
        &self,
        room_id: Uuid,
        account_id: Uuid,
        device: MemberDevice,
        added_by: Uuid,
    ) -> Result<()> {
        let mut rooms = self.rooms.write().await;
        let room = rooms.get_mut(&room_id)
            .ok_or(CoreError::NotFound("Room not found".into()))?;
        room.add_member(account_id, device, added_by)
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
        room.remove_member(account_id, removed_by)
    }

    pub async fn add_device(
        &self,
        room_id: Uuid,
        account_id: Uuid,
        device: MemberDevice,
    ) -> Result<()> {
        let mut rooms = self.rooms.write().await;
        let room = rooms.get_mut(&room_id)
            .ok_or(CoreError::NotFound("Room not found".into()))?;
        room.add_device(account_id, device)
    }

    pub async fn remove_device(
        &self,
        room_id: Uuid,
        account_id: Uuid,
        device_id: Uuid,
    ) -> Result<()> {
        let mut rooms = self.rooms.write().await;
        let room = rooms.get_mut(&room_id)
            .ok_or(CoreError::NotFound("Room not found".into()))?;
        room.remove_device(account_id, device_id)
    }

    /// Creates the MLS group of a room (default config: ciphersuite
    /// MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519). Returns the group id.
    pub async fn create_mls_group(
        &self,
        room_id: Uuid,
        signer: &impl Signer,
        creator_credential: CredentialWithKey,
    ) -> Result<Vec<u8>> {
        let mut rooms = self.rooms.write().await;
        let room = rooms.get_mut(&room_id)
            .ok_or(CoreError::NotFound("Room not found".into()))?;

        let group_config = MlsGroupCreateConfig::default();
        let group = MlsGroup::new(&self.provider, signer, &group_config, creator_credential)
            .map_err(mls_err)?;

        room.mls_group_id = group.group_id().as_slice().to_vec();
        room.mls_epoch = group.epoch().as_u64();
        let group_id = room.mls_group_id.clone();
        self.groups.write().await.insert(room_id, group);

        Ok(group_id)
    }

    /// Adds members (identified by their KeyPackages) and merges the resulting
    /// commit locally. The caller distributes the returned commit/welcome.
    pub async fn add_member_to_mls_group(
        &self,
        room_id: Uuid,
        signer: &impl Signer,
        member_key_packages: &[KeyPackage],
    ) -> Result<MlsCommitOutput> {
        let mut rooms = self.rooms.write().await;
        let room = rooms.get_mut(&room_id)
            .ok_or(CoreError::NotFound("Room not found".into()))?;
        let mut groups = self.groups.write().await;
        let group = groups.get_mut(&room_id)
            .ok_or(CoreError::InvalidStateTransition("MLS group not initialized".into()))?;

        let (commit, welcome, _group_info) = group
            .add_members(&self.provider, signer, member_key_packages)
            .map_err(mls_err)?;
        group.merge_pending_commit(&self.provider).map_err(mls_err)?;
        room.mls_epoch = group.epoch().as_u64();

        Ok(MlsCommitOutput {
            commit: commit.to_bytes().map_err(mls_err)?,
            welcome: Some(welcome.to_bytes().map_err(mls_err)?),
        })
    }

    pub async fn remove_member_from_mls_group(
        &self,
        room_id: Uuid,
        signer: &impl Signer,
        leaf_index: u32,
    ) -> Result<MlsCommitOutput> {
        let mut rooms = self.rooms.write().await;
        let room = rooms.get_mut(&room_id)
            .ok_or(CoreError::NotFound("Room not found".into()))?;
        let mut groups = self.groups.write().await;
        let group = groups.get_mut(&room_id)
            .ok_or(CoreError::InvalidStateTransition("MLS group not initialized".into()))?;

        let (commit, welcome, _group_info) = group
            .remove_members(&self.provider, signer, &[LeafNodeIndex::new(leaf_index)])
            .map_err(mls_err)?;
        group.merge_pending_commit(&self.provider).map_err(mls_err)?;
        room.mls_epoch = group.epoch().as_u64();

        Ok(MlsCommitOutput {
            commit: commit.to_bytes().map_err(mls_err)?,
            welcome: match welcome {
                Some(w) => Some(w.to_bytes().map_err(mls_err)?),
                None => None,
            },
        })
    }

    pub async fn encrypt_message(
        &self,
        room_id: Uuid,
        signer: &impl Signer,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let mut groups = self.groups.write().await;
        let group = groups.get_mut(&room_id)
            .ok_or(CoreError::InvalidStateTransition("MLS group not initialized".into()))?;

        let message = group
            .create_message(&self.provider, signer, plaintext)
            .map_err(mls_err)?;
        message.to_bytes().map_err(mls_err)
    }

    pub async fn decrypt_message(
        &self,
        room_id: Uuid,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let mut groups = self.groups.write().await;
        let group = groups.get_mut(&room_id)
            .ok_or(CoreError::InvalidStateTransition("MLS group not initialized".into()))?;

        let mls_message = MlsMessageIn::tls_deserialize_exact(ciphertext).map_err(mls_err)?;
        let protocol_message = mls_message.try_into_protocol_message().map_err(mls_err)?;
        let processed = group
            .process_message(&self.provider, protocol_message)
            .map_err(mls_err)?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => Ok(app.into_bytes()),
            _ => Err(CoreError::InvalidParameter("Not an application message".into())),
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
        
        if phrase_hash.as_slice() != backup.recovery_phrase_hash.as_slice() {
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
        let groups = self.groups.read().await;
        // Check if the group state is fresh enough
        if let Some(group) = groups.get(&room_id) {
            let epoch = group.epoch().as_u64();
            // In real implementation, check against max_freshness_lag_seconds
            epoch > 0
        } else {
            false
        }
    }
}
