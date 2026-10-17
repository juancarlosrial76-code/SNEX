use snex_crypto::{
    key_hierarchy::{KeyHierarchy, KeyMetadata, KeyType, RetentionClass, Dek, EncryptedData, MasterKey, BackupWrappingKey, PqWrappingKey, WrappedDek},
    hashing::Hash,
};
use crate::{anchoring::AuditChain, error::{CoreError, Result}};
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use serde::{Serialize, Deserialize};
use strum::{EnumString, Display, AsRefStr};
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, EnumString, Display, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum DeletionState {
    Active,
    RemovedFromApplication,
    PendingDeletion,
    Destroyed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub class: RetentionClass,
    pub retention_period_days: u32,
    pub backup_regime: BackupRegime,
    pub legal_hold_exempt: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, EnumString, Display, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum BackupRegime {
    Regime1,
    Regime2,
}

impl RetentionPolicy {
    pub fn default_for_class(class: RetentionClass) -> Self {
        match class {
            RetentionClass::RA | RetentionClass::RM | RetentionClass::RE | RetentionClass::RI => Self {
                class,
                retention_period_days: 14,
                backup_regime: BackupRegime::Regime1,
                legal_hold_exempt: false,
            },
            RetentionClass::RC => Self {
                class,
                retention_period_days: 0,
                backup_regime: BackupRegime::Regime1,
                legal_hold_exempt: true,
            },
            RetentionClass::RV => Self {
                class,
                retention_period_days: 30,
                backup_regime: BackupRegime::Regime2,
                legal_hold_exempt: false,
            },
            RetentionClass::RP | RetentionClass::RB => Self {
                class,
                retention_period_days: 56,
                backup_regime: BackupRegime::Regime2,
                legal_hold_exempt: true,
            },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RetentionRecord {
    pub id: Uuid,
    pub data_id: String,
    pub retention_class: RetentionClass,
    pub tenant_id: Option<Uuid>,
    pub person_key_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub destruction_deadline: Option<DateTime<Utc>>,
    pub state: DeletionState,
    pub legal_holds: Vec<LegalHold>,
    pub backup_generations: Vec<BackupGeneration>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LegalHold {
    pub id: Uuid,
    pub reason: String,
    pub placed_at: DateTime<Utc>,
    pub placed_by: String,
    pub review_interval_days: u32,
    pub expires_at: Option<DateTime<Utc>>,
    pub active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackupGeneration {
    pub generation: u64,
    pub regime: BackupRegime,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub wrapped_deks: Vec<WrappedDek>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeletionJournalEntry {
    pub id: Uuid,
    pub data_id: String,
    pub retention_class: RetentionClass,
    pub tenant_id: Option<Uuid>,
    pub person_key_id: Option<String>,
    pub destroyed_at: DateTime<Utc>,
    pub destroyed_by: String,
    pub key_material_hash: Hash,
    pub backup_generations_affected: Vec<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RetentionEngine {
    #[serde(skip)]
    pub key_hierarchy: KeyHierarchy,
    pub records: HashMap<String, RetentionRecord>,
    pub deletion_journal: Vec<DeletionJournalEntry>,
    pub audit_chain: AuditChain,
    pub volume_threshold: u32,
    pub pending_approvals: HashMap<Uuid, PendingDestruction>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingDestruction {
    pub id: Uuid,
    pub data_id: String,
    pub requested_at: DateTime<Utc>,
    pub requested_by: String,
    pub volume: u64,
    pub approved: bool,
    pub approved_at: Option<DateTime<Utc>>,
    pub approved_by: Option<String>,
}

impl RetentionEngine {
    pub fn new(master_key: MasterKey, volume_threshold: u32) -> Self {
        Self {
            key_hierarchy: KeyHierarchy::new(master_key),
            records: HashMap::new(),
            deletion_journal: Vec::new(),
            audit_chain: AuditChain::new(),
            volume_threshold,
            pending_approvals: HashMap::new(),
        }
    }

    pub fn register_data(
        &mut self,
        data_id: String,
        retention_class: RetentionClass,
        tenant_id: Option<Uuid>,
        person_key_id: Option<String>,
    ) -> Result<()> {
        let policy = RetentionPolicy::default_for_class(retention_class);
        let now = Utc::now();
        let destruction_deadline = if policy.retention_period_days > 0 {
            Some(now + Duration::days(policy.retention_period_days as i64))
        } else {
            None
        };

        let record = RetentionRecord {
            id: Uuid::new_v4(),
            data_id: data_id.clone(),
            retention_class,
            tenant_id,
            person_key_id,
            created_at: now,
            deleted_at: None,
            destruction_deadline,
            state: DeletionState::Active,
            legal_holds: Vec::new(),
            backup_generations: Vec::new(),
        };

        self.records.insert(data_id, record);
        Ok(())
    }

    pub fn request_deletion(
        &mut self,
        data_id: &str,
        requested_by: String,
        volume: u64,
    ) -> Result<()> {
        let record = self.records.get_mut(data_id)
            .ok_or_else(|| CoreError::NotFound(format!("Data not found: {}", data_id)))?;

        if record.state != DeletionState::Active {
            return Err(CoreError::InvalidStateTransition("Data not in active state".into()));
        }

        if !record.legal_holds.iter().any(|h| h.active) {
            return Err(CoreError::InvalidStateTransition("Legal hold active".into()));
        }

        record.state = DeletionState::RemovedFromApplication;
        record.deleted_at = Some(Utc::now());

        if volume > self.volume_threshold as u64 {
            let pending = PendingDestruction {
                id: Uuid::new_v4(),
                data_id: data_id.to_string(),
                requested_at: Utc::now(),
                requested_by,
                volume,
                approved: false,
                approved_at: None,
                approved_by: None,
            };
            self.pending_approvals.insert(pending.id, pending);
        } else {
            self.execute_destruction(data_id, requested_by)?;
        }

        Ok(())
    }

    pub fn approve_destruction(&mut self, pending_id: Uuid, approved_by: String) -> Result<()> {
        let pending = self.pending_approvals.get_mut(&pending_id)
            .ok_or_else(|| CoreError::NotFound("Pending destruction not found".into()))?;

        if pending.approved {
            return Err(CoreError::InvalidStateTransition("Already approved".into()));
        }

        pending.approved = true;
        pending.approved_at = Some(Utc::now());
        pending.approved_by = Some(approved_by.clone());

        let data_id = pending.data_id.clone();
        self.execute_destruction(&data_id, approved_by)?;
        self.pending_approvals.remove(&pending_id);

        Ok(())
    }

    fn execute_destruction(&mut self, data_id: &str, destroyed_by: String) -> Result<()> {
        let record = self.records.get_mut(data_id)
            .ok_or_else(|| CoreError::NotFound(format!("Data not found: {}", data_id)))?;

        if let Some(person_key_id) = &record.person_key_id {
            let _ = self.key_hierarchy.get_or_create_dek("master", person_key_id);
        }

        record.state = DeletionState::Destroyed;
        record.destruction_deadline = None;

        let journal_entry = DeletionJournalEntry {
            id: Uuid::new_v4(),
            data_id: data_id.to_string(),
            retention_class: record.retention_class,
            tenant_id: record.tenant_id,
            person_key_id: record.person_key_id.clone(),
            destroyed_at: Utc::now(),
            destroyed_by,
            key_material_hash: Hash([0u8; 32]),
            backup_generations_affected: record.backup_generations.iter().map(|g| g.generation).collect(),
        };

        self.deletion_journal.push(journal_entry);
        self.audit_chain.append(
            "retention".into(),
            "destruction".into(),
            serde_json::json!({"data_id": data_id}),
            record.tenant_id,
            None,
        )?;

        Ok(())
    }

    pub fn check_legal_hold(&self, data_id: &str) -> Result<bool> {
        let record = self.records.get(data_id)
            .ok_or_else(|| CoreError::NotFound(format!("Data not found: {}", data_id)))?;
        Ok(record.legal_holds.iter().any(|h| h.active))
    }

    pub fn place_legal_hold(
        &mut self,
        data_id: &str,
        reason: String,
        placed_by: String,
        review_interval_days: u32,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        let record = self.records.get_mut(data_id)
            .ok_or_else(|| CoreError::NotFound(format!("Data not found: {}", data_id)))?;

        let hold = LegalHold {
            id: Uuid::new_v4(),
            reason,
            placed_at: Utc::now(),
            placed_by,
            review_interval_days,
            expires_at,
            active: true,
        };

        record.legal_holds.push(hold);
        Ok(())
    }

    pub fn lift_legal_hold(&mut self, data_id: &str, hold_id: Uuid) -> Result<()> {
        let record = self.records.get_mut(data_id)
            .ok_or_else(|| CoreError::NotFound(format!("Data not found: {}", data_id)))?;

        if let Some(hold) = record.legal_holds.iter_mut().find(|h| h.id == hold_id) {
            hold.active = false;
        }

        Ok(())
    }

    pub fn process_backup_expiry(&mut self, current_generation: u64) {
        for record in self.records.values_mut() {
            record.backup_generations.retain(|g| g.generation > current_generation);
            
            if record.state == DeletionState::PendingDeletion && record.backup_generations.is_empty() {
                record.state = DeletionState::Destroyed;
                let journal_entry = DeletionJournalEntry {
                    id: Uuid::new_v4(),
                    data_id: record.data_id.clone(),
                    retention_class: record.retention_class,
                    tenant_id: record.tenant_id,
                    person_key_id: record.person_key_id.clone(),
                    destroyed_at: Utc::now(),
                    destroyed_by: "backup_expiry".into(),
                    key_material_hash: Hash([0u8; 32]),
                    backup_generations_affected: vec![],
                };
                self.deletion_journal.push(journal_entry);
            }
        }
    }

    pub fn recover(&mut self, backup_generation: u64) -> Result<()> {
        for record in self.records.values_mut() {
            if record.state == DeletionState::Destroyed {
                if record.backup_generations.iter().any(|g| g.generation <= backup_generation) {
                    record.state = DeletionState::Active;
                    record.deleted_at = None;
                    record.destruction_deadline = Some(Utc::now() + Duration::days(30));
                }
            }
        }
        
        for entry in &self.deletion_journal {
            if entry.backup_generations_affected.iter().any(|&g| g <= backup_generation) {
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retention_policies() {
        let policy = RetentionPolicy::default_for_class(RetentionClass::RA);
        assert_eq!(policy.backup_regime, BackupRegime::Regime1);
        assert_eq!(policy.retention_period_days, 14);
    }

    #[test]
    fn test_retention_engine() {
        let master = MasterKey::generate();
        let mut engine = RetentionEngine::new(master, 1000);
        
        engine.register_data("user123".into(), RetentionClass::RA, Some(Uuid::new_v4()), Some("person_key_1".into())).unwrap();
        
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
}