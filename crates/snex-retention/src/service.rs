use snex_core::{
    retention::{RetentionEngine, RetentionRecord, LegalHold, BackupGeneration, DeletionJournalEntry, BackupRegime, PendingDestruction, RetentionPolicy},
    error::{CoreError, Result},
};
use snex_crypto::{
    key_hierarchy::{MasterKey, KeyHierarchy, KeyMetadata, KeyType},
    hashing::Hash,
    RetentionClass,
};
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

pub struct RetentionService {
    engine: Arc<RwLock<RetentionEngine>>,
    config: snex_core::config::RetentionConfig,
}

impl RetentionService {
    pub fn new(master_key: MasterKey, config: snex_core::config::RetentionConfig) -> Self {
        let engine = Arc::new(RwLock::new(RetentionEngine::new(master_key, config.volume_threshold)));
        Self { engine, config }
    }

    pub async fn register_data(
        &self,
        data_id: String,
        retention_class: RetentionClass,
        tenant_id: Option<Uuid>,
        person_key_id: Option<String>,
    ) -> Result<()> {
        let mut engine = self.engine.write().await;
        engine.register_data(data_id, retention_class, tenant_id, person_key_id)
    }

    pub async fn request_deletion(
        &self,
        data_id: &str,
        requested_by: String,
        volume: u64,
    ) -> Result<()> {
        let mut engine = self.engine.write().await;
        engine.request_deletion(data_id, requested_by, volume)
    }

    pub async fn approve_destruction(
        &self,
        pending_id: Uuid,
        approved_by: String,
    ) -> Result<()> {
        let mut engine = self.engine.write().await;
        engine.approve_destruction(pending_id, approved_by)
    }

    pub async fn place_legal_hold(
        &self,
        data_id: &str,
        reason: String,
        placed_by: String,
        review_interval_days: u32,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        let mut engine = self.engine.write().await;
        engine.place_legal_hold(data_id, reason, placed_by, review_interval_days, expires_at)
    }

    pub async fn lift_legal_hold(
        &self,
        data_id: &str,
        hold_id: Uuid,
    ) -> Result<()> {
        let mut engine = self.engine.write().await;
        engine.lift_legal_hold(data_id, hold_id)
    }

    pub async fn check_legal_hold(&self, data_id: &str) -> Result<bool> {
        let engine = self.engine.read().await;
        engine.check_legal_hold(data_id)
    }

    pub async fn process_backup_expiry(&self, current_generation: u64) {
        let mut engine = self.engine.write().await;
        engine.process_backup_expiry(current_generation);
    }

    pub async fn recover(&self, backup_generation: u64) -> Result<()> {
        let mut engine = self.engine.write().await;
        engine.recover(backup_generation)
    }

    pub async fn get_record(&self, data_id: &str) -> Option<RetentionRecord> {
        let engine = self.engine.read().await;
        engine.records.get(data_id).cloned()
    }

    pub async fn get_deletion_journal(&self) -> Vec<DeletionJournalEntry> {
        let engine = self.engine.read().await;
        engine.deletion_journal.clone()
    }

    pub async fn start_backup_expiry_task(&self) {
        let engine = self.engine.clone();
        let regime1_interval = chrono::Duration::hours(self.config.regime1_generation_interval_hours as i64);
        let regime2_interval = chrono::Duration::hours(self.config.regime2_generation_interval_hours as i64);
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
            let mut current_gen = 0;
            loop {
                interval.tick().await;
                current_gen += 1;
                let mut engine = engine.write().await;
                engine.process_backup_expiry(current_gen);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snex_core::config::AppConfig;
    use snex_crypto::key_hierarchy::MasterKey;

    #[tokio::test]
    async fn test_retention_service() {
        let master_key = MasterKey::generate();
        let config = AppConfig::default().retention;
        let service = RetentionService::new(master_key, config);
        
        service.register_data(
            "user123".into(),
            snex_crypto::RetentionClass::RA,
            Some(Uuid::new_v4()),
            Some("person_key_1".into()),
        ).await.unwrap();
        
        let record = service.get_record("user123").await.unwrap();
        assert_eq!(record.retention_class, snex_crypto::RetentionClass::RA);
    }
}