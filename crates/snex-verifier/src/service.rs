use snex_core::{
    pseudonym::{EstablishmentRequest, Batch, EpochConfirmation, PseudonymFunction, PseudonymCounter},
    epoch::Epoch,
    tenant::TenantConfiguration,
    config::AppConfig,
    error::{CoreError, Result},
};
use snex_crypto::{
    bbs::BbsPublicKey,
    nullifiers::{Nullifier, OperationSecret, Pseudonym, PseudonymSecret},
    commitments::Commitment,
    hashing::Hash,
};
use crate::state::{VerifierState, SharedVerifierState, BuildUpModeState};
use crate::database::VerifierDatabase;
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error};

pub struct VerifierService {
    pub state: SharedVerifierState,
    pub database: VerifierDatabase,
    pub config: AppConfig,
}

impl VerifierService {
    pub fn new(config: AppConfig, database: VerifierDatabase) -> Self {
        let state = Arc::new(RwLock::new(VerifierState::new(config.clone())));
        Self { state, database, config }
    }

    pub async fn initialize(&self) -> Result<()> {
        self.start_batch_release_task().await;
        self.start_cleanup_task().await;
        Ok(())
    }

    async fn start_batch_release_task(&self) {
        let state = self.state.clone();
        let database = self.database.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                
                let mut state = state.write().await;
                if let Some(batch) = state.release_batch() {
                    info!("Releasing batch with {} establishments", batch.establishments.len());
                    if let Err(e) = state.activate_registrations(&batch) {
                        error!("Failed to activate registrations: {}", e);
                    }
                    
                    for req in &batch.establishments {
                        if let Err(e) = state.activate_registrations(&batch) {
                            error!("Failed to activate: {}", e);
                        }
                    }
                    
                    if let Err(e) = database.store_batch(&batch).await {
                        error!("Failed to store batch: {}", e);
                    }
                }
            }
        });
    }

    async fn start_cleanup_task(&self) {
        let state = self.state.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                
                let mut state = state.write().await;
                state.batching_buffer.cleanup_expired(Utc::now());
            }
        });
    }

    pub async fn process_establishment(&self, request: EstablishmentRequest) -> Result<()> {
        let mut state = self.state.write().await;
        state.process_establishment(request.clone())?;
        
        let reg = snex_core::pseudonym::PseudonymRegistration::new(
            request.tenant_id,
            crate::state::pseudonym_from_commitment(&request.commitment),
            request.epoch,
            request.lifetime_index,
            request.establishment_nullifier,
            request.pair_tag,
            request.membership_credential.attributes.iter().any(|a| a == b"reporting"),
            request.membership_credential.attributes.iter().any(|a| a == b"voting"),
        );
        
        self.database.store_registration(&reg).await?;
        Ok(())
    }

    pub async fn confirm_epoch(&self, confirmation: EpochConfirmation) -> Result<()> {
        let mut state = self.state.write().await;
        state.confirm_epoch(confirmation.clone())?;
        self.database.store_epoch_confirmation(&confirmation).await?;
        Ok(())
    }

    pub async fn create_snapshot(&self, tenant_id: Uuid, epoch: Epoch, ballot_id: Option<Uuid>) -> Result<snex_core::voting::Snapshot> {
        let mut state = self.state.write().await;
        let snapshot = state.create_snapshot(tenant_id, epoch, ballot_id)?;
        self.database.store_snapshot(&snapshot).await?;
        Ok(snapshot)
    }

    pub async fn get_snapshot(&self, snapshot_id: Uuid) -> Result<Option<snex_core::voting::Snapshot>> {
        self.database.get_snapshot(snapshot_id).await
    }

    pub async fn get_anonymity_set(&self, tenant_id: Uuid, function: PseudonymFunction) -> u32 {
        let state = self.state.read().await;
        state.get_anonymity_set(tenant_id, function)
    }

    pub async fn check_build_up_mode(&self, tenant_id: Uuid, function: PseudonymFunction) -> bool {
        let mut state = self.state.write().await;
        state.check_build_up_mode(tenant_id, function)
    }

    pub async fn terminate_pseudonym(&self, pseudonym: Pseudonym, tenant_id: Uuid) -> Result<()> {
        let mut state = self.state.write().await;
        state.terminate_pseudonym(pseudonym, tenant_id)?;
        
        let terminated = snex_core::pseudonym::TerminatedPseudonym {
            pseudonym_hash: Hash([0u8; 32]),
            tenant_id,
            terminated_epoch: Epoch::current(),
            lifetime_index: 0,
        };
        self.database.store_terminated_pseudonym(&terminated).await?;
        Ok(())
    }

    pub async fn block_pseudonym(&self, pseudonym: Pseudonym, tenant_id: Uuid, reason: String) -> Result<()> {
        let mut state = self.state.write().await;
        state.block_pseudonym(pseudonym, tenant_id, reason)?;
        Ok(())
    }

    pub async fn is_terminated(&self, pseudonym: Pseudonym) -> bool {
        let state = self.state.read().await;
        state.is_terminated(pseudonym)
    }

    pub async fn add_issuer_key(&self, epoch: u64, pk: BbsPublicKey) {
        let mut state = self.state.write().await;
        state.add_issuer_key(epoch, pk);
    }

    pub async fn add_governance_key(&self, tenant_id: Uuid, pk: BbsPublicKey) {
        let mut state = self.state.write().await;
        state.add_governance_key(tenant_id, pk);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snex_core::config::AppConfig;
    use sqlx::PgPool;

    #[tokio::test]
    async fn test_verifier_service() {
        let config = AppConfig::default();
        let pool = PgPool::connect("postgresql://localhost/snex_test").await.unwrap();
        let database = VerifierDatabase::new(pool);
        let service = VerifierService::new(config, database);
        
        let epoch = Epoch::current();
        let snapshot = service.create_snapshot(Uuid::new_v4(), epoch, None).await.unwrap();
        assert!(!snapshot.id.is_nil());
    }
}