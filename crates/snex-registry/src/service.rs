use snex_core::{
    voting::{Vote, VoteRegister, VoteValue, Ballot},
    reporting::{Report, Case, Reply, RateLimitWindow, ReportWindowSchedule},
    epoch::Epoch,
    error::{CoreError, Result},
};
use snex_crypto::{
    nullifiers::{Nullifier, CaseHandle, MailboxAccess},
    hashing::Hash,
    encryption::EncryptedData,
};
use crate::state::{RegistryState, SharedRegistryState, NullifierDomain, NullifierEntry, AdmissionJournalEntry, Mailbox, MailboxMessage, MessageDirection, LeaseToken};
use crate::database::RegistryDatabase;
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error};

pub struct RegistryService {
    pub state: SharedRegistryState,
    database: RegistryDatabase,
    instance_id: Uuid,
}

impl RegistryService {
    pub fn new(database: RegistryDatabase) -> Self {
        let state = Arc::new(RwLock::new(RegistryState::new()));
        let instance_id = Uuid::new_v4();
        Self { state, database, instance_id }
    }

    pub async fn initialize(&self) -> Result<()> {
        self.acquire_lease().await?;
        self.start_lease_renewal().await;
        self.start_epoch_rotation().await;
        Ok(())
    }

    async fn acquire_lease(&self) -> Result<()> {
        let mut state = self.state.write().await;
        if !state.acquire_lease(self.instance_id, 30) {
            return Err(CoreError::InvalidStateTransition("Could not acquire lease".into()));
        }
        Ok(())
    }

    async fn start_lease_renewal(&self) {
        let state = self.state.clone();
        let instance_id = self.instance_id;
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));
            loop {
                interval.tick().await;
                let mut state = state.write().await;
                state.renew_lease(instance_id, 30);
            }
        });
    }

    async fn start_epoch_rotation(&self) {
        let state = self.state.clone();
        let database = self.database.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                
                let mut state = state.write().await;
                let current_epoch = Epoch::current();
                
                if current_epoch > state.current_epoch {
                    info!("Registry epoch rotation from {} to {}", state.current_epoch, current_epoch);
                    state.current_epoch = current_epoch;
                    
                    let _ = database.get_admission_journal(current_epoch, None).await;
                }
            }
        });
    }

    pub async fn register_vote(&self, vote: &Vote) -> Result<()> {
        let mut state = self.state.write().await;
        state.register_vote(vote)?;
        
        self.database.store_vote_register(&state.vote_registers.get(&vote.ballot_id).unwrap().clone()).await?;
        Ok(())
    }

    pub async fn get_vote_register(&self, ballot_id: Uuid) -> Result<Option<VoteRegister>> {
        let state = self.state.read().await;
        Ok(state.vote_registers.get(&ballot_id).cloned())
    }

    pub async fn finalize_vote_register(&self, ballot_id: Uuid) -> Result<()> {
        let mut state = self.state.write().await;
        state.finalize_vote_register(ballot_id);
        
        if let Some(register) = state.vote_registers.get(&ballot_id) {
            self.database.store_vote_register(register).await?;
        }
        Ok(())
    }

    pub async fn register_report(&self, report: &Report, case: &Case) -> Result<()> {
        let mut state = self.state.write().await;
        state.register_report(report, case)?;
        
        self.database.store_report(report).await?;
        self.database.store_case(case).await?;
        self.database.store_mailbox(&state.mailboxes.get(&report.case_handle).unwrap().clone()).await?;
        Ok(())
    }

    pub async fn add_reply(&self, case_id: Uuid, reply: &Reply) -> Result<()> {
        let mut state = self.state.write().await;
        state.add_reply(case_id, reply)?;
        
        if let Some(case) = state.cases.get(&case_id) {
            if let Some(mailbox) = state.mailboxes.get(&case.case_handle) {
                self.database.store_mailbox(mailbox).await?;
            }
        }
        Ok(())
    }

    pub async fn get_mailbox(&self, case_handle: &CaseHandle) -> Result<Option<Mailbox>> {
        let state = self.state.read().await;
        Ok(state.get_mailbox(case_handle).cloned())
    }

    pub async fn handover_case(&self, case_id: Uuid, new_officer_key: Vec<u8>) -> Result<()> {
        let mut state = self.state.write().await;
        state.handover_case(case_id, new_officer_key)?;
        
        if let Some(case) = state.cases.get(&case_id) {
            self.database.store_case(case).await?;
        }
        Ok(())
    }

    pub async fn close_case(&self, case_id: Uuid) -> Result<()> {
        let mut state = self.state.write().await;
        state.close_case(case_id)?;
        
        if let Some(case) = state.cases.get(&case_id) {
            self.database.store_case(case).await?;
        }
        Ok(())
    }

    pub async fn add_to_block_list(&self, domain: NullifierDomain, nullifier: Nullifier) {
        let mut state = self.state.write().await;
        state.add_to_block_list(domain, nullifier);
    }

    pub async fn is_blocked(&self, domain: NullifierDomain, nullifier: &Nullifier) -> bool {
        let state = self.state.read().await;
        state.is_blocked(domain, nullifier)
    }

    pub async fn add_termination(&self, tenant_id: Uuid, pseudonym_hash: Hash, epoch: Epoch, lifetime_index: u32) {
        let mut state = self.state.write().await;
        let entry = crate::state::TerminatedEntry {
            pseudonym_hash,
            tenant_id,
            terminated_epoch: epoch,
            lifetime_index,
            terminated_at: Utc::now(),
        };
        state.add_termination(tenant_id, entry.clone());
        self.database.store_termination(tenant_id, &entry).await.unwrap();
    }

    pub async fn is_terminated(&self, tenant_id: Uuid, pseudonym_hash: &Hash) -> bool {
        let state = self.state.read().await;
        state.is_terminated(tenant_id, pseudonym_hash)
    }

    pub async fn check_nullifier(&self, domain: NullifierDomain, nullifier: &Nullifier) -> bool {
        let state = self.state.read().await;
        state.check_nullifier(domain, nullifier)
    }

    pub async fn get_admission_journal(&self, epoch: Epoch, tenant_id: Option<Uuid>) -> Result<Vec<AdmissionJournalEntry>> {
        self.database.get_admission_journal(epoch, tenant_id).await
    }

    pub async fn get_current_lease_token(&self) -> Option<LeaseToken> {
        let state = self.state.read().await;
        state.lease_token.clone()
    }

    pub fn check_fencing_token(&self, token: u64) -> bool {
        let state = self.state.blocking_read();
        state.check_fencing_token(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::PgPool;
    use snex_crypto::nullifiers::OperationSecret;

    #[tokio::test]
    async fn test_registry_service() {
        let pool = PgPool::connect("postgresql://localhost/snex_test").await.unwrap();
        let database = RegistryDatabase::new(pool);
        let service = RegistryService::new(database);
        
        let op_secret = OperationSecret::generate();
        let nullifier = op_secret.derive_vote_nullifier(b"ballot1");
        
        let blocked = service.check_nullifier(NullifierDomain::Vote, &nullifier).await;
        assert!(!blocked);
    }
}