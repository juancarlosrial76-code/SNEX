use snex_core::{
    voting::{Ballot, Vote, VoteRegister, VoteValue, VoteRelation, VoteTally, Snapshot, MerkleProof},
    epoch::Epoch,
    pseudonym::PseudonymFunction,
    error::{CoreError, Result},
};
use snex_crypto::{
    nullifiers::{Nullifier, OperationSecret, Pseudonym},
    hash::Hash,
};
use snex_registry::service::RegistryService;
use snex_verifier::service::VerifierService;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tracing::{info, warn};

pub struct VotingService {
    registry: Arc<RegistryService>,
    verifier: Arc<VerifierService>,
    config: snex_core::config::AppConfig,
}

impl VotingService {
    pub fn new(
        registry: Arc<RegistryService>,
        verifier: Arc<VerifierService>,
        config: snex_core::config::AppConfig,
    ) -> Self {
        Self { registry, verifier, config }
    }

    pub async fn create_ballot(
        &self,
        tenant_id: Uuid,
        title: String,
        description: String,
        opens_at: DateTime<Utc>,
        closes_at: DateTime<Utc>,
    ) -> Result<Ballot> {
        let epoch = Epoch::current();
        let snapshot = self.verifier.create_snapshot(tenant_id, epoch, None).await?;
        
        let mut ballot = Ballot::new(
            tenant_id,
            title,
            description,
            opens_at,
            closes_at,
            epoch,
            snex_core::voting::BallotTier::Tier1Consultative,
        );
        ballot.snapshot_root = snapshot.merkle_root;
        ballot.snapshot_size = snapshot.leaves.len() as u32;
        
        info!("Ballot created: {} for tenant {}", ballot.id, tenant_id);
        Ok(ballot)
    }

    pub async fn cast_vote(
        &self,
        ballot: &Ballot,
        operation_secret: &OperationSecret,
        vote_value: VoteValue,
        pseudonym: Pseudonym,
        merkle_proof: MerkleProof,
        snapshot_leaf: snex_core::voting::SnapshotLeaf,
    ) -> Result<Vote> {
        if !ballot.is_open() {
            return Err(CoreError::InvalidStateTransition("Ballot not open".into()));
        }
        
        let build_up = self.verifier.check_build_up_mode(ballot.tenant_id, PseudonymFunction::Voting).await;
        if build_up {
            return Err(CoreError::BuildUpMode { reason: "Voting in build-up mode".into() });
        }
        
        let nullifier = operation_secret.derive_vote_nullifier(ballot.id.as_bytes());
        
        let exists = self.registry.check_nullifier(snex_core::registry::NullifierDomain::Vote, &nullifier).await;
        if exists {
            return Err(CoreError::DoubleVote);
        }
        
        let blocked = self.registry.is_blocked(snex_core::registry::NullifierDomain::Vote, &nullifier).await;
        if blocked {
            return Err(CoreError::InvalidStateTransition("Vote nullifier blocked".into()));
        }
        
        let relation = VoteRelation {
            ballot_id: ballot.id,
            snapshot_id: Uuid::nil(),
            pseudonym,
            operation_secret: operation_secret.clone(),
            vote_value,
            merkle_proof,
        };
        
        let vote = Vote::new(
            ballot.id,
            nullifier,
            vote_value,
            pseudonym,
            vec![],
        );
        
        self.registry.register_vote(&vote).await?;
        
        info!("Vote cast for ballot: {}", ballot.id);
        Ok(vote)
    }

    pub async fn finalize_ballot(&self, ballot_id: Uuid) -> Result<VoteTally> {
        self.registry.finalize_vote_register(ballot_id).await?;
        
        let register = self.registry.get_vote_register(ballot_id).await?
            .ok_or(CoreError::NotFound("Vote register not found".into()))?;
        
        let tally = register.tally();
        info!("Ballot {} finalized with tally: {:?}", ballot_id, tally);
        Ok(tally)
    }

    pub async fn get_vote_register(&self, ballot_id: Uuid) -> Result<Option<VoteRegister>> {
        self.registry.get_vote_register(ballot_id).await
    }

    pub async fn verify_snapshot_proof(
        &self,
        snapshot: &Snapshot,
        proof: &MerkleProof,
        leaf: &snex_core::voting::SnapshotLeaf,
    ) -> bool {
        snapshot.verify_proof(proof, leaf)
    }

    pub async fn get_snapshot(&self, snapshot_id: Uuid) -> Result<Option<Snapshot>> {
        self.verifier.get_snapshot(snapshot_id).await
    }

    pub async fn get_anonymity_set(&self, tenant_id: Uuid) -> u32 {
        self.verifier.get_anonymity_set(tenant_id, PseudonymFunction::Voting).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snex_core::config::AppConfig;
    use snex_crypto::nullifiers::{OperationSecret, PseudonymSecret};
    use sqlx::PgPool;

    #[tokio::test]
    async fn test_voting_service() {
        let pool = PgPool::connect("postgresql://localhost/snex_test").await.unwrap();
        let registry_db = snex_registry::database::RegistryDatabase::new(pool.clone());
        let registry = Arc::new(snex_registry::service::RegistryService::new(registry_db));
        
        let verifier_db = snex_verifier::database::VerifierDatabase::new(pool);
        let verifier = Arc::new(snex_verifier::service::VerifierService::new(AppConfig::default(), verifier_db));
        
        let config = AppConfig::default();
        let service = VotingService::new(registry, verifier, config);
        
        let tenant_id = Uuid::new_v4();
        let ballot = service.create_ballot(
            tenant_id,
            "Test Ballot".into(),
            "Description".into(),
            Utc::now() + chrono::Duration::hours(1),
            Utc::now() + chrono::Duration::hours(25),
        ).await.unwrap();
        
        assert!(!ballot.id.is_nil());
    }
}