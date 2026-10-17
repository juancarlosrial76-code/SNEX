use snex_crypto::{
    nullifiers::{Pseudonym, PseudonymSecret, OperationSecret, Nullifier, CaseHandle, MailboxBaseSecret},
    commitments::{CommitmentKey, Commitment},
    bbs::{BbsCredential, BbsPublicKey},
};
use crate::{tenant::TenantRole, epoch::Epoch, error::{CoreError, Result}};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use strum::{EnumString, Display, AsRefStr};
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, EnumString, Display, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum PseudonymState {
    Provisional,
    Active,
    Blocked,
    Terminated,
    Expired,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PseudonymRegistration {
    pub id: Uuid,
    pub pseudonym: Pseudonym,
    pub tenant_id: Uuid,
    pub epoch: Epoch,
    pub lifetime_index: u32,
    pub state: PseudonymState,
    pub established_at: DateTime<Utc>,
    pub activated_at: Option<DateTime<Utc>>,
    pub blocked_at: Option<DateTime<Utc>>,
    pub terminated_at: Option<DateTime<Utc>>,
    pub block_reason: Option<String>,
    pub establishment_nullifier: Nullifier,
    pub pair_tag: Nullifier,
    pub reporting_authorised: bool,
    pub voting_authorised: bool,
    pub epoch_confirmed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EstablishmentRequest {
    pub tenant_id: Uuid,
    pub person_credential: BbsCredential,
    pub membership_credential: BbsCredential,
    pub commitment: Commitment,
    pub commitment_key: CommitmentKey,
    pub establishment_nullifier: Nullifier,
    pub pair_tag: Nullifier,
    pub epoch: Epoch,
    pub lifetime_index: u32,
    pub zero_knowledge_proof: Vec<u8>,
    pub received_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Batch {
    pub id: Uuid,
    pub establishments: Vec<EstablishmentRequest>,
    pub created_at: DateTime<Utc>,
    pub released_at: Option<DateTime<Utc>>,
    pub release_threshold: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchingBuffer {
    pub pending: HashMap<String, EstablishmentRequest>,
    pub min_batch_size: u32,
    pub max_batch_size: u32,
    pub max_establishment_period_hours: u32,
    pub max_failed_attempts: u32,
}

impl BatchingBuffer {
    pub fn new(min_batch_size: u32, max_batch_size: u32, max_period_hours: u32, max_attempts: u32) -> Self {
        Self {
            pending: HashMap::new(),
            min_batch_size,
            max_batch_size,
            max_establishment_period_hours: max_period_hours,
            max_failed_attempts: max_attempts,
        }
    }

    pub fn add(&mut self, request: EstablishmentRequest) -> Result<()> {
        if self.pending.len() >= self.max_batch_size as usize {
            return Err(CoreError::InvalidStateTransition("Buffer full".into()));
        }
        self.pending.insert(request.establishment_nullifier.to_hex().into(), request);
        Ok(())
    }

    pub fn can_release(&self) -> bool {
        self.pending.len() >= self.min_batch_size as usize
    }

    pub fn should_release(&self, threshold: u32) -> bool {
        self.pending.len() >= threshold as usize
    }

    pub fn release(&mut self, threshold: u32) -> Option<Batch> {
        if !self.should_release(threshold) {
            return None;
        }
        let establishments: Vec<_> = self.pending.drain().map(|(_, v)| v).collect();
        Some(Batch {
            id: Uuid::new_v4(),
            establishments,
            created_at: Utc::now(),
            released_at: Some(Utc::now()),
            release_threshold: threshold,
        })
    }

    pub fn cleanup_expired(&mut self, now: DateTime<Utc>) {
        self.pending.retain(|_, req| {
            let elapsed = now.signed_duration_since(req.received_at).num_hours();
            elapsed < self.max_establishment_period_hours as i64
        });
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochConfirmation {
    pub pseudonym: Pseudonym,
    pub tenant_id: Uuid,
    pub epoch: Epoch,
    pub person_credential: BbsCredential,
    pub membership_credential: BbsCredential,
    pub zero_knowledge_proof: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PseudonymCounter {
    pub tenant_id: Uuid,
    pub epoch: Epoch,
    pub function: PseudonymFunction,
    pub count: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, EnumString, Display, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum PseudonymFunction {
    Reporting,
    Voting,
}

impl PseudonymRegistration {
    pub fn new(
        tenant_id: Uuid,
        pseudonym: Pseudonym,
        epoch: Epoch,
        lifetime_index: u32,
        establishment_nullifier: Nullifier,
        pair_tag: Nullifier,
        reporting_authorised: bool,
        voting_authorised: bool,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            pseudonym,
            tenant_id,
            epoch,
            lifetime_index,
            state: PseudonymState::Provisional,
            established_at: Utc::now(),
            activated_at: None,
            blocked_at: None,
            terminated_at: None,
            block_reason: None,
            establishment_nullifier,
            pair_tag,
            reporting_authorised,
            voting_authorised,
            epoch_confirmed: false,
        }
    }

    pub fn activate(&mut self) {
        self.state = PseudonymState::Active;
        self.activated_at = Some(Utc::now());
    }

    pub fn block(&mut self, reason: String) {
        self.state = PseudonymState::Blocked;
        self.blocked_at = Some(Utc::now());
        self.block_reason = Some(reason);
    }

    pub fn terminate(&mut self) {
        self.state = PseudonymState::Terminated;
        self.terminated_at = Some(Utc::now());
    }

    pub fn confirm_epoch(&mut self) {
        self.epoch_confirmed = true;
    }

    pub fn is_active(&self) -> bool {
        self.state == PseudonymState::Active && self.epoch_confirmed
    }

    pub fn authorises(&self, function: PseudonymFunction) -> bool {
        match function {
            PseudonymFunction::Reporting => self.reporting_authorised,
            PseudonymFunction::Voting => self.voting_authorised,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TerminatedPseudonym {
    pub pseudonym_hash: Hash,
    pub tenant_id: Uuid,
    pub terminated_epoch: Epoch,
    pub lifetime_index: u32,
}

impl TerminatedPseudonym {
    pub fn from_registration(reg: &PseudonymRegistration) -> Self {
        use snex_crypto::hashing::DOMAIN_COMMITMENT;
        let hash = snex_crypto::Hash::with_domain(DOMAIN_COMMITMENT, reg.pseudonym.as_bytes());
        Self {
            pseudonym_hash: hash,
            tenant_id: reg.tenant_id,
            terminated_epoch: reg.epoch,
            lifetime_index: reg.lifetime_index,
        }
    }
}

use snex_crypto::hashing::Hash;

#[cfg(test)]
mod tests {
    use super::*;
    use snex_crypto::nullifiers::{PseudonymSecret, OperationSecret};

    #[test]
    fn test_batching_buffer() {
        let mut buffer = BatchingBuffer::new(3, 10, 72, 2);
        assert!(!buffer.can_release());
        
        for i in 0..3 {
            let op_secret = OperationSecret::generate();
            let req = EstablishmentRequest {
                tenant_id: Uuid::new_v4(),
                person_credential: BbsCredential {
                    schema_id: "test".into(),
                    issuer: BbsPublicKey { key: vec![0u8; 96] },
                    subject: vec![],
                    attributes: vec![],
                    signature: snex_crypto::bbs::BbsSignature { signature: vec![0u8; 112] },
                    epoch: 1,
                    issued_at: 0,
                    expires_at: 0,
                },
                membership_credential: BbsCredential {
                    schema_id: "test".into(),
                    issuer: BbsPublicKey { key: vec![0u8; 96] },
                    subject: vec![],
                    attributes: vec![],
                    signature: snex_crypto::bbs::BbsSignature { signature: vec![0u8; 112] },
                    epoch: 1,
                    issued_at: 0,
                    expires_at: 0,
                },
                commitment: Commitment { point: snex_crypto::k256::AffinePoint::IDENTITY },
                commitment_key: CommitmentKey::generate(),
                establishment_nullifier: op_secret.derive_establishment_nullifier(1, b"tenant", i),
                pair_tag: op_secret.derive_pair_tag(1, b"tenant"),
                epoch: Epoch(1),
                lifetime_index: i,
                zero_knowledge_proof: vec![],
                received_at: Utc::now(),
            };
            buffer.add(req).unwrap();
        }
        
        assert!(buffer.can_release());
        let batch = buffer.release(3).unwrap();
        assert_eq!(batch.establishments.len(), 3);
    }
}