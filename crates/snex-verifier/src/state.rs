use snex_core::{
    pseudonym::{PseudonymRegistration, EstablishmentRequest, Batch, BatchingBuffer, EpochConfirmation, PseudonymCounter, PseudonymFunction, TerminatedPseudonym},
    epoch::Epoch,
    tenant::{Tenant, TenantConfiguration},
    config::AppConfig,
    error::{CoreError, Result},
};
use snex_crypto::{
    bbs::{BbsCredential, BbsPublicKey},
    nullifiers::{Nullifier, OperationSecret, PseudonymSecret, Pseudonym},
    commitments::{Commitment, CommitmentKey},
    hashing::Hash,
};
use rand::Rng;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};
use tokio::sync::RwLock;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifierState {
    pub registrations: HashMap<Uuid, PseudonymRegistration>,
    pub pseudonym_to_registration: HashMap<String, Uuid>,
    pub batching_buffer: BatchingBuffer,
    pub epoch_confirmations: HashMap<Uuid, EpochConfirmation>,
    pub pseudonym_counters: HashMap<Uuid, HashMap<PseudonymFunction, u32>>,
    pub terminated_pseudonyms: HashMap<Uuid, TerminatedPseudonym>,
    pub snapshots: HashMap<Uuid, snex_core::voting::Snapshot>,
    pub issuer_public_keys: HashMap<u64, BbsPublicKey>,
    pub governance_public_keys: HashMap<Uuid, Vec<BbsPublicKey>>,
    pub current_epoch: Epoch,
    pub config: AppConfig,
    pub build_up_mode: HashMap<Uuid, HashMap<PseudonymFunction, BuildUpModeState>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuildUpModeState {
    pub active: bool,
    pub trigger: String,
    pub entered_at: DateTime<Utc>,
    pub re_release_waiting_period_days: u32,
}

impl VerifierState {
    pub fn new(config: AppConfig) -> Self {
        let batch_config = &config.verifier;
        Self {
            registrations: HashMap::new(),
            pseudonym_to_registration: HashMap::new(),
            batching_buffer: BatchingBuffer::new(
                batch_config.min_batch_size,
                batch_config.max_batch_size,
                batch_config.max_establishment_period_hours,
                batch_config.max_failed_establishment_attempts,
            ),
            epoch_confirmations: HashMap::new(),
            pseudonym_counters: HashMap::new(),
            terminated_pseudonyms: HashMap::new(),
            snapshots: HashMap::new(),
            issuer_public_keys: HashMap::new(),
            governance_public_keys: HashMap::new(),
            current_epoch: Epoch::current(),
            config,
            build_up_mode: HashMap::new(),
        }
    }

    pub fn add_issuer_key(&mut self, epoch: u64, pk: BbsPublicKey) {
        self.issuer_public_keys.insert(epoch, pk);
    }

    pub fn add_governance_key(&mut self, tenant_id: Uuid, pk: BbsPublicKey) {
        self.governance_public_keys.entry(tenant_id).or_default().push(pk);
    }

    pub fn process_establishment(&mut self, request: EstablishmentRequest) -> Result<()> {
        self.verify_establishment_proof(&request)?;
        
        self.batching_buffer.add(request)?;
        
        Ok(())
    }

    fn verify_establishment_proof(&self, request: &EstablishmentRequest) -> Result<()> {
        let issuer_pk = self.issuer_public_keys.get(&request.epoch.0)
            .ok_or(CoreError::NotFound("Issuer key not found".into()))?;
        
        let gov_pk = self.governance_public_keys.get(&request.tenant_id)
            .and_then(|keys| keys.last())
            .ok_or(CoreError::NotFound("Governance key not found".into()))?;
        
        let person_valid = request.person_credential.verify(issuer_pk)?;
        let membership_valid = request.membership_credential.verify(gov_pk)?;
        
        if !person_valid || !membership_valid {
            return Err(CoreError::InvalidProof("Credential verification failed".into()));
        }
        
        if request.person_credential.subject != request.membership_credential.subject {
            return Err(CoreError::InvalidProof("Credential subject mismatch".into()));
        }
        
        Ok(())
    }

    pub fn release_batch(&mut self) -> Option<Batch> {
        let threshold = rand::thread_rng().gen_range(self.config.verifier.batch_release_threshold_min..=self.config.verifier.batch_release_threshold_max);
        self.batching_buffer.release(threshold)
    }

    pub fn activate_registrations(&mut self, batch: &Batch) -> Result<()> {
        for req in &batch.establishments {
            let reg = PseudonymRegistration::new(
                req.tenant_id,
                pseudonym_from_commitment(&req.commitment),
                req.epoch,
                req.lifetime_index,
                req.establishment_nullifier,
                req.pair_tag,
                req.membership_credential.attributes.iter().any(|a| a == b"reporting"),
                req.membership_credential.attributes.iter().any(|a| a == b"voting"),
            );
            
            self.registrations.insert(reg.id, reg.clone());
            self.pseudonym_to_registration.insert(reg.pseudonym.to_hex(), reg.id);
            
            let counter = self.pseudonym_counters.entry(req.tenant_id).or_default();
            if reg.reporting_authorised {
                *counter.entry(PseudonymFunction::Reporting).or_insert(0) += 1;
            }
            if reg.voting_authorised {
                *counter.entry(PseudonymFunction::Voting).or_insert(0) += 1;
            }
        }
        Ok(())
    }

    pub fn confirm_epoch(&mut self, confirmation: EpochConfirmation) -> Result<()> {
        self.verify_epoch_confirmation(&confirmation)?;
        
        let reg_id = self.pseudonym_to_registration.get(&confirmation.pseudonym.to_hex())
            .ok_or(CoreError::NotFound("Pseudonym not found".into()))?;
        
        if let Some(reg) = self.registrations.get_mut(reg_id) {
            reg.confirm_epoch();
        }
        
        let reporting = confirmation.membership_credential.attributes.iter().any(|a| a == b"reporting");
        let voting = confirmation.membership_credential.attributes.iter().any(|a| a == b"voting");
        let tenant_id = confirmation.tenant_id;
        self.epoch_confirmations.insert(Uuid::new_v4(), confirmation);
        
        let counter = self.pseudonym_counters.entry(tenant_id).or_default();
        if reporting {
            *counter.entry(PseudonymFunction::Reporting).or_insert(0) += 1;
        }
        if voting {
            *counter.entry(PseudonymFunction::Voting).or_insert(0) += 1;
        }
        
        Ok(())
    }

    fn verify_epoch_confirmation(&self, confirmation: &EpochConfirmation) -> Result<()> {
        let issuer_pk = self.issuer_public_keys.get(&confirmation.epoch.0)
            .ok_or(CoreError::NotFound("Issuer key not found".into()))?;
        
        let person_valid = confirmation.person_credential.verify(issuer_pk)?;
        let membership_valid = confirmation.membership_credential.verify(
            self.governance_public_keys.get(&confirmation.tenant_id)
                .and_then(|keys| keys.last())
                .ok_or(CoreError::NotFound("Governance key not found".into()))?
        )?;
        
        if !person_valid || !membership_valid {
            return Err(CoreError::InvalidProof("Credential verification failed".into()));
        }
        
        Ok(())
    }

    pub fn get_anonymity_set(&self, tenant_id: Uuid, function: PseudonymFunction) -> u32 {
        self.pseudonym_counters
            .get(&tenant_id)
            .and_then(|c| c.get(&function).copied())
            .unwrap_or(0)
    }

    pub fn check_build_up_mode(&mut self, tenant_id: Uuid, function: PseudonymFunction) -> bool {
        let set_size = self.get_anonymity_set(tenant_id, function);
        let min_set = self.config.verifier.minimum_anonymity_set;
        
        let mode = self.build_up_mode.entry(tenant_id).or_default()
            .entry(function).or_insert(BuildUpModeState {
                active: false,
                trigger: String::new(),
                entered_at: Utc::now(),
                re_release_waiting_period_days: self.config.verifier.re_release_waiting_period_days,
            });
        
        if set_size < min_set && !mode.active {
            mode.active = true;
            mode.trigger = format!("Anonymity set {} below minimum {}", set_size, min_set);
            mode.entered_at = Utc::now();
            true
        } else if mode.active && set_size >= min_set {
            let elapsed = Utc::now().signed_duration_since(mode.entered_at).num_days();
            if elapsed >= mode.re_release_waiting_period_days as i64 {
                mode.active = false;
                mode.trigger.clear();
                false
            } else {
                true
            }
        } else {
            mode.active
        }
    }

    pub fn create_snapshot(&mut self, tenant_id: Uuid, epoch: Epoch, ballot_id: Option<Uuid>) -> Result<snex_core::voting::Snapshot> {
        let mut snapshot = snex_core::voting::Snapshot::new(tenant_id, epoch, ballot_id);
        
        for (reg_id, reg) in &self.registrations {
            if reg.tenant_id == tenant_id && reg.epoch == epoch && reg.is_active() {
                snapshot.add_leaf(snex_core::voting::SnapshotLeaf {
                    pseudonym: reg.pseudonym,
                    reporting_authorised: reg.reporting_authorised,
                    voting_authorised: reg.voting_authorised,
                    index: reg.lifetime_index,
                });
            }
        }
        
        snapshot.build_merkle_root()?;
        self.snapshots.insert(snapshot.id, snapshot.clone());
        
        Ok(snapshot)
    }

    pub fn terminate_pseudonym(&mut self, pseudonym: Pseudonym, tenant_id: Uuid) -> Result<()> {
        let reg_id = self.pseudonym_to_registration.get(&pseudonym.to_hex())
            .ok_or(CoreError::NotFound("Pseudonym not found".into()))?;
        
        if let Some(reg) = self.registrations.get_mut(reg_id) {
            reg.terminate();
            
            let terminated = TerminatedPseudonym::from_registration(reg);
            self.terminated_pseudonyms.insert(Uuid::new_v4(), terminated);
            
            let counter = self.pseudonym_counters.entry(tenant_id).or_default();
            if reg.reporting_authorised {
                *counter.entry(PseudonymFunction::Reporting).or_insert(0) = counter.get(&PseudonymFunction::Reporting).map(|v| v.saturating_sub(1)).unwrap_or(0);
            }
            if reg.voting_authorised {
                *counter.entry(PseudonymFunction::Voting).or_insert(0) = counter.get(&PseudonymFunction::Voting).map(|v| v.saturating_sub(1)).unwrap_or(0);
            }
        }
        
        Ok(())
    }

    pub fn block_pseudonym(&mut self, pseudonym: Pseudonym, tenant_id: Uuid, reason: String) -> Result<()> {
        let reg_id = self.pseudonym_to_registration.get(&pseudonym.to_hex())
            .ok_or(CoreError::NotFound("Pseudonym not found".into()))?;
        
        if let Some(reg) = self.registrations.get_mut(reg_id) {
            reg.block(reason);
            
            let counter = self.pseudonym_counters.entry(tenant_id).or_default();
            if reg.reporting_authorised {
                *counter.entry(PseudonymFunction::Reporting).or_insert(0) = counter.get(&PseudonymFunction::Reporting).map(|v| v.saturating_sub(1)).unwrap_or(0);
            }
            if reg.voting_authorised {
                *counter.entry(PseudonymFunction::Voting).or_insert(0) = counter.get(&PseudonymFunction::Voting).map(|v| v.saturating_sub(1)).unwrap_or(0);
            }
        }
        
        Ok(())
    }

    pub fn is_terminated(&self, pseudonym: Pseudonym) -> bool {
        self.terminated_pseudonyms.values().any(|t| t.pseudonym_hash.as_bytes() == pseudonym.as_bytes())
    }
}

/// Leitet das Pseudonym deterministisch aus dem Commitment ab (32 Byte).
/// Frueher: `to_encoded_point(..).try_into().unwrap()` (33 Byte -> 32, haette Panic ausgeloest).
pub(crate) fn pseudonym_from_commitment(commitment: &Commitment) -> Pseudonym {
    Pseudonym(commitment.hash().0)
}

pub type SharedVerifierState = Arc<RwLock<VerifierState>>;

use std::sync::Arc;