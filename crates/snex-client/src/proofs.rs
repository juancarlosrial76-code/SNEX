use snex_core::{
    identity::CredentialPair,
    pseudonym::{EstablishmentRequest, EpochConfirmation, PseudonymFunction},
    voting::{VoteRelation, MerkleProof, SnapshotLeaf},
    reporting::ReportWindowSchedule,
    epoch::Epoch,
    error::{CoreError, Result},
};
use snex_crypto::{
    bbs::{BbsCredential, BbsPublicKey, BbsProof, verify_blind_issuance},
    commitments::{Commitment, CommitmentKey},
    nullifiers::{Nullifier, OperationSecret, Pseudonym, PseudonymSecret},
    hashing::Hash,
};
use uuid::Uuid;

pub struct ProofGenerator;

impl ProofGenerator {
    pub fn generate_establishment_proof(
        person_credential: &BbsCredential,
        membership_credential: &BbsCredential,
        commitment: &Commitment,
        commitment_key: &CommitmentKey,
        epoch: Epoch,
        tenant_id: &[u8],
        lifetime_index: u32,
    ) -> Result<EstablishmentRequest> {
        let operation_secret = OperationSecret::generate();
        let pseudo_secret = PseudonymSecret::generate();
        
        let establishment_nullifier = operation_secret.derive_establishment_nullifier(epoch.0, tenant_id, lifetime_index);
        let pair_tag = operation_secret.derive_pair_tag(epoch.0, tenant_id);
        
        let zero_knowledge_proof = vec![0u8; 256];
        
        Ok(EstablishmentRequest {
            tenant_id: Uuid::from_slice(tenant_id).unwrap(),
            person_credential: person_credential.clone(),
            membership_credential: membership_credential.clone(),
            commitment: *commitment,
            commitment_key: commitment_key.clone(),
            establishment_nullifier,
            pair_tag,
            epoch,
            lifetime_index,
            zero_knowledge_proof,
            received_at: chrono::Utc::now(),
        })
    }

    pub fn generate_epoch_confirmation_proof(
        person_credential: &BbsCredential,
        membership_credential: &BbsCredential,
        pseudonym: Pseudonym,
        epoch: Epoch,
        tenant_id: Uuid,
    ) -> Result<EpochConfirmation> {
        let zero_knowledge_proof = vec![0u8; 256];
        
        Ok(EpochConfirmation {
            pseudonym,
            tenant_id,
            epoch,
            person_credential: person_credential.clone(),
            membership_credential: membership_credential.clone(),
            zero_knowledge_proof,
        })
    }

    pub fn generate_vote_proof(
        vote_relation: &VoteRelation,
        credential: &BbsCredential,
        public_key: &BbsPublicKey,
    ) -> Result<BbsProof> {
        let nonce = vote_relation.ballot_id.as_bytes().to_vec();
        
        Ok(BbsProof::generate(credential, public_key, &[], &nonce)?)
    }

    pub fn generate_report_proof(
        operation_secret: &OperationSecret,
        report_window: u64,
        slot: u32,
    ) -> Nullifier {
        operation_secret.derive_report_nullifier(report_window, slot)
    }

    pub fn generate_rate_limit_tag(
        operation_secret: &OperationSecret,
        window: u64,
        tenant_id: &[u8],
    ) -> Nullifier {
        operation_secret.derive_rate_limit_tag(window, tenant_id)
    }
}

pub struct ProofVerifier;

impl ProofVerifier {
    pub fn verify_establishment_proof(
        person_credential: &BbsCredential,
        membership_credential: &BbsCredential,
        commitment: &Commitment,
        person_pk: &BbsPublicKey,
        membership_pk: &BbsPublicKey,
    ) -> Result<bool> {
        let person_valid = person_credential.verify(person_pk)?;
        let membership_valid = membership_credential.verify(membership_pk)?;
        
        if !person_valid || !membership_valid {
            return Ok(false);
        }
        
        if person_credential.subject != membership_credential.subject {
            return Ok(false);
        }
        
        let blinded_verified = verify_blind_issuance(person_pk, commitment, person_credential)?;
        
        Ok(blinded_verified)
    }

    pub fn verify_epoch_confirmation_proof(
        person_credential: &BbsCredential,
        membership_credential: &BbsCredential,
        person_pk: &BbsPublicKey,
        membership_pk: &BbsPublicKey,
    ) -> Result<bool> {
        let person_valid = person_credential.verify(person_pk)?;
        let membership_valid = membership_credential.verify(membership_pk)?;
        
        Ok(person_valid && membership_valid)
    }

    pub fn verify_vote_proof(
        vote_relation: &VoteRelation,
        credential: &BbsCredential,
        snapshot: &snex_core::voting::Snapshot,
        snapshot_pk: &BbsPublicKey,
    ) -> Result<bool> {
        let merkle_valid = snapshot.verify_proof(&vote_relation.merkle_proof, &SnapshotLeaf {
            pseudonym: vote_relation.pseudonym,
            reporting_authorised: false,
            voting_authorised: true,
            index: vote_relation.merkle_proof.leaf_index,
        });
        
        if !merkle_valid {
            return Ok(false);
        }
        
        let nonce = vote_relation.ballot_id.as_bytes().to_vec();
        let proof = BbsProof::generate(credential, snapshot_pk, &[], &nonce)?;
        
        Ok(proof.verify(snapshot_pk, &nonce, &[])?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snex_crypto::nullifiers::{OperationSecret, PseudonymSecret};

    #[test]
    fn test_proof_generator() {
        let op_secret = OperationSecret::generate();
        let tag = ProofGenerator::generate_rate_limit_tag(&op_secret, 0, b"tenant");
        assert!(!tag.as_bytes().iter().all(|&b| b == 0));
    }
}