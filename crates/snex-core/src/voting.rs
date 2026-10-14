use snex_crypto::{
    nullifiers::{Nullifier, OperationSecret, Pseudonym},
    bbs::BbsCredential,
    hash::Hash,
};
use crate::{epoch::Epoch, pseudonym::PseudonymFunction, error::{CoreError, Result}};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use strum::{EnumString, Display, AsRefStr};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, EnumString, Display, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum VoteValue {
    Yes,
    No,
    Abstain,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ballot {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub title: String,
    pub description: String,
    pub opens_at: DateTime<Utc>,
    pub closes_at: DateTime<Utc>,
    pub epoch: Epoch,
    pub snapshot_root: Hash,
    pub snapshot_size: u32,
    pub status: BallotStatus,
    pub created_at: DateTime<Utc>,
    pub tier: BallotTier,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, EnumString, Display, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum BallotStatus {
    Upcoming,
    Open,
    Closed,
    Published,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, EnumString, Display, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum BallotTier {
    Tier1Consultative,
    Tier2Binding,
}

impl Ballot {
    pub fn new(
        tenant_id: Uuid,
        title: String,
        description: String,
        opens_at: DateTime<Utc>,
        closes_at: DateTime<Utc>,
        epoch: Epoch,
        tier: BallotTier,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            title,
            description,
            opens_at,
            closes_at,
            epoch,
            snapshot_root: Hash([0u8; 32]),
            snapshot_size: 0,
            status: BallotStatus::Upcoming,
            created_at: Utc::now(),
            tier,
        }
    }

    pub fn is_open(&self) -> bool {
        let now = Utc::now();
        self.status == BallotStatus::Open && now >= self.opens_at && now <= self.closes_at
    }

    pub fn open(&mut self) {
        self.status = BallotStatus::Open;
    }

    pub fn close(&mut self) {
        self.status = BallotStatus::Closed;
    }

    pub fn publish(&mut self) {
        self.status = BallotStatus::Published;
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    pub id: Uuid,
    pub ballot_id: Uuid,
    pub nullifier: Nullifier,
    pub vote_value: VoteValue,
    pub vote_hash: Hash,
    pub pseudonym: Pseudonym,
    pub proof: Vec<u8>,
    pub cast_at: DateTime<Utc>,
    pub verified: bool,
}

impl Vote {
    pub fn new(
        ballot_id: Uuid,
        nullifier: Nullifier,
        vote_value: VoteValue,
        pseudonym: Pseudonym,
        proof: Vec<u8>,
    ) -> Self {
        let mut data = Vec::new();
        data.extend_from_slice(nullifier.as_bytes());
        data.push(vote_value as u8);
        let vote_hash = snex_crypto::Hash::new(&data);
        
        Self {
            id: Uuid::new_v4(),
            ballot_id,
            nullifier,
            vote_value,
            vote_hash,
            pseudonym,
            proof,
            cast_at: Utc::now(),
            verified: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VoteRegister {
    pub ballot_id: Uuid,
    pub entries: HashMap<Nullifier, VoteRegisterEntry>,
    pub finalized: bool,
    pub anchored_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VoteRegisterEntry {
    pub nullifier: Nullifier,
    pub vote_value: VoteValue,
    pub vote_hash: Hash,
    pub cast_at: DateTime<Utc>,
}

impl VoteRegister {
    pub fn new(ballot_id: Uuid) -> Self {
        Self {
            ballot_id,
            entries: HashMap::new(),
            finalized: false,
            anchored_at: None,
        }
    }

    pub fn add_vote(&mut self, vote: &Vote) -> Result<()> {
        if self.finalized {
            return Err(CoreError::InvalidStateTransition("Register finalized".into()));
        }
        if self.entries.contains_key(&vote.nullifier) {
            return Err(CoreError::DoubleVote);
        }
        self.entries.insert(vote.nullifier, VoteRegisterEntry {
            nullifier: vote.nullifier,
            vote_value: vote.vote_value,
            vote_hash: vote.vote_hash,
            cast_at: vote.cast_at,
        });
        Ok(())
    }

    pub fn finalize(&mut self) {
        self.finalized = true;
        self.anchored_at = Some(Utc::now());
    }

    pub fn tally(&self) -> VoteTally {
        let mut yes = 0;
        let mut no = 0;
        let mut abstain = 0;
        
        for entry in self.entries.values() {
            match entry.vote_value {
                VoteValue::Yes => yes += 1,
                VoteValue::No => no += 1,
                VoteValue::Abstain => abstain += 1,
            }
        }
        
        VoteTally {
            total: self.entries.len() as u32,
            yes,
            no,
            abstain,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VoteTally {
    pub total: u32,
    pub yes: u32,
    pub no: u32,
    pub abstain: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub epoch: Epoch,
    pub ballot_id: Option<Uuid>,
    pub merkle_root: Hash,
    pub leaves: Vec<SnapshotLeaf>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotLeaf {
    pub pseudonym: Pseudonym,
    pub reporting_authorised: bool,
    pub voting_authorised: bool,
    pub index: u32,
}

impl Snapshot {
    pub fn new(tenant_id: Uuid, epoch: Epoch, ballot_id: Option<Uuid>) -> Self {
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            epoch,
            ballot_id,
            merkle_root: Hash([0u8; 32]),
            leaves: Vec::new(),
            created_at: Utc::now(),
        }
    }

    pub fn add_leaf(&mut self, leaf: SnapshotLeaf) {
        self.leaves.push(leaf);
    }

    pub fn build_merkle_root(&mut self) -> Result<()> {
        if self.leaves.is_empty() {
            return Ok(());
        }
        
        let mut level: Vec<Hash> = self.leaves.iter()
            .map(|leaf| {
                let mut data = Vec::new();
                data.extend_from_slice(leaf.pseudonym.as_bytes());
                data.push(leaf.reporting_authorised as u8);
                data.push(leaf.voting_authorised as u8);
                data.extend_from_slice(&leaf.index.to_be_bytes());
                snex_crypto::Hash::new(&data)
            })
            .collect();
        
        while level.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in level.chunks(2) {
                let mut data = Vec::new();
                data.extend_from_slice(chunk[0].as_bytes());
                if chunk.len() > 1 {
                    data.extend_from_slice(chunk[1].as_bytes());
                } else {
                    data.extend_from_slice(chunk[0].as_bytes());
                }
                next_level.push(snex_crypto::Hash::new(&data));
            }
            level = next_level;
        }
        
        self.merkle_root = level[0];
        Ok(())
    }

    pub fn generate_proof(&self, index: u32) -> Option<MerkleProof> {
        if index as usize >= self.leaves.len() {
            return None;
        }
        
        let mut proof = Vec::new();
        let mut current_index = index;
        let mut level: Vec<Hash> = self.leaves.iter()
            .map(|leaf| {
                let mut data = Vec::new();
                data.extend_from_slice(leaf.pseudonym.as_bytes());
                data.push(leaf.reporting_authorised as u8);
                data.push(leaf.voting_authorised as u8);
                data.extend_from_slice(&leaf.index.to_be_bytes());
                snex_crypto::Hash::new(&data)
            })
            .collect();
        
        while level.len() > 1 {
            let sibling_index = if current_index % 2 == 0 { current_index + 1 } else { current_index - 1 };
            if sibling_index < level.len() as u32 {
                proof.push(level[sibling_index as usize]);
            } else {
                proof.push(level[current_index as usize]);
            }
            current_index /= 2;
            
            let mut next_level = Vec::new();
            for chunk in level.chunks(2) {
                let mut data = Vec::new();
                data.extend_from_slice(chunk[0].as_bytes());
                if chunk.len() > 1 {
                    data.extend_from_slice(chunk[1].as_bytes());
                } else {
                    data.extend_from_slice(chunk[0].as_bytes());
                }
                next_level.push(snex_crypto::Hash::new(&data));
            }
            level = next_level;
        }
        
        Some(MerkleProof {
            leaf_index: index,
            siblings: proof,
            root: self.merkle_root,
        })
    }

    pub fn verify_proof(&self, proof: &MerkleProof, leaf: &SnapshotLeaf) -> bool {
        let mut current_hash = {
            let mut data = Vec::new();
            data.extend_from_slice(leaf.pseudonym.as_bytes());
            data.push(leaf.reporting_authorised as u8);
            data.push(leaf.voting_authorised as u8);
            data.extend_from_slice(&leaf.index.to_be_bytes());
            snex_crypto::Hash::new(&data)
        };
        
        let mut index = proof.leaf_index;
        for sibling in &proof.siblings {
            let mut data = Vec::new();
            if index % 2 == 0 {
                data.extend_from_slice(current_hash.as_bytes());
                data.extend_from_slice(sibling.as_bytes());
            } else {
                data.extend_from_slice(sibling.as_bytes());
                data.extend_from_slice(current_hash.as_bytes());
            }
            current_hash = snex_crypto::Hash::new(&data);
            index /= 2;
        }
        
        current_hash == proof.root
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: u32,
    pub siblings: Vec<Hash>,
    pub root: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VoteRelation {
    pub ballot_id: Uuid,
    pub snapshot_id: Uuid,
    pub pseudonym: Pseudonym,
    pub operation_secret: OperationSecret,
    pub vote_value: VoteValue,
    pub merkle_proof: MerkleProof,
}

impl VoteRelation {
    pub fn generate_nullifier(&self) -> Nullifier {
        self.operation_secret.derive_vote_nullifier(self.ballot_id.as_bytes())
    }

    pub fn generate_vote_hash(&self, nullifier: &Nullifier) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(nullifier.as_bytes());
        data.push(self.vote_value as u8);
        snex_crypto::Hash::new(&data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snex_crypto::nullifiers::{OperationSecret, PseudonymSecret};

    #[test]
    fn test_ballot_lifecycle() {
        let mut ballot = Ballot::new(
            Uuid::new_v4(),
            "Test Ballot".into(),
            "Description".into(),
            Utc::now() + chrono::Duration::hours(1),
            Utc::now() + chrono::Duration::hours(25),
            Epoch::current(),
            BallotTier::Tier1Consultative,
        );
        assert_eq!(ballot.status, BallotStatus::Upcoming);
        ballot.open();
        assert_eq!(ballot.status, BallotStatus::Open);
    }

    #[test]
    fn test_vote_register() {
        let mut register = VoteRegister::new(Uuid::new_v4());
        let op_secret = OperationSecret::generate();
        let pseudonym = PseudonymSecret::generate().derive_pseudonym(b"tenant", 0);
        let nullifier = op_secret.derive_vote_nullifier(b"ballot1");
        
        let vote = Vote::new(Uuid::new_v4(), nullifier, VoteValue::Yes, pseudonym, vec![]);
        register.add_vote(&vote).unwrap();
        
        let tally = register.tally();
        assert_eq!(tally.yes, 1);
        assert_eq!(tally.total, 1);
    }

    #[test]
    fn test_snapshot_merkle() {
        let mut snapshot = Snapshot::new(Uuid::new_v4(), Epoch::current(), None);
        let pseudo_secret = PseudonymSecret::generate();
        
        for i in 0..4 {
            let pseudonym = pseudo_secret.derive_pseudonym(b"tenant", i);
            snapshot.add_leaf(SnapshotLeaf {
                pseudonym,
                reporting_authorised: true,
                voting_authorised: true,
                index: i,
            });
        }
        
        snapshot.build_merkle_root().unwrap();
        assert_ne!(snapshot.merkle_root.as_bytes(), &[0u8; 32]);
        
        let proof = snapshot.generate_proof(0).unwrap();
        assert!(snapshot.verify_proof(&proof, &snapshot.leaves[0]));
    }
}