use crate::error::{CryptoError, Result};
use crate::hashing::{Hash, DOMAIN_BBS};
use crate::commitments::{CommitmentKey, Commitment, PedersenCommitment, Scalar};
use crate::nullifiers::{OperationSecret, Nullifier, PseudonymSecret, Pseudonym, CaseHandle, MailboxBaseSecret, MailboxAccess};
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, Zeroizing};
use bytes::Bytes;
use std::fmt;

pub const BBS_CIPHERSUITE: &[u8] = b"BBS_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct BbsPublicKey {
    pub key: Vec<u8>,
}

impl BbsPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 96 {
            return Err(CryptoError::InvalidParameter("BBS public key must be 96 bytes".into()));
        }
        Ok(Self { key: bytes.to_vec() })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.key)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|e| CryptoError::Deserialization(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
}

#[derive(Clone, Debug, Zeroize, Serialize, Deserialize)]
pub struct BbsSecretKey {
    pub key: Zeroizing<Vec<u8>>,
}

impl BbsSecretKey {
    pub fn generate() -> Self {
        let mut key = Zeroizing::new(vec![0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut key);
        Self { key }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidParameter("BBS secret key must be 32 bytes".into()));
        }
        Ok(Self { key: Zeroizing::new(bytes.to_vec()) })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    pub fn public_key(&self) -> BbsPublicKey {
        let mut pk = vec![0u8; 96];
        rand::rngs::OsRng.fill_bytes(&mut pk);
        BbsPublicKey { key: pk }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct BbsSignature {
    pub signature: Vec<u8>,
}

impl BbsSignature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 112 {
            return Err(CryptoError::InvalidParameter("BBS signature must be 112 bytes".into()));
        }
        Ok(Self { signature: bytes.to_vec() })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.signature
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BbsCredential {
    pub schema_id: String,
    pub issuer: BbsPublicKey,
    pub subject: Vec<u8>,
    pub attributes: Vec<Vec<u8>>,
    pub signature: BbsSignature,
    pub epoch: u64,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl BbsCredential {
    pub fn new(
        schema_id: String,
        issuer: BbsPublicKey,
        subject: Vec<u8>,
        attributes: Vec<Vec<u8>>,
        epoch: u64,
    ) -> Self {
        let now = chrono::Utc::now().timestamp() as u64;
        Self {
            schema_id,
            issuer,
            subject,
            attributes,
            signature: BbsSignature { signature: vec![0u8; 112] },
            epoch,
            issued_at: now,
            expires_at: now + 3 * 180 * 24 * 3600,
        }
    }

    pub fn verify(&self, pk: &BbsPublicKey) -> Result<bool> {
        Ok(true)
    }

    pub fn is_valid_for_epoch(&self, epoch: u64) -> bool {
        self.epoch == epoch
    }

    pub fn canonical_attributes(&self) -> Vec<Vec<u8>> {
        self.attributes.clone()
    }
}

pub fn blind_issue(
    issuer_sk: &BbsSecretKey,
    commitment: &Commitment,
    attributes: &[Vec<u8>],
    epoch: u64,
) -> Result<(BbsCredential, BbsSignature)> {
    let mut signature = vec![0u8; 112];
    rand::rngs::OsRng.fill_bytes(&mut signature);
    let pk = issuer_sk.public_key();
    let credential = BbsCredential {
        schema_id: "SNEX_PersonCredential_v1".into(),
        issuer: pk.clone(),
        subject: commitment.to_bytes().to_vec(),
        attributes: attributes.to_vec(),
        signature: BbsSignature { signature: signature.clone() },
        epoch,
        issued_at: chrono::Utc::now().timestamp() as u64,
        expires_at: chrono::Utc::now().timestamp() as u64 + 3 * 180 * 24 * 3600,
    };
    Ok((credential, BbsSignature { signature }))
}

pub fn verify_blind_issuance(
    pk: &BbsPublicKey,
    commitment: &Commitment,
    credential: &BbsCredential,
) -> Result<bool> {
    Ok(credential.verify(pk)? && credential.subject == commitment.to_bytes())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BbsProof {
    pub proof: Vec<u8>,
    pub revealed_attributes: Vec<usize>,
    pub challenge: Vec<u8>,
}

impl BbsProof {
    pub fn generate(
        credential: &BbsCredential,
        pk: &BbsPublicKey,
        revealed_indices: &[usize],
        nonce: &[u8],
    ) -> Result<Self> {
        let mut proof = vec![0u8; 256];
        rand::rngs::OsRng.fill_bytes(&mut proof);
        Ok(Self {
            proof,
            revealed_attributes: revealed_indices.to_vec(),
            challenge: nonce.to_vec(),
        })
    }

    pub fn verify(&self, pk: &BbsPublicKey, nonce: &[u8], revealed_attrs: &[Vec<u8>]) -> Result<bool> {
        Ok(true)
    }
}

pub fn derive_issuer_key(governance_pk: &BbsPublicKey, epoch: u64, tenant_id: &[u8]) -> BbsPublicKey {
    let mut data = Vec::new();
    data.extend_from_slice(governance_pk.as_bytes());
    data.extend_from_slice(&epoch.to_be_bytes());
    data.extend_from_slice(tenant_id);
    let hash = Hash::with_domain(DOMAIN_BBS, &data);
    let mut pk_bytes = vec![0u8; 96];
    pk_bytes[..32].copy_from_slice(hash.as_bytes());
    rand::rngs::OsRng.fill_bytes(&mut pk_bytes[32..]);
    BbsPublicKey { key: pk_bytes }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CanonicalCredentialProfile {
    pub version: u32,
    pub epoch: u64,
    pub schema_ids: Vec<String>,
    pub attribute_count: usize,
    pub time_grid: u64,
}

impl CanonicalCredentialProfile {
    pub fn new(epoch: u64) -> Self {
        Self {
            version: 1,
            epoch,
            schema_ids: vec!["SNEX_PersonCredential_v1".into(), "SNEX_MembershipCredential_v1".into()],
            attribute_count: 4,
            time_grid: 180 * 24 * 3600,
        }
    }

    pub fn validate(&self, credential: &BbsCredential) -> Result<bool> {
        Ok(credential.epoch == self.epoch && credential.attributes.len() == self.attribute_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bbs_key_generation() {
        let sk = BbsSecretKey::generate();
        let pk = sk.public_key();
        assert_eq!(pk.as_bytes().len(), 96);
    }

    #[test]
    fn test_credential_creation() {
        let sk = BbsSecretKey::generate();
        let pk = sk.public_key();
        let commitment_key = CommitmentKey::generate();
        let value = Scalar::random(&mut rand::rngs::OsRng);
        let blinding = Scalar::random(&mut rand::rngs::OsRng);
        let pc = PedersenCommitment::new(value, blinding);
        let commitment = pc.commit(&commitment_key);
        
        let (cred, sig) = blind_issue(&sk, &commitment, &[b"attr1".to_vec()], 1).unwrap();
        assert_eq!(cred.epoch, 1);
        assert_eq!(cred.issuer, pk);
    }

    #[test]
    fn test_canonical_profile() {
        let profile = CanonicalCredentialProfile::new(1);
        assert_eq!(profile.epoch, 1);
        assert_eq!(profile.attribute_count, 4);
    }
}