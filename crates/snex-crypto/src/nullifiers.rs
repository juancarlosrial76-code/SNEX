use crate::error::{CryptoError, Result};
use crate::hashing::{Hash, DOMAIN_NULLIFIER, DOMAIN_RLN_TAG, DOMAIN_PAIR_TAG};
use crate::commitments::Scalar;
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, Zeroizing};
use rand::RngCore;

pub const DOMAIN_ESTABLISHMENT_NULLIFIER: &[u8] = b"SNEX/EST_NULLIFIER/v1";
pub const DOMAIN_VOTE_NULLIFIER: &[u8] = b"SNEX/VOTE_NULLIFIER/v1";
pub const DOMAIN_REPORT_NULLIFIER: &[u8] = b"SNEX/REPORT_NULLIFIER/v1";
pub const DOMAIN_RATE_LIMIT_TAG: &[u8] = b"SNEX/RLN_TAG/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Zeroize)]
pub struct Nullifier(pub [u8; 32]);

impl Nullifier {
    pub fn new(data: &[u8]) -> Self {
        Self(Hash::with_domain(DOMAIN_NULLIFIER, data).0)
    }

    pub fn with_domain(domain: &[u8], data: &[u8]) -> Self {
        Self(Hash::with_domain(domain, data).0)
    }

    pub fn from_operation_secret(
        op_secret: &OperationSecret,
        domain: &[u8],
        context: &[u8],
    ) -> Self {
        let mut data = Vec::new();
        data.extend_from_slice(op_secret.as_bytes());
        data.extend_from_slice(context);
        Self::with_domain(domain, &data)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|e| CryptoError::Deserialization(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidParameter("Nullifier must be 32 bytes".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl AsRef<[u8]> for Nullifier {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, Zeroize)]
pub struct OperationSecret(pub Zeroizing<[u8; 32]>);

impl serde::Serialize for OperationSecret {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0.as_ref())
    }
}

impl<'de> serde::Deserialize<'de> for OperationSecret {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        let arr: [u8; 32] = bytes.as_slice().try_into()
            .map_err(|_| serde::de::Error::custom("invalid operation secret length"))?;
        Ok(Self(Zeroizing::new(arr)))
    }
}

impl OperationSecret {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(Zeroizing::new(bytes))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn derive_nullifier(&self, domain: &[u8], context: &[u8]) -> Nullifier {
        Nullifier::from_operation_secret(self, domain, context)
    }

    pub fn derive_establishment_nullifier(&self, epoch: u64, tenant_id: &[u8], index: u32) -> Nullifier {
        let mut ctx = Vec::new();
        ctx.extend_from_slice(&epoch.to_be_bytes());
        ctx.extend_from_slice(tenant_id);
        ctx.extend_from_slice(&index.to_be_bytes());
        self.derive_nullifier(DOMAIN_ESTABLISHMENT_NULLIFIER, &ctx)
    }

    pub fn derive_vote_nullifier(&self, ballot_id: &[u8]) -> Nullifier {
        self.derive_nullifier(DOMAIN_VOTE_NULLIFIER, ballot_id)
    }

    pub fn derive_report_nullifier(&self, report_window: u64, slot: u32) -> Nullifier {
        let mut ctx = Vec::new();
        ctx.extend_from_slice(&report_window.to_be_bytes());
        ctx.extend_from_slice(&slot.to_be_bytes());
        self.derive_nullifier(DOMAIN_REPORT_NULLIFIER, &ctx)
    }

    pub fn derive_rate_limit_tag(&self, window: u64, tenant_id: &[u8]) -> Nullifier {
        let mut ctx = Vec::new();
        ctx.extend_from_slice(&window.to_be_bytes());
        ctx.extend_from_slice(tenant_id);
        self.derive_nullifier(DOMAIN_RATE_LIMIT_TAG, &ctx)
    }

    pub fn derive_pair_tag(&self, epoch: u64, tenant_id: &[u8]) -> Nullifier {
        let mut ctx = Vec::new();
        ctx.extend_from_slice(&epoch.to_be_bytes());
        ctx.extend_from_slice(tenant_id);
        self.derive_nullifier(DOMAIN_PAIR_TAG, &ctx)
    }
}

#[derive(Clone, Debug, Zeroize)]
pub struct PseudonymSecret(pub Zeroizing<[u8; 32]>);

impl serde::Serialize for PseudonymSecret {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0.as_ref())
    }
}

impl<'de> serde::Deserialize<'de> for PseudonymSecret {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        let arr: [u8; 32] = bytes.as_slice().try_into()
            .map_err(|_| serde::de::Error::custom("invalid pseudonym secret length"))?;
        Ok(Self(Zeroizing::new(arr)))
    }
}

impl PseudonymSecret {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(Zeroizing::new(bytes))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn derive_pseudonym(&self, tenant_id: &[u8], lifetime_index: u32) -> Pseudonym {
        use crate::hashing::DOMAIN_PSEUDONYM;
        let mut data = Vec::new();
        data.extend_from_slice(self.as_bytes());
        data.extend_from_slice(tenant_id);
        data.extend_from_slice(&lifetime_index.to_be_bytes());
        let hash = Hash::with_domain(DOMAIN_PSEUDONYM, &data);
        Pseudonym(hash.0)
    }

    pub fn derive_mailbox_base_secret(&self) -> MailboxBaseSecret {
        use crate::hashing::DOMAIN_MAILBOX_ACCESS;
        let hash = Hash::with_domain(DOMAIN_MAILBOX_ACCESS, self.as_bytes());
        MailboxBaseSecret(Zeroizing::new(hash.0))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Pseudonym(pub [u8; 32]);

impl Pseudonym {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|e| CryptoError::Deserialization(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidParameter("Pseudonym must be 32 bytes".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    pub fn hash(&self) -> Hash {
        use crate::hashing::DOMAIN_COMMITMENT;
        Hash::with_domain(DOMAIN_COMMITMENT, self.as_bytes())
    }
}

#[derive(Clone, Debug, Zeroize)]
pub struct MailboxBaseSecret(pub Zeroizing<[u8; 32]>);

impl serde::Serialize for MailboxBaseSecret {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0.as_ref())
    }
}

impl<'de> serde::Deserialize<'de> for MailboxBaseSecret {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        let arr: [u8; 32] = bytes.as_slice().try_into()
            .map_err(|_| serde::de::Error::custom("invalid mailbox base secret length"))?;
        Ok(Self(Zeroizing::new(arr)))
    }
}

impl MailboxBaseSecret {
    pub fn derive_mailbox_access(&self, case_handle: &CaseHandle) -> MailboxAccess {
        use crate::hashing::DOMAIN_MAILBOX_ACCESS;
        let mut data = Vec::new();
        data.extend_from_slice(self.0.as_ref());
        data.extend_from_slice(case_handle.as_bytes());
        let hash = Hash::with_domain(DOMAIN_MAILBOX_ACCESS, &data);
        MailboxAccess(hash.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MailboxAccess(pub [u8; 32]);

impl MailboxAccess {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CaseHandle(pub [u8; 32]);

impl CaseHandle {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Zeroize)]
pub struct RecoveryCode(pub [u8; 32]);

impl RecoveryCode {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_secret_nullifiers() {
        let op_secret = OperationSecret::generate();
        let nullifier1 = op_secret.derive_vote_nullifier(b"ballot1");
        let nullifier2 = op_secret.derive_vote_nullifier(b"ballot2");
        assert_ne!(nullifier1, nullifier2);

        let nullifier3 = op_secret.derive_vote_nullifier(b"ballot1");
        assert_eq!(nullifier1, nullifier3);
    }

    #[test]
    fn test_pseudonym_derivation() {
        let pseudo_secret = PseudonymSecret::generate();
        let pseudonym1 = pseudo_secret.derive_pseudonym(b"tenant1", 0);
        let pseudonym2 = pseudo_secret.derive_pseudonym(b"tenant2", 0);
        assert_ne!(pseudonym1, pseudonym2);

        let pseudonym3 = pseudo_secret.derive_pseudonym(b"tenant1", 1);
        assert_ne!(pseudonym1, pseudonym3);
    }

    #[test]
    fn test_mailbox_access() {
        let pseudo_secret = PseudonymSecret::generate();
        let mailbox_base = pseudo_secret.derive_mailbox_base_secret();
        let case_handle = CaseHandle::generate();
        let access1 = mailbox_base.derive_mailbox_access(&case_handle);
        let access2 = mailbox_base.derive_mailbox_access(&case_handle);
        assert_eq!(access1, access2);
    }
}