use blake3;
use crate::error::{CryptoError, Result};

pub const DOMAIN_BBS: &[u8] = b"SNEX/BBS/v1";
pub const DOMAIN_COMMITMENT: &[u8] = b"SNEX/COMMITMENT/v1";
pub const DOMAIN_NULLIFIER: &[u8] = b"SNEX/NULLIFIER/v1";
pub const DOMAIN_EPOCH_SECRET: &[u8] = b"SNEX/EPOCH_SECRET/v1";
pub const DOMAIN_PSEUDONYM: &[u8] = b"SNEX/PSEUDONYM/v1";
pub const DOMAIN_PAIR_TAG: &[u8] = b"SNEX/PAIR_TAG/v1";
pub const DOMAIN_ESCROW: &[u8] = b"SNEX/ESCROW/v1";
pub const DOMAIN_RLN_TAG: &[u8] = b"SNEX/RLN_TAG/v1";
pub const DOMAIN_CASE_HANDLE: &[u8] = b"SNEX/CASE_HANDLE/v1";
pub const DOMAIN_MAILBOX_ACCESS: &[u8] = b"SNEX/MAILBOX_ACCESS/v1";
pub const DOMAIN_RECOVERY_CODE: &[u8] = b"SNEX/RECOVERY_CODE/v1";
pub const DOMAIN_ANCHOR: &[u8] = b"SNEX/ANCHOR/v1";
pub const DOMAIN_JOURNAL: &[u8] = b"SNEX/JOURNAL/v1";
pub const DOMAIN_DVI: &[u8] = b"SNEX/DVI/v1";
pub const DOMAIN_GOVERNANCE: &[u8] = b"SNEX/GOVERNANCE/v1";
pub const DOMAIN_PQ_WRAPPER: &[u8] = b"SNEX/PQ_WRAPPER/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub fn new(data: &[u8]) -> Self {
        Self(blake3::hash(data).into())
    }

    pub fn with_domain(domain: &[u8], data: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain);
        hasher.update(data);
        Self(hasher.finalize().into())
    }

    pub fn with_domains(domains: &[&[u8]], data: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        for domain in domains {
            hasher.update(domain);
        }
        hasher.update(data);
        Self(hasher.finalize().into())
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
            return Err(CryptoError::InvalidParameter("Hash must be 32 bytes".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl serde::Serialize for Hash {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for Hash {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, out).expect("HKDF expand");
}

pub fn derive_key(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    hkdf_sha256(salt, ikm, info, &mut out);
    out
}