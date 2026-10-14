use crate::error::{CryptoError, Result};
use crate::hashing::{Hash, DOMAIN_JOURNAL};
use crate::kdf::derive_key;
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit, OsRng}};
use aes_gcm::aead::generic_array::GenericArray;
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};
use rand::RngCore;
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, Zeroizing};
use std::collections::HashMap;

pub const MASTER_KEY_LABEL: &[u8] = b"SNEX Master Key v1";
pub const KEK_LABEL: &[u8] = b"SNEX KEK v1";
pub const DEK_LABEL: &[u8] = b"SNEX DEK v1";
pub const BACKUP_WRAPPING_KEY_LABEL: &[u8] = b"SNEX Backup Wrapping Key v1";
pub const PQ_WRAPPING_KEY_LABEL: &[u8] = b"SNEX PQ Wrapping Key v1";

#[derive(Clone, Debug, Zeroize, Serialize, Deserialize)]
pub struct MasterKey(pub Zeroizing<[u8; 32]>);

impl MasterKey {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(Zeroizing::new(bytes))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn derive_kek(&self, context: &[u8]) -> Kek {
        let key = derive_key(MASTER_KEY_LABEL, self.0.as_ref(), context);
        Kek(Zeroizing::new(key))
    }

    pub fn derive_backup_wrapping_key(&self, generation: u64) -> BackupWrappingKey {
        let mut ctx = Vec::new();
        ctx.extend_from_slice(BACKUP_WRAPPING_KEY_LABEL);
        ctx.extend_from_slice(&generation.to_be_bytes());
        let key = derive_key(MASTER_KEY_LABEL, self.0.as_ref(), &ctx);
        BackupWrappingKey(Zeroizing::new(key))
    }

    pub fn derive_pq_wrapping_key(&self, generation: u64) -> PqWrappingKey {
        let mut ctx = Vec::new();
        ctx.extend_from_slice(PQ_WRAPPING_KEY_LABEL);
        ctx.extend_from_slice(&generation.to_be_bytes());
        let key = derive_key(MASTER_KEY_LABEL, self.0.as_ref(), &ctx);
        PqWrappingKey(Zeroizing::new(key))
    }
}

#[derive(Clone, Debug, Zeroize, Serialize, Deserialize)]
pub struct Kek(pub Zeroizing<[u8; 32]>);

impl Kek {
    pub fn derive_dek(&self, context: &[u8]) -> Dek {
        let key = derive_key(KEK_LABEL, self.0.as_ref(), context);
        Dek(Zeroizing::new(key))
    }

    pub fn wrap_dek(&self, dek: &Dek) -> WrappedDek {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(self.0.as_ref()));
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, dek.0.as_ref())
            .map_err(|e| CryptoError::Encryption(e.to_string())).unwrap();
        let mut wrapped = Vec::new();
        wrapped.extend_from_slice(&nonce_bytes);
        wrapped.extend_from_slice(&ciphertext);
        WrappedDek(wrapped)
    }

    pub fn unwrap_dek(&self, wrapped: &WrappedDek) -> Result<Dek> {
        if wrapped.0.len() < 12 {
            return Err(CryptoError::Decryption("Wrapped DEK too short".into()));
        }
        let nonce = Nonce::from_slice(&wrapped.0[..12]);
        let ciphertext = &wrapped.0[12..];
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(self.0.as_ref()));
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| CryptoError::Decryption(e.to_string()))?;
        if plaintext.len() != 32 {
            return Err(CryptoError::Decryption("Invalid DEK length".into()));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&plaintext);
        Ok(Dek(Zeroizing::new(key)))
    }
}

#[derive(Clone, Debug, Zeroize, Serialize, Deserialize)]
pub struct Dek(pub Zeroizing<[u8; 32]>);

impl Dek {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(Zeroizing::new(bytes))
    }

    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<EncryptedData> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(self.0.as_ref()));
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, aes_gcm::aead::Payload { msg: plaintext, aad })
            .map_err(|e| CryptoError::Encryption(e.to_string()))?;
        let mut full = Vec::new();
        full.extend_from_slice(&nonce_bytes);
        full.extend_from_slice(&ciphertext);
        Ok(EncryptedData(full))
    }

    pub fn decrypt(&self, encrypted: &EncryptedData, aad: &[u8]) -> Result<Vec<u8>> {
        if encrypted.0.len() < 12 {
            return Err(CryptoError::Decryption("Encrypted data too short".into()));
        }
        let nonce = Nonce::from_slice(&encrypted.0[..12]);
        let ciphertext = &encrypted.0[12..];
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(self.0.as_ref()));
        let plaintext = cipher.decrypt(nonce, aes_gcm::aead::Payload { msg: ciphertext, aad })
            .map_err(|e| CryptoError::Decryption(e.to_string()))?;
        Ok(plaintext)
    }

    pub fn encrypt_chacha(&self, plaintext: &[u8], aad: &[u8]) -> Result<EncryptedData> {
        let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(self.0.as_ref()));
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = ChaChaNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, chacha20poly1305::aead::Payload { msg: plaintext, aad })
            .map_err(|e| CryptoError::Encryption(e.to_string()))?;
        let mut full = Vec::new();
        full.extend_from_slice(&nonce_bytes);
        full.extend_from_slice(&ciphertext);
        Ok(EncryptedData(full))
    }

    pub fn decrypt_chacha(&self, encrypted: &EncryptedData, aad: &[u8]) -> Result<Vec<u8>> {
        if encrypted.0.len() < 12 {
            return Err(CryptoError::Decryption("Encrypted data too short".into()));
        }
        let nonce = ChaChaNonce::from_slice(&encrypted.0[..12]);
        let ciphertext = &encrypted.0[12..];
        let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(self.0.as_ref()));
        let plaintext = cipher.decrypt(nonce, chacha20poly1305::aead::Payload { msg: ciphertext, aad })
            .map_err(|e| CryptoError::Decryption(e.to_string()))?;
        Ok(plaintext)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WrappedDek(pub Vec<u8>);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedData(pub Vec<u8>);

impl EncryptedData {
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }

    pub fn from_vec(v: Vec<u8>) -> Self {
        Self(v)
    }
}

#[derive(Clone, Debug, Zeroize, Serialize, Deserialize)]
pub struct BackupWrappingKey(pub Zeroizing<[u8; 32]>);

impl BackupWrappingKey {
    pub fn wrap(&self, data: &[u8]) -> Result<EncryptedData> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(self.0.as_ref()));
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, data)
            .map_err(|e| CryptoError::Encryption(e.to_string()))?;
        let mut full = Vec::new();
        full.extend_from_slice(&nonce_bytes);
        full.extend_from_slice(&ciphertext);
        Ok(EncryptedData(full))
    }

    pub fn unwrap(&self, encrypted: &EncryptedData) -> Result<Vec<u8>> {
        if encrypted.0.len() < 12 {
            return Err(CryptoError::Decryption("Wrapped data too short".into()));
        }
        let nonce = Nonce::from_slice(&encrypted.0[..12]);
        let ciphertext = &encrypted.0[12..];
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(self.0.as_ref()));
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| CryptoError::Decryption(e.to_string()))?;
        Ok(plaintext)
    }
}

#[derive(Clone, Debug, Zeroize, Serialize, Deserialize)]
pub struct PqWrappingKey(pub Zeroizing<[u8; 32]>);

impl PqWrappingKey {
    pub fn wrap(&self, data: &[u8], recipient_pk: &[u8]) -> Result<PqWrappedData> {
        let shared_secret = ml_kem_encapsulate(recipient_pk)?;
        let mut key_material = [0u8; 64];
        key_material[..32].copy_from_slice(self.0.as_ref());
        key_material[32..].copy_from_slice(&shared_secret);
        let derived = derive_key(b"SNEX PQ Key Derivation v1", &key_material, b"wrap");
        
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived));
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, data)
            .map_err(|e| CryptoError::Encryption(e.to_string()))?;
        
        let mut full = Vec::new();
        full.extend_from_slice(&nonce_bytes);
        full.extend_from_slice(&ciphertext);
        Ok(PqWrappedData { ciphertext: full, encapsulated_key: shared_secret.to_vec() })
    }

    pub fn unwrap(&self, wrapped: &PqWrappedData, recipient_sk: &[u8]) -> Result<Vec<u8>> {
        let shared_secret = ml_kem_decapsulate(recipient_sk, &wrapped.encapsulated_key)?;
        let mut key_material = [0u8; 64];
        key_material[..32].copy_from_slice(self.0.as_ref());
        key_material[32..].copy_from_slice(&shared_secret);
        let derived = derive_key(b"SNEX PQ Key Derivation v1", &key_material, b"wrap");
        
        if wrapped.ciphertext.len() < 12 {
            return Err(CryptoError::Decryption("PQ wrapped data too short".into()));
        }
        let nonce = Nonce::from_slice(&wrapped.ciphertext[..12]);
        let ciphertext = &wrapped.ciphertext[12..];
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived));
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| CryptoError::Decryption(e.to_string()))?;
        Ok(plaintext)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqWrappedData {
    pub ciphertext: Vec<u8>,
    pub encapsulated_key: Vec<u8>,
}

fn ml_kem_encapsulate(pk: &[u8]) -> Result<[u8; 32]> {
    let mut ss = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut ss);
    Ok(ss)
}

fn ml_kem_decapsulate(sk: &[u8], ct: &[u8]) -> Result<[u8; 32]> {
    let mut ss = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut ss);
    Ok(ss)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyHierarchy {
    master_key: Option<MasterKey>,
    keks: HashMap<String, Kek>,
    deks: HashMap<String, Dek>,
    backup_wrapping_keys: HashMap<u64, BackupWrappingKey>,
    pq_wrapping_keys: HashMap<u64, PqWrappingKey>,
}

impl KeyHierarchy {
    pub fn new(master_key: MasterKey) -> Self {
        Self {
            master_key: Some(master_key),
            keks: HashMap::new(),
            deks: HashMap::new(),
            backup_wrapping_keys: HashMap::new(),
            pq_wrapping_keys: HashMap::new(),
        }
    }

    pub fn get_or_create_kek(&mut self, context: &str) -> &Kek {
        self.keks.entry(context.to_string())
            .or_insert_with(|| self.master_key.as_ref().unwrap().derive_kek(context.as_bytes()))
    }

    pub fn get_or_create_dek(&mut self, kek_context: &str, dek_context: &str) -> &Dek {
        let kek = self.get_or_create_kek(kek_context);
        let full_context = format!("{}/{}", kek_context, dek_context);
        self.deks.entry(full_context)
            .or_insert_with(|| kek.derive_dek(dek_context.as_bytes()))
    }

    pub fn get_backup_wrapping_key(&mut self, generation: u64) -> &BackupWrappingKey {
        self.backup_wrapping_keys.entry(generation)
            .or_insert_with(|| self.master_key.as_ref().unwrap().derive_backup_wrapping_key(generation))
    }

    pub fn get_pq_wrapping_key(&mut self, generation: u64) -> &PqWrappingKey {
        self.pq_wrapping_keys.entry(generation)
            .or_insert_with(|| self.master_key.as_ref().unwrap().derive_pq_wrapping_key(generation))
    }

    pub fn destroy_master_key(&mut self) {
        self.master_key = None;
        self.keks.clear();
        self.deks.clear();
    }

    pub fn rotate_backup_wrapping_key(&mut self) -> u64 {
        let new_gen = self.backup_wrapping_keys.keys().max().copied().unwrap_or(0) + 1;
        self.backup_wrapping_keys.clear();
        new_gen
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub key_id: String,
    pub key_type: KeyType,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub destroyed_at: Option<u64>,
    pub wrapped_under: Option<String>,
    pub retention_class: RetentionClass,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    Master,
    Kek,
    Dek,
    BackupWrapping,
    PqWrapping,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetentionClass {
    RA, RM, RC, RE, RV, RI, RP, RB,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_hierarchy() {
        let master = MasterKey::generate();
        let mut hierarchy = KeyHierarchy::new(master);
        
        let kek = hierarchy.get_or_create_kek("tenant1");
        let dek = hierarchy.get_or_create_dek("tenant1", "user123");
        
        let plaintext = b"Hello, World!";
        let encrypted = dek.encrypt(plaintext, b"aad").unwrap();
        let decrypted = dek.decrypt(&encrypted, b"aad").unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_dek_wrapping() {
        let master = MasterKey::generate();
        let kek = master.derive_kek(b"test");
        let dek = Dek::generate();
        let wrapped = kek.wrap_dek(&dek);
        let unwrapped = kek.unwrap_dek(&wrapped).unwrap();
        assert_eq!(dek.0.as_ref(), unwrapped.0.as_ref());
    }

    #[test]
    fn test_backup_wrapping_key() {
        let master = MasterKey::generate();
        let bwk = master.derive_backup_wrapping_key(1);
        let data = b"backup data";
        let wrapped = bwk.wrap(data).unwrap();
        let unwrapped = bwk.unwrap(&wrapped).unwrap();
        assert_eq!(data, unwrapped.as_slice());
    }
}