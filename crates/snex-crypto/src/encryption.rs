use crate::error::{CryptoError, Result};
use crate::key_hierarchy::{Dek, EncryptedData, PqWrappingKey, PqWrappedData};
use crate::hashing::Hash;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret, EphemeralSecret};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use ml_kem::{MlKem768, MlKem1024};
use rand::RngCore;
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, Zeroizing};

pub const TLS_HYBRID_LABEL: &[u8] = b"SNEX TLS Hybrid v1";
pub const PQ_HYBRID_LABEL: &[u8] = b"SNEX PQ Hybrid v1";

#[derive(Clone, Debug, Zeroize, Serialize, Deserialize)]
pub struct X25519KeyPair {
    pub private: Zeroizing<X25519StaticSecret>,
    pub public: X25519PublicKey,
}

impl X25519KeyPair {
    pub fn generate() -> Self {
        let private = X25519StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = X25519PublicKey::from(&private);
        Self { private: Zeroizing::new(private), public }
    }

    pub fn from_private(private: X25519StaticSecret) -> Self {
        let public = X25519PublicKey::from(&private);
        Self { private: Zeroizing::new(private), public }
    }

    pub fn diffie_hellman(&self, peer_public: &X25519PublicKey) -> [u8; 32] {
        self.private.diffie_hellman(peer_public).to_bytes()
    }
}

#[derive(Clone, Debug, Zeroize, Serialize, Deserialize)]
pub struct Ed25519KeyPair {
    pub private: Zeroizing<SigningKey>,
    pub public: VerifyingKey,
}

impl Ed25519KeyPair {
    pub fn generate() -> Self {
        let private = SigningKey::generate(&mut rand::rngs::OsRng);
        let public = private.verifying_key();
        Self { private: Zeroizing::new(private), public }
    }

    pub fn from_private(private: SigningKey) -> Self {
        let public = private.verifying_key();
        Self { private: Zeroizing::new(private), public }
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.private.sign(msg)
    }

    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<()> {
        self.public.verify(msg, sig)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MlKem768KeyPair {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

impl MlKem768KeyPair {
    pub fn generate() -> Result<Self> {
        let (pk, sk) = MlKem768::keygen();
        Ok(Self {
            public: pk.to_vec(),
            private: sk.to_vec(),
        })
    }

    pub fn encapsulate(&self) -> Result<(Vec<u8>, [u8; 32])> {
        let pk = MlKem768::PublicKey::from_bytes(&self.public)
            .map_err(|_| CryptoError::PostQuantumWrapper("Invalid ML-KEM-768 public key".into()))?;
        let (ct, ss) = MlKem768::encapsulate(&pk);
        Ok((ct.to_vec(), ss.into()))
    }

    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; 32]> {
        let sk = MlKem768::SecretKey::from_bytes(&self.private)
            .map_err(|_| CryptoError::PostQuantumWrapper("Invalid ML-KEM-768 secret key".into()))?;
        let ct = MlKem768::Ciphertext::from_bytes(ciphertext)
            .map_err(|_| CryptoError::PostQuantumWrapper("Invalid ML-KEM-768 ciphertext".into()))?;
        let ss = MlKem768::decapsulate(&sk, &ct);
        Ok(ss.into())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MlKem1024KeyPair {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

impl MlKem1024KeyPair {
    pub fn generate() -> Result<Self> {
        let (pk, sk) = MlKem1024::keygen();
        Ok(Self {
            public: pk.to_vec(),
            private: sk.to_vec(),
        })
    }

    pub fn encapsulate(&self) -> Result<(Vec<u8>, [u8; 32])> {
        let pk = MlKem1024::PublicKey::from_bytes(&self.public)
            .map_err(|_| CryptoError::PostQuantumWrapper("Invalid ML-KEM-1024 public key".into()))?;
        let (ct, ss) = MlKem1024::encapsulate(&pk);
        Ok((ct.to_vec(), ss.into()))
    }

    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; 32]> {
        let sk = MlKem1024::SecretKey::from_bytes(&self.private)
            .map_err(|_| CryptoError::PostQuantumWrapper("Invalid ML-KEM-1024 secret key".into()))?;
        let ct = MlKem1024::Ciphertext::from_bytes(ciphertext)
            .map_err(|_| CryptoError::PostQuantumWrapper("Invalid ML-KEM-1024 ciphertext".into()))?;
        let ss = MlKem1024::decapsulate(&sk, &ct);
        Ok(ss.into())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MlDsaKeyPair {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

impl MlDsaKeyPair {
    pub fn generate() -> Result<Self> {
        let (pk, sk) = ml_dsa::MlDsa65::keygen();
        Ok(Self {
            public: pk.to_vec(),
            private: sk.to_vec(),
        })
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let sk = ml_dsa::MlDsa65::SecretKey::from_bytes(&self.private)
            .map_err(|_| CryptoError::PostQuantumWrapper("Invalid ML-DSA secret key".into()))?;
        let sig = ml_dsa::MlDsa65::sign(&sk, msg);
        Ok(sig.to_vec())
    }

    pub fn verify(public: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool> {
        let pk = ml_dsa::MlDsa65::PublicKey::from_bytes(public)
            .map_err(|_| CryptoError::PostQuantumWrapper("Invalid ML-DSA public key".into()))?;
        let sig = ml_dsa::MlDsa65::Signature::from_bytes(sig)
            .map_err(|_| CryptoError::PostQuantumWrapper("Invalid ML-DSA signature".into()))?;
        Ok(ml_dsa::MlDsa65::verify(&pk, msg, &sig).is_ok())
    }
}

pub fn hybrid_key_exchange(
    our_x25519: &X25519KeyPair,
    our_mlkem768: &MlKem768KeyPair,
    peer_x25519_pk: &X25519PublicKey,
    peer_mlkem768_pk: &[u8],
) -> Result<[u8; 64]> {
    let x25519_shared = our_x25519.diffie_hellman(peer_x25519_pk);
    let (_, mlkem_shared) = our_mlkem768.encapsulate()?;
    
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(&x25519_shared);
    combined[32..].copy_from_slice(&mlkem_shared);
    
    let derived = crate::kdf::derive_key(TLS_HYBRID_LABEL, &combined, b"session");
    Ok(derived)
}

pub fn hybrid_encrypt(
    dek: &Dek,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedData> {
    dek.encrypt(plaintext, aad)
}

pub fn hybrid_decrypt(
    dek: &Dek,
    encrypted: &EncryptedData,
    aad: &[u8],
) -> Result<Vec<u8>> {
    dek.decrypt(encrypted, aad)
}

pub fn client_side_pq_wrap(
    pq_wrapping_key: &PqWrappingKey,
    data: &[u8],
    recipient_mlkem1024_pk: &[u8],
) -> Result<PqWrappedData> {
    pq_wrapping_key.wrap(data, recipient_mlkem1024_pk)
}

pub fn client_side_pq_unwrap(
    pq_wrapping_key: &PqWrappingKey,
    wrapped: &PqWrappedData,
    recipient_mlkem1024_sk: &[u8],
) -> Result<Vec<u8>> {
    pq_wrapping_key.unwrap(wrapped, recipient_mlkem1024_sk)
}

pub fn server_side_pq_wrap(
    pq_wrapping_key: &PqWrappingKey,
    data: &[u8],
) -> Result<EncryptedData> {
    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(pq_wrapping_key.0.as_ref()));
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, data)
        .map_err(|e| CryptoError::Encryption(e.to_string()))?;
    let mut full = Vec::new();
    full.extend_from_slice(&nonce_bytes);
    full.extend_from_slice(&ciphertext);
    Ok(EncryptedData(full))
}

pub fn server_side_pq_unwrap(
    pq_wrapping_key: &PqWrappingKey,
    encrypted: &EncryptedData,
) -> Result<Vec<u8>> {
    if encrypted.0.len() < 12 {
        return Err(CryptoError::Decryption("Server PQ wrapped data too short".into()));
    }
    let nonce = aes_gcm::Nonce::from_slice(&encrypted.0[..12]);
    let ciphertext = &encrypted.0[12..];
    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(pq_wrapping_key.0.as_ref()));
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| CryptoError::Decryption(e.to_string()))?;
    Ok(plaintext)
}

use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};

pub fn sign_with_both(
    ed25519_kp: &Ed25519KeyPair,
    ml_dsa_kp: &MlDsaKeyPair,
    msg: &[u8],
) -> Result<HybridSignature> {
    let ed_sig = ed25519_kp.sign(msg);
    let ml_sig = ml_dsa_kp.sign(msg)?;
    Ok(HybridSignature {
        ed25519: ed_sig.to_bytes().to_vec(),
        ml_dsa: ml_sig,
    })
}

pub fn verify_with_both(
    ed25519_pk: &VerifyingKey,
    ml_dsa_pk: &[u8],
    msg: &[u8],
    sig: &HybridSignature,
) -> Result<bool> {
    let ed_sig = ed25519_dalek::Signature::from_bytes(&sig.ed25519)
        .map_err(|_| CryptoError::InvalidSignature)?;
    ed25519_pk.verify(msg, &ed_sig)
        .map_err(|_| CryptoError::SignatureVerificationFailed)?;
    
    let ml_ok = MlDsaKeyPair::verify(ml_dsa_pk, msg, &sig.ml_dsa)?;
    
    Ok(ml_ok)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HybridSignature {
    pub ed25519: Vec<u8>,
    pub ml_dsa: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_dh() {
        let alice = X25519KeyPair::generate();
        let bob = X25519KeyPair::generate();
        let shared1 = alice.diffie_hellman(&bob.public);
        let shared2 = bob.diffie_hellman(&alice.public);
        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_ed25519_sign_verify() {
        let kp = Ed25519KeyPair::generate();
        let msg = b"test message";
        let sig = kp.sign(msg);
        kp.verify(msg, &sig).unwrap();
    }

    #[test]
    fn test_ml_kem_768() {
        let kp = MlKem768KeyPair::generate().unwrap();
        let (ct, ss1) = kp.encapsulate().unwrap();
        let ss2 = kp.decapsulate(&ct).unwrap();
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_hybrid_key_exchange() {
        let alice_x25519 = X25519KeyPair::generate();
        let alice_mlkem = MlKem768KeyPair::generate().unwrap();
        let bob_x25519 = X25519KeyPair::generate();
        let bob_mlkem = MlKem768KeyPair::generate().unwrap();
        
        let alice_shared = hybrid_key_exchange(
            &alice_x25519, &alice_mlkem,
            &bob_x25519.public, &bob_mlkem.public
        ).unwrap();
        
        let bob_shared = hybrid_key_exchange(
            &bob_x25519, &bob_mlkem,
            &alice_x25519.public, &alice_mlkem.public
        ).unwrap();
        
        assert_eq!(alice_shared, bob_shared);
    }
}