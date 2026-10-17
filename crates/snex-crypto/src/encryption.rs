use crate::error::{CryptoError, Result};
use crate::key_hierarchy::{Dek, PqWrappingKey, PqWrappedData};
pub use crate::key_hierarchy::EncryptedData;
use crate::hashing::Hash;
use x25519_dalek::PublicKey as X25519PublicKey;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use ml_kem::{MlKem768, MlKem1024, KemCore, EncodedSizeUser, Ciphertext as MlKemCiphertext};
use ml_kem::kem::{Encapsulate, Decapsulate};
use ml_kem::array::Array;
use rand::RngCore;
use serde::{Serialize, Deserialize, ser::SerializeStruct};
use zeroize::{Zeroize, Zeroizing};

pub const TLS_HYBRID_LABEL: &[u8] = b"SNEX TLS Hybrid v1";
pub const PQ_HYBRID_LABEL: &[u8] = b"SNEX PQ Hybrid v1";

#[derive(Clone, Debug, Zeroize)]
pub struct X25519KeyPair {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

impl X25519KeyPair {
    pub fn generate() -> Self {
        let mut private = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut private);
        let public = x25519_dalek::x25519(private, [9u8; 32]);
        Self { private, public }
    }

    pub fn from_private(private: [u8; 32]) -> Self {
        let public = x25519_dalek::x25519(private, [9u8; 32]);
        Self { private, public }
    }

    pub fn diffie_hellman(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        x25519_dalek::x25519(self.private, *peer_public)
    }
}

impl Serialize for X25519KeyPair {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("X25519KeyPair", 2)?;
        state.serialize_field("private", &self.private)?;
        state.serialize_field("public", &self.public)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for X25519KeyPair {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct X25519KeyPairHelper {
            private: [u8; 32],
            public: [u8; 32],
        }
        let helper = X25519KeyPairHelper::deserialize(deserializer)?;
        Ok(Self { private: helper.private, public: helper.public })
    }
}

#[derive(Clone, Debug)]
pub struct Ed25519KeyPair {
    pub private: SigningKey,
    pub public: VerifyingKey,
}

impl Ed25519KeyPair {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let private = SigningKey::from_bytes(&bytes);
        let public = private.verifying_key();
        Self { private, public }
    }

    pub fn from_private(private: SigningKey) -> Self {
        let public = private.verifying_key();
        Self { private, public }
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.private.sign(msg)
    }

    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<()> {
        self.public.verify(msg, sig)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }
}

impl Serialize for Ed25519KeyPair {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("Ed25519KeyPair", 2)?;
        state.serialize_field("private", &self.private.to_bytes())?;
        state.serialize_field("public", &self.public.to_bytes())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Ed25519KeyPair {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Ed25519KeyPairHelper {
            private: [u8; 32],
            public: [u8; 32],
        }
        let helper = Ed25519KeyPairHelper::deserialize(deserializer)?;
        let private = SigningKey::from_bytes(&helper.private);
        let public = VerifyingKey::from_bytes(&helper.public)
            .map_err(serde::de::Error::custom)?;
        Ok(Self { private, public })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MlKem768KeyPair {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

impl MlKem768KeyPair {
    pub fn generate() -> Result<Self> {
        let mut rng = rand::rngs::OsRng;
        let (dk, ek) = MlKem768::generate(&mut rng);
        Ok(Self {
            public: ek.as_bytes().as_slice().to_vec(),
            private: dk.as_bytes().as_slice().to_vec(),
        })
    }

    pub fn encapsulate(&self) -> Result<(Vec<u8>, [u8; 32])> {
        let ek_bytes: &Array<_, _> = self.public.as_slice().try_into()
            .map_err(|_| CryptoError::PostQuantumWrapper("Invalid ML-KEM-768 public key length".into()))?;
        let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(ek_bytes);
        let mut rng = rand::rngs::OsRng;
        let (ct, ss) = ek.encapsulate(&mut rng)
            .map_err(|_| CryptoError::PostQuantumWrapper("ML-KEM-768 encapsulation failed".into()))?;
        let ss_bytes: [u8; 32] = ss.as_slice().try_into()
            .map_err(|_| CryptoError::PostQuantumWrapper("Invalid shared key length".into()))?;
        Ok((ct.as_slice().to_vec(), ss_bytes))
    }

    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; 32]> {
        let dk_bytes: &Array<_, _> = self.private.as_slice().try_into()
            .map_err(|_| CryptoError::PostQuantumWrapper("Invalid ML-KEM-768 secret key length".into()))?;
        let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(dk_bytes);
        let ct: &MlKemCiphertext<MlKem768> = ciphertext.try_into()
            .map_err(|_| CryptoError::PostQuantumWrapper("Invalid ML-KEM-768 ciphertext".into()))?;
        let ss = dk.decapsulate(ct)
            .map_err(|_| CryptoError::PostQuantumWrapper("ML-KEM-768 decapsulation failed".into()))?;
        let ss_bytes: [u8; 32] = ss.as_slice().try_into()
            .map_err(|_| CryptoError::PostQuantumWrapper("Invalid shared key length".into()))?;
        Ok(ss_bytes)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MlKem1024KeyPair {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

impl MlKem1024KeyPair {
    pub fn generate() -> Result<Self> {
        let mut rng = rand::rngs::OsRng;
        let (dk, ek) = MlKem1024::generate(&mut rng);
        Ok(Self {
            public: ek.as_bytes().as_slice().to_vec(),
            private: dk.as_bytes().as_slice().to_vec(),
        })
    }

    pub fn encapsulate(&self) -> Result<(Vec<u8>, [u8; 32])> {
        let ek_bytes: &Array<_, _> = self.public.as_slice().try_into()
            .map_err(|_| CryptoError::PostQuantumWrapper("Invalid ML-KEM-1024 public key length".into()))?;
        let ek = <MlKem1024 as KemCore>::EncapsulationKey::from_bytes(ek_bytes);
        let mut rng = rand::rngs::OsRng;
        let (ct, ss) = ek.encapsulate(&mut rng)
            .map_err(|_| CryptoError::PostQuantumWrapper("ML-KEM-1024 encapsulation failed".into()))?;
        let ss_bytes: [u8; 32] = ss.as_slice().try_into()
            .map_err(|_| CryptoError::PostQuantumWrapper("Invalid shared key length".into()))?;
        Ok((ct.as_slice().to_vec(), ss_bytes))
    }

    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; 32]> {
        let dk_bytes: &Array<_, _> = self.private.as_slice().try_into()
            .map_err(|_| CryptoError::PostQuantumWrapper("Invalid ML-KEM-1024 secret key length".into()))?;
        let dk = <MlKem1024 as KemCore>::DecapsulationKey::from_bytes(dk_bytes);
        let ct: &MlKemCiphertext<MlKem1024> = ciphertext.try_into()
            .map_err(|_| CryptoError::PostQuantumWrapper("Invalid ML-KEM-1024 ciphertext".into()))?;
        let ss = dk.decapsulate(ct)
            .map_err(|_| CryptoError::PostQuantumWrapper("ML-KEM-1024 decapsulation failed".into()))?;
        let ss_bytes: [u8; 32] = ss.as_slice().try_into()
            .map_err(|_| CryptoError::PostQuantumWrapper("Invalid shared key length".into()))?;
        Ok(ss_bytes)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MlDsaKeyPair {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

impl MlDsaKeyPair {
    pub fn generate() -> Result<Self> {
        use ml_dsa::Keypair;
        let mut seed_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed_bytes);
        let seed = ml_dsa::Seed::try_from(&seed_bytes[..])
            .map_err(|_| CryptoError::PostQuantumWrapper("Invalid seed length".into()))?;
        let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&seed);
        let pk = sk.verifying_key();
        Ok(Self {
            public: pk.encode().as_slice().to_vec(),
            private: sk.to_seed().as_slice().to_vec(),
        })
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        use ml_dsa::Signer;
        let seed = ml_dsa::Seed::try_from(self.private.as_slice())
            .map_err(|_| CryptoError::PostQuantumWrapper("Invalid ML-DSA secret key length".into()))?;
        let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&seed);
        let sig = sk.try_sign(msg)
            .map_err(|_| CryptoError::PostQuantumWrapper("ML-DSA signing failed".into()))?;
        Ok(sig.encode().as_slice().to_vec())
    }

    pub fn verify(public: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool> {
        use ml_dsa::Verifier;
        let pk_enc = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa65>::try_from(public)
            .map_err(|_| CryptoError::PostQuantumWrapper("Invalid ML-DSA public key length".into()))?;
        let pk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(&pk_enc);
        let sig = ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(sig)
            .map_err(|_| CryptoError::PostQuantumWrapper("Invalid ML-DSA signature".into()))?;
        Ok(pk.verify(msg, &sig).is_ok())
    }
}

pub fn hybrid_key_exchange(
    our_x25519: &X25519KeyPair,
    our_mlkem768: &MlKem768KeyPair,
    peer_x25519_pk: &[u8; 32],
    peer_mlkem768_pk: &[u8],
) -> Result<[u8; 32]> {
    let x25519_shared = our_x25519.diffie_hellman(peer_x25519_pk);
    let (_, mlkem_shared) = our_mlkem768.encapsulate()?;

    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(&x25519_shared);
    combined[32..].copy_from_slice(&mlkem_shared);

    let derived = crate::hashing::derive_key(TLS_HYBRID_LABEL, &combined, b"session");
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
    use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(pq_wrapping_key.0.as_ref()));
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

pub fn server_side_pq_unwrap(
    pq_wrapping_key: &PqWrappingKey,
    encrypted: &EncryptedData,
) -> Result<Vec<u8>> {
    use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
    if encrypted.0.len() < 12 {
        return Err(CryptoError::Decryption("Server PQ wrapped data too short".into()));
    }
    let nonce = Nonce::from_slice(&encrypted.0[..12]);
    let ciphertext = &encrypted.0[12..];
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(pq_wrapping_key.0.as_ref()));
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| CryptoError::Decryption(e.to_string()))?;
    Ok(plaintext)
}

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
    let ed_sig_bytes: [u8; 64] = sig.ed25519.as_slice().try_into()
        .map_err(|_| CryptoError::InvalidSignature)?;
    let ed_sig = ed25519_dalek::Signature::from_bytes(&ed_sig_bytes);
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
