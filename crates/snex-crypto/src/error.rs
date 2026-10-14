use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Invalid secret key")]
    InvalidSecretKey,

    #[error("Invalid commitment")]
    InvalidCommitment,

    #[error("Invalid nullifier")]
    InvalidNullifier,

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Key derivation error: {0}")]
    KeyDerivation(String),

    #[error("Invalid epoch")]
    InvalidEpoch,

    #[error("Epoch mismatch")]
    EpochMismatch,

    #[error("Batch size too small: need at least {min}, got {got}")]
    BatchSizeTooSmall { min: usize, got: usize },

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Invalid proof")]
    InvalidProof,

    #[error("Invalid witness")]
    InvalidWitness,

    #[error("Commitment opening failed")]
    CommitmentOpeningFailed,

    #[error("HSM error: {0}")]
    Hsm(String),

    #[error("Post-quantum wrapper error: {0}")]
    PostQuantumWrapper(String),

    #[error("MLS error: {0}")]
    Mls(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;