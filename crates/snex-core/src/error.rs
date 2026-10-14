use thiserror::Error;
use snex_crypto::error::CryptoError;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Already exists: {0}")]
    AlreadyExists(String),

    #[error("Invalid state transition: {0}")]
    InvalidStateTransition(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Tenant isolation violation: {0}")]
    TenantIsolationViolation(String),

    #[error("Anonymity set too small: need {min}, have {got}")]
    AnonymitySetTooSmall { min: u32, got: u32 },

    #[error("Build-up mode active: {reason}")]
    BuildUpMode { reason: String },

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Epoch mismatch: expected {expected}, got {got}")]
    EpochMismatch { expected: u64, got: u64 },

    #[error("Credential expired")]
    CredentialExpired,

    #[error("Credential not yet valid")]
    CredentialNotYetValid,

    #[error("Invalid credential")]
    InvalidCredential(String),

    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    #[error("Double vote detected")]
    DoubleVote,

    #[error("Double report detected")]
    DoubleReport,

    #[error("Pseudonym terminated")]
    PseudonymTerminated,

    #[error("Pseudonym blocked")]
    PseudonymBlocked,

    #[error("Verification provider error: {0}")]
    VerificationProvider(String),

    #[error("Governance key error: {0}")]
    GovernanceKey(String),

    #[error("MLS error: {0}")]
    Mls(String),

    #[error("Anchoring error: {0}")]
    Anchoring(String),

    #[error("Retention error: {0}")]
    Retention(String),

    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, CoreError>;