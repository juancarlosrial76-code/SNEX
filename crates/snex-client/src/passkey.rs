use snex_core::error::{CoreError, Result};
use serde::{Serialize, Deserialize};
use uuid::Uuid;

pub const WEBAUTHN_NOT_AVAILABLE: &str = "webauthn not available in this build";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasskeyCredential {
    pub id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub aaguid: Option<Vec<u8>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasskeyRegistration {
    pub rp_id: String,
    pub user_handle: Vec<u8>,
    pub challenge: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub attestation_object: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasskeyAuthentication {
    pub rp_id: String,
    pub challenge: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub signature: Vec<u8>,
}

fn webauthn_unavailable() -> CoreError {
    CoreError::Internal(WEBAUTHN_NOT_AVAILABLE.to_string())
}

pub struct PasskeyManager {
    rp_id: String,
    rp_name: String,
}

impl PasskeyManager {
    pub fn new(rp_id: String, rp_name: String) -> Self {
        Self { rp_id, rp_name }
    }

    fn derive_challenge(&self, context: &[u8]) -> Vec<u8> {
        let mut seed = Vec::with_capacity(self.rp_id.len() + context.len() + 32);
        seed.extend_from_slice(self.rp_id.as_bytes());
        seed.extend_from_slice(context);
        seed.extend_from_slice(&rand::random::<[u8; 32]>());
        snex_crypto::hashing::Hash::with_domain(b"SNEX/PASSKEY_CHALLENGE/v1", &seed).0.to_vec()
    }

    fn client_data_json(&self, challenge: &[u8], kind: &str) -> Vec<u8> {
        format!(
            r#"{{"type":"webauthn.{}","challenge":"{}","origin":"https://{}"}}"#,
            kind,
            base64url(challenge),
            self.rp_id
        )
        .into_bytes()
    }

    pub fn create_registration_options(
        &self,
        user_id: &[u8],
        _username: &str,
        _display_name: &str,
    ) -> Result<PasskeyRegistration> {
        let challenge = self.derive_challenge(user_id);
        let client_data_json = self.client_data_json(&challenge, "create");
        let credential_id = snex_crypto::hashing::Hash::with_domain(b"SNEX/PASSKEY_CREDENTIAL_ID/v1", &challenge).0.to_vec();

        Ok(PasskeyRegistration {
            rp_id: self.rp_id.clone(),
            user_handle: user_id.to_vec(),
            challenge,
            client_data_json,
            credential_id,
            public_key: Vec::new(),
            attestation_object: Vec::new(),
        })
    }

    pub fn finish_registration(&self, _registration: PasskeyRegistration) -> Result<PasskeyCredential> {
        Err(webauthn_unavailable())
    }

    pub fn create_authentication_options(&self) -> Result<PasskeyAuthentication> {
        let challenge = self.derive_challenge(b"authentication");
        let client_data_json = self.client_data_json(&challenge, "get");

        Ok(PasskeyAuthentication {
            rp_id: self.rp_id.clone(),
            challenge,
            client_data_json,
            authenticator_data: Vec::new(),
            credential_id: Vec::new(),
            signature: Vec::new(),
        })
    }

    pub fn finish_authentication(
        &self,
        _authentication: PasskeyAuthentication,
        _credentials: &[PasskeyCredential],
    ) -> Result<PasskeyCredential> {
        Err(webauthn_unavailable())
    }
}

fn base64url(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 63] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passkey_manager() {
        let manager = PasskeyManager::new("localhost".into(), "SNEX".into());
        assert_eq!(manager.rp_id, "localhost");
    }

    #[test]
    fn test_registration_options_placeholder() {
        let manager = PasskeyManager::new("localhost".into(), "SNEX".into());
        let options = manager.create_registration_options(b"user-1", "alice", "Alice").unwrap();
        assert_eq!(options.challenge.len(), 32);
        assert_eq!(manager.finish_registration(options).unwrap_err().to_string(),
            format!("Internal error: {}", WEBAUTHN_NOT_AVAILABLE));
    }
}
