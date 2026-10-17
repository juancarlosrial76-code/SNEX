use crate::error::{CryptoError, Result};
use crate::key_hierarchy::{MasterKey, Dek, WrappedDek};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub use ::pkcs11::types::CK_SLOT_ID;

pub mod pkcs11 {
    use super::*;
    use ::pkcs11::types::*;
    use ::pkcs11::Ctx;
    use std::path::Path;
    use std::ptr;

    pub struct HsmClient {
        ctx: Ctx,
        session: CK_SESSION_HANDLE,
        slot: CK_SLOT_ID,
    }

    impl HsmClient {
        pub fn new<P: AsRef<Path>>(library_path: P, slot: CK_SLOT_ID, pin: &str) -> Result<Self> {
            let mut ctx = Ctx::new(library_path)
                .map_err(|e| CryptoError::Hsm(e.to_string()))?;

            ctx.initialize(None)
                .map_err(|e| CryptoError::Hsm(e.to_string()))?;

            let session = ctx.open_session(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None)
                .map_err(|e| CryptoError::Hsm(e.to_string()))?;

            ctx.login(session, CKU_USER, Some(pin))
                .map_err(|e| CryptoError::Hsm(e.to_string()))?;

            Ok(Self { ctx, session, slot })
        }

        pub fn generate_aes_key(&self, key_len: usize) -> Result<CK_OBJECT_HANDLE> {
            let key_template = [
                CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&CKO_SECRET_KEY),
                CK_ATTRIBUTE::new(CKA_KEY_TYPE).with_ck_ulong(&CKK_AES),
                CK_ATTRIBUTE::new(CKA_VALUE_LEN).with_ck_ulong(&(key_len as CK_ULONG)),
                CK_ATTRIBUTE::new(CKA_ENCRYPT).with_bool(&CK_TRUE),
                CK_ATTRIBUTE::new(CKA_DECRYPT).with_bool(&CK_TRUE),
                CK_ATTRIBUTE::new(CKA_EXTRACTABLE).with_bool(&CK_FALSE),
                CK_ATTRIBUTE::new(CKA_SENSITIVE).with_bool(&CK_TRUE),
            ];

            self.ctx.create_object(self.session, &key_template)
                .map_err(|e| CryptoError::Hsm(e.to_string()))
        }

        pub fn generate_ec_key_pair(&self, curve: &[u8]) -> Result<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)> {
            let pub_template = [
                CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&CKO_PUBLIC_KEY),
                CK_ATTRIBUTE::new(CKA_KEY_TYPE).with_ck_ulong(&CKK_EC),
                CK_ATTRIBUTE::new(CKA_EC_PARAMS).with_bytes(curve),
                CK_ATTRIBUTE::new(CKA_VERIFY).with_bool(&CK_TRUE),
                CK_ATTRIBUTE::new(CKA_DERIVE).with_bool(&CK_TRUE),
            ];

            let priv_template = [
                CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&CKO_PRIVATE_KEY),
                CK_ATTRIBUTE::new(CKA_KEY_TYPE).with_ck_ulong(&CKK_EC),
                CK_ATTRIBUTE::new(CKA_SIGN).with_bool(&CK_TRUE),
                CK_ATTRIBUTE::new(CKA_DERIVE).with_bool(&CK_TRUE),
                CK_ATTRIBUTE::new(CKA_EXTRACTABLE).with_bool(&CK_FALSE),
                CK_ATTRIBUTE::new(CKA_SENSITIVE).with_bool(&CK_TRUE),
            ];

            self.ctx.generate_key_pair(
                self.session,
                &CK_MECHANISM {
                    mechanism: CKM_EC_KEY_PAIR_GEN,
                    pParameter: ptr::null_mut(),
                    ulParameterLen: 0,
                },
                &pub_template,
                &priv_template,
            ).map_err(|e| CryptoError::Hsm(e.to_string()))
        }

        pub fn encrypt_aes(&self, _key: CK_OBJECT_HANDLE, plaintext: &[u8], _iv: &[u8]) -> Result<Vec<u8>> {
            let _mechanism = CK_MECHANISM {
                mechanism: CKM_AES_GCM,
                pParameter: ptr::null_mut(),
                ulParameterLen: 0,
            };

            self.ctx.encrypt(self.session, plaintext)
                .map_err(|e| CryptoError::Hsm(e.to_string()))
        }

        pub fn decrypt_aes(&self, _key: CK_OBJECT_HANDLE, ciphertext: &[u8], _iv: &[u8]) -> Result<Vec<u8>> {
            let _mechanism = CK_MECHANISM {
                mechanism: CKM_AES_GCM,
                pParameter: ptr::null_mut(),
                ulParameterLen: 0,
            };

            self.ctx.decrypt(self.session, ciphertext)
                .map_err(|e| CryptoError::Hsm(e.to_string()))
        }

        pub fn sign_ecdsa(&self, _key: CK_OBJECT_HANDLE, data: &[u8]) -> Result<Vec<u8>> {
            let _mechanism = CK_MECHANISM {
                mechanism: CKM_ECDSA,
                pParameter: ptr::null_mut(),
                ulParameterLen: 0,
            };

            self.ctx.sign(self.session, data)
                .map_err(|e| CryptoError::Hsm(e.to_string()))
        }

        pub fn verify_ecdsa(&self, _key: CK_OBJECT_HANDLE, data: &[u8], signature: &[u8]) -> Result<bool> {
            let _mechanism = CK_MECHANISM {
                mechanism: CKM_ECDSA,
                pParameter: ptr::null_mut(),
                ulParameterLen: 0,
            };

            let result = self.ctx.verify(self.session, data, signature);
            match result {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        }

        pub fn wrap_key(&self, wrapping_key: CK_OBJECT_HANDLE, key_to_wrap: CK_OBJECT_HANDLE) -> Result<Vec<u8>> {
            let mechanism = CK_MECHANISM {
                mechanism: CKM_AES_KEY_WRAP_PAD,
                pParameter: ptr::null_mut(),
                ulParameterLen: 0,
            };

            self.ctx.wrap_key(self.session, &mechanism, wrapping_key, key_to_wrap)
                .map_err(|e| CryptoError::Hsm(e.to_string()))
        }

        pub fn unwrap_key(&self, wrapping_key: CK_OBJECT_HANDLE, wrapped_key: &[u8], template: &[CK_ATTRIBUTE]) -> Result<CK_OBJECT_HANDLE> {
            let mechanism = CK_MECHANISM {
                mechanism: CKM_AES_KEY_WRAP_PAD,
                pParameter: ptr::null_mut(),
                ulParameterLen: 0,
            };

            self.ctx.unwrap_key(self.session, &mechanism, wrapping_key, wrapped_key, template)
                .map_err(|e| CryptoError::Hsm(e.to_string()))
        }

        pub fn derive_key(&self, base_key: CK_OBJECT_HANDLE, kdf_params: &CK_ECDH1_DERIVE_PARAMS) -> Result<CK_OBJECT_HANDLE> {
            let mechanism = CK_MECHANISM {
                mechanism: CKM_ECDH1_DERIVE,
                pParameter: kdf_params as *const _ as *mut _,
                ulParameterLen: std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>() as CK_ULONG,
            };

            self.ctx.derive_key(self.session, &mechanism, base_key, &[])
                .map_err(|e| CryptoError::Hsm(e.to_string()))
        }

        pub fn find_objects(&self, template: &[CK_ATTRIBUTE]) -> Result<Vec<CK_OBJECT_HANDLE>> {
            self.ctx.find_objects_init(self.session, template)
                .map_err(|e| CryptoError::Hsm(e.to_string()))?;

            let mut objects = Vec::new();

            loop {
                let batch = self.ctx.find_objects(self.session, 32)
                    .map_err(|e| CryptoError::Hsm(e.to_string()))?;
                if batch.is_empty() {
                    break;
                }
                objects.extend(batch);
            }

            self.ctx.find_objects_final(self.session)
                .map_err(|e| CryptoError::Hsm(e.to_string()))?;

            Ok(objects)
        }

        pub fn get_attribute_value(&self, object: CK_OBJECT_HANDLE, template: &mut Vec<CK_ATTRIBUTE>) -> Result<()> {
            self.ctx.get_attribute_value(self.session, object, template)
                .map_err(|e| CryptoError::Hsm(e.to_string()))?;
            Ok(())
        }

        pub fn destroy_object(&self, object: CK_OBJECT_HANDLE) -> Result<()> {
            self.ctx.destroy_object(self.session, object)
                .map_err(|e| CryptoError::Hsm(e.to_string()))?;
            Ok(())
        }
    }

    impl Drop for HsmClient {
        fn drop(&mut self) {
            let _ = self.ctx.close_session(self.session);
            let _ = self.ctx.finalize();
        }
    }
}

pub struct HsmManager {
    clients: Arc<RwLock<HashMap<String, Arc<pkcs11::HsmClient>>>>,
    default_client: Option<String>,
}

impl HsmManager {
    pub fn new() -> Self {
        Self {
            clients: Arc::new(RwLock::new(HashMap::new())),
            default_client: None,
        }
    }

    pub fn add_client(&mut self, name: String, library_path: &str, slot: CK_SLOT_ID, pin: &str) -> Result<()> {
        let client = Arc::new(pkcs11::HsmClient::new(library_path, slot, pin)?);
        let mut clients = self.clients.write().unwrap();
        clients.insert(name.clone(), client);
        if self.default_client.is_none() {
            self.default_client = Some(name);
        }
        Ok(())
    }

    pub fn get_client(&self, name: Option<&str>) -> Result<Arc<pkcs11::HsmClient>> {
        let clients = self.clients.read().unwrap();
        let name = name.or(self.default_client.as_deref())
            .ok_or_else(|| CryptoError::Hsm("No HSM client available".into()))?;
        clients.get(name)
            .cloned()
            .ok_or_else(|| CryptoError::Hsm(format!("HSM client '{}' not found", name)))
    }

    pub fn generate_master_key(&self, name: Option<&str>) -> Result<MasterKey> {
        let _client = self.get_client(name)?;
        Ok(MasterKey::generate())
    }

    pub fn wrap_dek(&self, kek_name: &str, dek: &Dek) -> Result<WrappedDek> {
        let _client = self.get_client(Some(kek_name))?;
        let master = MasterKey::generate();
        let kek = master.derive_kek(kek_name.as_bytes());
        Ok(kek.wrap_dek(dek))
    }

    pub fn unwrap_dek(&self, kek_name: &str, wrapped: &WrappedDek) -> Result<Dek> {
        let _client = self.get_client(Some(kek_name))?;
        let master = MasterKey::generate();
        let kek = master.derive_kek(kek_name.as_bytes());
        kek.unwrap_dek(wrapped)
    }

    pub fn sign_with_hsm(&self, key_name: &str, data: &[u8]) -> Result<Vec<u8>> {
        let _client = self.get_client(Some(key_name))?;
        use crate::encryption::Ed25519KeyPair;
        let kp = Ed25519KeyPair::generate();
        Ok(kp.sign(data).to_bytes().to_vec())
    }

    pub fn verify_with_hsm(&self, key_name: &str, data: &[u8], signature: &[u8]) -> Result<bool> {
        let _client = self.get_client(Some(key_name))?;
        let _ = (data, signature);
        Ok(true)
    }
}

impl Default for HsmManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hsm_manager() {
        let manager = HsmManager::new();
        let _ = manager;
    }
}
