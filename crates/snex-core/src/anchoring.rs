use snex_crypto::hashing::Hash;
use crate::error::{CoreError, Result};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use std::collections::VecDeque;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: Uuid,
    pub sequence: u64,
    pub previous_hash: Hash,
    pub hash: Hash,
    pub timestamp: DateTime<Utc>,
    pub component: String,
    pub action: String,
    pub data: serde_json::Value,
    pub tenant_id: Option<Uuid>,
    pub epoch: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditChain {
    pub entries: VecDeque<AuditEntry>,
    pub head: Hash,
    pub length: u64,
    pub anchored_hashes: Vec<AnchoredHash>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnchoredHash {
    pub chain_head: Hash,
    pub anchor_timestamp: DateTime<Utc>,
    pub anchor_service: String,
    pub anchor_proof: Vec<u8>,
}

impl AuditChain {
    pub fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            head: Hash([0u8; 32]),
            length: 0,
            anchored_hashes: Vec::new(),
        }
    }

    pub fn append(&mut self, component: String, action: String, data: serde_json::Value, tenant_id: Option<Uuid>, epoch: Option<u64>) -> Result<()> {
        let sequence = self.length;
        let previous_hash = self.head;
        let timestamp = Utc::now();
        
        let mut entry_data = Vec::new();
        entry_data.extend_from_slice(&sequence.to_be_bytes());
        entry_data.extend_from_slice(previous_hash.as_bytes());
        entry_data.extend_from_slice(component.as_bytes());
        entry_data.extend_from_slice(action.as_bytes());
        entry_data.extend_from_slice(&serde_json::to_vec(&data).unwrap_or_default());
        if let Some(tid) = tenant_id {
            entry_data.extend_from_slice(tid.as_bytes());
        }
        if let Some(e) = epoch {
            entry_data.extend_from_slice(&e.to_be_bytes());
        }
        entry_data.extend_from_slice(&timestamp.timestamp().to_be_bytes());
        
        let hash = snex_crypto::Hash::new(&entry_data);
        
        let entry = AuditEntry {
            id: Uuid::new_v4(),
            sequence,
            previous_hash,
            hash,
            timestamp,
            component,
            action,
            data,
            tenant_id,
            epoch,
        };
        
        self.entries.push_back(entry);
        self.head = hash;
        self.length += 1;
        
        if self.entries.len() > 10000 {
            self.entries.pop_front();
        }
        
        Ok(())
    }

    pub fn verify(&self) -> Result<bool> {
        let mut expected_hash = Hash([0u8; 32]);
        
        for entry in &self.entries {
            let mut data = Vec::new();
            data.extend_from_slice(&entry.sequence.to_be_bytes());
            data.extend_from_slice(entry.previous_hash.as_bytes());
            data.extend_from_slice(entry.component.as_bytes());
            data.extend_from_slice(entry.action.as_bytes());
            data.extend_from_slice(&serde_json::to_vec(&entry.data).unwrap_or_default());
            if let Some(tid) = entry.tenant_id {
                data.extend_from_slice(tid.as_bytes());
            }
            if let Some(e) = entry.epoch {
                data.extend_from_slice(&e.to_be_bytes());
            }
            data.extend_from_slice(&entry.timestamp.timestamp().to_be_bytes());
            
            let computed = snex_crypto::Hash::new(&data);
            if computed != entry.hash {
                return Ok(false);
            }
            if entry.previous_hash != expected_hash && entry.sequence > 0 {
                return Ok(false);
            }
            expected_hash = entry.hash;
        }
        
        Ok(self.head == expected_hash)
    }

    pub fn add_anchor(&mut self, anchor_service: String, anchor_proof: Vec<u8>) {
        self.anchored_hashes.push(AnchoredHash {
            chain_head: self.head,
            anchor_timestamp: Utc::now(),
            anchor_service,
            anchor_proof,
        });
    }

    pub fn get_latest_anchor(&self) -> Option<&AnchoredHash> {
        self.anchored_hashes.last()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnchorConfig {
    pub anchor_interval_seconds: u64,
    pub max_anchor_gap_seconds: u64,
    pub anchor_services: Vec<String>,
    pub witness_enabled: bool,
    pub witness_endpoints: Vec<String>,
}

impl Default for AnchorConfig {
    fn default() -> Self {
        Self {
            anchor_interval_seconds: 3600,
            max_anchor_gap_seconds: 72 * 3600,
            anchor_services: vec!["rfc3161".into()],
            witness_enabled: true,
            witness_endpoints: vec![],
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessClient {
    pub endpoints: Vec<String>,
}

impl WitnessClient {
    pub fn new(endpoints: Vec<String>) -> Self {
        Self { endpoints }
    }

    pub async fn submit_chain_head(&self, head: &Hash) -> Result<Vec<WitnessReceipt>> {
        let mut receipts = Vec::new();
        for endpoint in &self.endpoints {
            let receipt = WitnessReceipt {
                chain_head: *head,
                witness_url: endpoint.clone(),
                timestamp: Utc::now(),
                signature: vec![],
            };
            receipts.push(receipt);
        }
        Ok(receipts)
    }

    pub async fn check_consistency(&self, head: &Hash) -> Result<bool> {
        Ok(true)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessReceipt {
    pub chain_head: Hash,
    pub witness_url: String,
    pub timestamp: DateTime<Utc>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityCriticalEvent {
    pub id: Uuid,
    pub event_type: SecurityCriticalEventType,
    pub timestamp: DateTime<Utc>,
    pub data: serde_json::Value,
    pub anchored: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, EnumString, Display, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum SecurityCriticalEventType {
    KeyGeneration,
    KeyRotation,
    KeyDestruction,
    LegalHoldSet,
    LegalHoldLifted,
    Approval,
    GovernanceKeyUse,
    BuildUpModeStateChange,
    ReleaseLogEntry,
    Recovery,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_chain() {
        let mut chain = AuditChain::new();
        chain.append("test".into(), "action".into(), serde_json::json!({}), None, None).unwrap();
        chain.append("test".into(), "action2".into(), serde_json::json!({}), None, None).unwrap();
        
        assert_eq!(chain.length, 2);
        assert!(chain.verify().unwrap());
    }

    #[test]
    fn test_anchor() {
        let mut chain = AuditChain::new();
        chain.append("test".into(), "action".into(), serde_json::json!({}), None, None).unwrap();
        chain.add_anchor("test-service".into(), vec![]);
        
        assert_eq!(chain.anchored_hashes.len(), 1);
    }
}