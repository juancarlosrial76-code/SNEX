use snex_core::{
    anchoring::{AuditChain, AnchoredHash, AnchorConfig, WitnessClient, WitnessReceipt, SecurityCriticalEvent, SecurityCriticalEventType},
    error::{CoreError, Result},
};
use snex_crypto::hashing::Hash;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};
use reqwest::Client;

pub struct AnchoringService {
    audit_chain: Arc<RwLock<AuditChain>>,
    config: AnchorConfig,
    witness_client: Option<WitnessClient>,
    http_client: Client,
}

impl AnchoringService {
    pub fn new(config: AnchorConfig) -> Result<Self> {
        let witness_client = if config.witness_enabled && !config.witness_endpoints.is_empty() {
            Some(WitnessClient::new(config.witness_endpoints.clone()))
        } else {
            None
        };
        
        let http_client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| CoreError::Internal(e.to_string()))?;
        
        Ok(Self {
            audit_chain: Arc::new(RwLock::new(AuditChain::new())),
            config,
            witness_client,
            http_client,
        })
    }

    pub async fn append(&self, component: String, action: String, data: serde_json::Value, tenant_id: Option<Uuid>, epoch: Option<u64>) -> Result<()> {
        let mut chain = self.audit_chain.write().await;
        chain.append(component, action, data, tenant_id, epoch)?;
        
        if chain.length % 100 == 0 {
            drop(chain);
            self.anchor().await?;
        }
        
        Ok(())
    }

    pub async fn anchor(&self) -> Result<()> {
        let mut chain = self.audit_chain.write().await;
        let head = chain.head;
        
        let anchor_proof = self.submit_to_anchor_services(&head).await?;
        
        chain.add_anchor("rfc3161".into(), anchor_proof);
        
        if let Some(witness) = &self.witness_client {
            let receipts = witness.submit_chain_head(&head).await?;
            for receipt in receipts {
                chain.add_anchor(receipt.witness_url, receipt.signature);
            }
        }
        
        Ok(())
    }

    async fn submit_to_anchor_services(&self, head: &Hash) -> Result<Vec<u8>> {
        for service_url in &self.config.anchor_services {
            let response = self.http_client
                .post(service_url)
                .json(&serde_json::json!({
                    "hash": head.to_hex(),
                    "timestamp": Utc::now().to_rfc3339(),
                }))
                .send()
                .await;
            
            if let Ok(resp) = response {
                if resp.status().is_success() {
                    let body = resp.bytes().await.map_err(|e| CoreError::Internal(e.to_string()))?;
                    return Ok(body.to_vec());
                }
            }
        }
        
        Ok(vec![])
    }

    pub async fn verify_chain(&self) -> Result<bool> {
        let chain = self.audit_chain.read().await;
        chain.verify()
    }

    pub async fn get_latest_anchor(&self) -> Result<Option<AnchoredHash>> {
        let chain = self.audit_chain.read().await;
        Ok(chain.get_latest_anchor().cloned())
    }

    pub async fn check_witness_consistency(&self) -> Result<bool> {
        let chain = self.audit_chain.read().await;
        if let Some(witness) = &self.witness_client {
            witness.check_consistency(&chain.head).await
        } else {
            Ok(true)
        }
    }

    pub async fn log_security_critical_event(&self, event_type: SecurityCriticalEventType, data: serde_json::Value) -> Result<()> {
        let event = SecurityCriticalEvent {
            id: Uuid::new_v4(),
            event_type,
            timestamp: Utc::now(),
            data,
            anchored: false,
        };
        
        self.append(
            "security".into(),
            format!("{:?}", event_type),
            serde_json::to_value(event).unwrap(),
            None,
            None,
        ).await?;
        
        self.anchor().await?;
        
        Ok(())
    }

    pub async fn start_anchor_task(&self) {
        let config = self.config.clone();
        let service = self.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(config.anchor_interval_seconds));
            loop {
                interval.tick().await;
                if let Err(e) = service.anchor().await {
                    warn!("Anchor failed: {}", e);
                }
            }
        });
    }
}

impl Clone for AnchoringService {
    fn clone(&self) -> Self {
        Self {
            audit_chain: self.audit_chain.clone(),
            config: self.config.clone(),
            witness_client: self.witness_client.clone(),
            http_client: self.http_client.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snex_core::config::AppConfig;

    #[tokio::test]
    async fn test_anchoring_service() {
        let config = AnchorConfig::default();
        let service = AnchoringService::new(config).unwrap();
        
        service.append("test".into(), "action".into(), serde_json::json!({}), None, None).await.unwrap();
        
        let valid = service.verify_chain().await.unwrap();
        assert!(valid);
    }
}