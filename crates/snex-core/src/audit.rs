use snex_crypto::hashing::Hash;
use crate::{tenant::{TenantAuditEntry, AuditAction, Actor}, error::{CoreError, Result}};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditLog {
    pub entries: Vec<AuditLogEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub tenant_id: Option<Uuid>,
    pub actor: Actor,
    pub action: AuditAction,
    pub component: String,
    pub details: serde_json::Value,
    pub hash: Hash,
    pub previous_hash: Hash,
    pub epoch: Option<u64>,
    pub batch_id: Option<Uuid>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    pub fn append(
        &mut self,
        tenant_id: Option<Uuid>,
        actor: Actor,
        action: AuditAction,
        component: String,
        details: serde_json::Value,
        epoch: Option<u64>,
        batch_id: Option<Uuid>,
    ) -> Result<()> {
        let sequence = self.entries.len() as u64;
        let previous_hash = self.entries.last().map(|e| e.hash).unwrap_or(Hash([0u8; 32]));
        let timestamp = Utc::now();
        
        let mut data = Vec::new();
        data.extend_from_slice(&sequence.to_be_bytes());
        data.extend_from_slice(previous_hash.as_bytes());
        if let Some(tid) = tenant_id {
            data.extend_from_slice(tid.as_bytes());
        }
        data.extend_from_slice(&serde_json::to_vec(&details).unwrap_or_default());
        if let Some(e) = epoch {
            data.extend_from_slice(&e.to_be_bytes());
        }
        if let Some(bid) = batch_id {
            data.extend_from_slice(bid.as_bytes());
        }
        data.extend_from_slice(&timestamp.timestamp().to_be_bytes());
        
        let hash = snex_crypto::Hash::new(&data);
        
        let entry = AuditLogEntry {
            id: Uuid::new_v4(),
            sequence,
            timestamp,
            tenant_id,
            actor,
            action,
            component,
            details,
            hash,
            previous_hash,
            epoch,
            batch_id,
        };
        
        self.entries.push(entry);
        Ok(())
    }

    pub fn verify(&self) -> Result<bool> {
        let mut expected_hash = Hash([0u8; 32]);
        
        for entry in &self.entries {
            let mut data = Vec::new();
            data.extend_from_slice(&entry.sequence.to_be_bytes());
            data.extend_from_slice(entry.previous_hash.as_bytes());
            if let Some(tid) = entry.tenant_id {
                data.extend_from_slice(tid.as_bytes());
            }
            data.extend_from_slice(&serde_json::to_vec(&entry.details).unwrap_or_default());
            if let Some(e) = entry.epoch {
                data.extend_from_slice(&e.to_be_bytes());
            }
            if let Some(bid) = entry.batch_id {
                data.extend_from_slice(bid.as_bytes());
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
        
        Ok(true)
    }

    pub fn get_tenant_audit(&self, tenant_id: Uuid) -> Vec<&AuditLogEntry> {
        self.entries.iter()
            .filter(|e| e.tenant_id == Some(tenant_id))
            .collect()
    }

    pub fn get_by_batch(&self, batch_id: Uuid) -> Vec<&AuditLogEntry> {
        self.entries.iter()
            .filter(|e| e.batch_id == Some(batch_id))
            .collect()
    }

    pub fn get_by_epoch(&self, epoch: u64) -> Vec<&AuditLogEntry> {
        self.entries.iter()
            .filter(|e| e.epoch == Some(epoch))
            .collect()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransparencyReport {
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub orders_received: u32,
    pub orders_complied: u32,
    pub orders_challenged: u32,
    pub openings_requested: u32,
    pub openings_performed: u32,
    pub openings_declined: u32,
    pub recoveries: u32,
    pub relay_changes: u32,
    pub subprocessor_changes: u32,
    pub build_up_mode_activations: u32,
    pub anchor_count: u32,
    pub anchor_gaps: u32,
    pub published_at: DateTime<Utc>,
}

impl TransparencyReport {
    pub fn new(period_start: DateTime<Utc>, period_end: DateTime<Utc>) -> Self {
        Self {
            period_start,
            period_end,
            orders_received: 0,
            orders_complied: 0,
            orders_challenged: 0,
            openings_requested: 0,
            openings_performed: 0,
            openings_declined: 0,
            recoveries: 0,
            relay_changes: 0,
            subprocessor_changes: 0,
            build_up_mode_activations: 0,
            anchor_count: 0,
            anchor_gaps: 0,
            published_at: Utc::now(),
        }
    }

    pub fn to_bands(&self, min_band: u32) -> TransparencyReportBands {
        TransparencyReportBands {
            orders_received: self.band(self.orders_received, min_band),
            orders_complied: self.band(self.orders_complied, min_band),
            orders_challenged: self.band(self.orders_challenged, min_band),
            openings_requested: self.band(self.openings_requested, min_band),
            openings_performed: self.band(self.openings_performed, min_band),
            openings_declined: self.band(self.openings_declined, min_band),
            recoveries: self.band(self.recoveries, min_band),
            relay_changes: self.band(self.relay_changes, min_band),
            subprocessor_changes: self.band(self.subprocessor_changes, min_band),
            build_up_mode_activations: self.band(self.build_up_mode_activations, min_band),
            anchor_count: self.band(self.anchor_count, min_band),
            anchor_gaps: self.band(self.anchor_gaps, min_band),
        }
    }

    fn band(&self, value: u32, min_band: u32) -> String {
        if value < min_band {
            "below band".into()
        } else {
            let band = (value / min_band) * min_band;
            format!("{}-{}", band, band + min_band - 1)
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransparencyReportBands {
    pub orders_received: String,
    pub orders_complied: String,
    pub orders_challenged: String,
    pub openings_requested: String,
    pub openings_performed: String,
    pub openings_declined: String,
    pub recoveries: String,
    pub relay_changes: String,
    pub subprocessor_changes: String,
    pub build_up_mode_activations: String,
    pub anchor_count: String,
    pub anchor_gaps: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_log() {
        let mut log = AuditLog::new();
        log.append(None, Actor::System, AuditAction::TenantCreated, "tenant".into(), serde_json::json!({}), None, None).unwrap();
        log.append(None, Actor::System, AuditAction::MemberAdded, "tenant".into(), serde_json::json!({}), None, None).unwrap();
        
        assert!(log.verify().unwrap());
        assert_eq!(log.entries.len(), 2);
    }

    #[test]
    fn test_transparency_report_bands() {
        let report = TransparencyReport::new(Utc::now() - chrono::Duration::days(180), Utc::now());
        let bands = report.to_bands(10);
        assert_eq!(bands.orders_received, "below band");
    }
}