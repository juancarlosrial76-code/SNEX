use config::{Config, File, Environment};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub crypto: CryptoConfig,
    pub issuer: IssuerConfig,
    pub verifier: VerifierConfig,
    pub registry: RegistryConfig,
    pub anchoring: AnchoringConfig,
    pub retention: RetentionConfig,
    pub level_c: LevelCConfig,
    pub relay: RelayConfig,
    pub logging: LoggingConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
    pub request_timeout_seconds: u64,
    pub max_request_size: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connect_timeout_seconds: u64,
    pub idle_timeout_seconds: u64,
    pub migration_table: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    pub max_connections: u32,
    pub connection_timeout_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CryptoConfig {
    pub master_key_path: Option<PathBuf>,
    pub hsm_enabled: bool,
    pub hsm_slot: Option<u64>,
    pub hsm_pin: Option<String>,
    pub backup_wrapping_key_rotation_days: u32,
    pub pq_wrapper_enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssuerConfig {
    pub epoch_duration_days: u32,
    pub credential_lifetime_epochs: u32,
    pub advance_issuance_epochs: u32,
    pub grace_period_days: u32,
    pub grace_annual_ceiling_days: u32,
    pub minimum_cohort_size: u32,
    pub governance_key_rotation_epochs: u32,
    pub initial_quorum: u32,
    pub total_shares: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifierConfig {
    pub min_batch_size: u32,
    pub max_batch_size: u32,
    pub batch_release_threshold_min: u32,
    pub batch_release_threshold_max: u32,
    pub max_establishment_period_hours: u32,
    pub min_establishment_jitter_hours: u32,
    pub max_failed_establishment_attempts: u32,
    pub publication_cohort_size: u32,
    pub re_release_waiting_period_days: u32,
    pub minimum_anonymity_set: u32,
    pub band_width: u32,
    pub set_display_delay_hours: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistryConfig {
    pub nullifier_retention_days: u32,
    pub block_list_retention_days: u32,
    pub termination_list_retention_days: u32,
    pub volume_threshold_for_approval: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnchoringConfig {
    pub anchor_interval_seconds: u64,
    pub max_anchor_gap_seconds: u64,
    pub anchor_services: Vec<String>,
    pub witness_enabled: bool,
    pub witness_endpoints: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RetentionConfig {
    pub regime1_generations: u32,
    pub regime1_generation_interval_hours: u32,
    pub regime2_generations: u32,
    pub regime2_generation_interval_hours: u32,
    pub database_rollback_window_days: u32,
    pub volume_threshold: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LevelCConfig {
    pub minors_blocked: bool,
    pub key_package_retention_days: u32,
    pub max_freshness_lag_seconds: u64,
    pub allowed_ciphersuites: Vec<u16>,
    pub require_post_quantum: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayConfig {
    pub endpoints: Vec<String>,
    pub latency_budget_ms: u64,
    pub availability_threshold: f64,
    pub post_quantum_hybrid: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: LogFormat,
    pub json_output: bool,
    pub log_sql: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Text,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            database: DatabaseConfig::default(),
            redis: RedisConfig::default(),
            crypto: CryptoConfig::default(),
            issuer: IssuerConfig::default(),
            verifier: VerifierConfig::default(),
            registry: RegistryConfig::default(),
            anchoring: AnchoringConfig::default(),
            retention: RetentionConfig::default(),
            level_c: LevelCConfig::default(),
            relay: RelayConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 8080,
            workers: num_cpus::get(),
            request_timeout_seconds: 30,
            max_request_size: 10 * 1024 * 1024,
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "postgresql://localhost/snex".into(),
            max_connections: 20,
            min_connections: 5,
            connect_timeout_seconds: 10,
            idle_timeout_seconds: 300,
            migration_table: "_sqlx_migrations".into(),
        }
    }
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: "redis://localhost:6379".into(),
            max_connections: 50,
            connection_timeout_seconds: 5,
        }
    }
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            master_key_path: None,
            hsm_enabled: false,
            hsm_slot: None,
            hsm_pin: None,
            backup_wrapping_key_rotation_days: 7,
            pq_wrapper_enabled: true,
        }
    }
}

impl Default for IssuerConfig {
    fn default() -> Self {
        Self {
            epoch_duration_days: 180,
            credential_lifetime_epochs: 3,
            advance_issuance_epochs: 1,
            grace_period_days: 14,
            grace_annual_ceiling_days: 30,
            minimum_cohort_size: 30,
            governance_key_rotation_epochs: 2,
            initial_quorum: 2,
            total_shares: 3,
        }
    }
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            min_batch_size: 8,
            max_batch_size: 50,
            batch_release_threshold_min: 8,
            batch_release_threshold_max: 12,
            max_establishment_period_hours: 72,
            min_establishment_jitter_hours: 1,
            max_failed_establishment_attempts: 2,
            publication_cohort_size: 5,
            re_release_waiting_period_days: 7,
            minimum_anonymity_set: 30,
            band_width: 10,
            set_display_delay_hours: 24,
        }
    }
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            nullifier_retention_days: 365,
            block_list_retention_days: 365,
            termination_list_retention_days: 3650,
            volume_threshold_for_approval: 1000,
        }
    }
}

impl Default for AnchoringConfig {
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

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            regime1_generations: 14,
            regime1_generation_interval_hours: 24,
            regime2_generations: 8,
            regime2_generation_interval_hours: 168,
            database_rollback_window_days: 7,
            volume_threshold: 1000,
        }
    }
}

impl Default for LevelCConfig {
    fn default() -> Self {
        Self {
            minors_blocked: true,
            key_package_retention_days: 90,
            max_freshness_lag_seconds: 3600,
            allowed_ciphersuites: vec![0x0001, 0x0002],
            require_post_quantum: false,
        }
    }
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            endpoints: vec![],
            latency_budget_ms: 500,
            availability_threshold: 0.99,
            post_quantum_hybrid: true,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            format: LogFormat::Text,
            json_output: false,
            log_sql: false,
        }
    }
}

impl AppConfig {
    pub fn load(config_path: Option<&PathBuf>) -> config::ConfigResult<Self> {
        let mut builder = Config::builder();
        
        if let Some(path) = config_path {
            builder = builder.add_source(File::with_name(path.to_str().unwrap()).required(false));
        }
        
        builder = builder.add_source(Environment::with_prefix("SNEX").separator("_"));
        builder.build()?.try_deserialize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AppConfig::default();
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.issuer.epoch_duration_days, 180);
        assert_eq!(config.verifier.minimum_anonymity_set, 30);
    }
}