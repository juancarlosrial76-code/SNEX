use snex_core::config::AppConfig;
use snex_issuer::service::IssuerService;
use snex_verifier::service::VerifierService;
use snex_registry::service::RegistryService;
use snex_reporting::service::ReportingService;
use snex_voting::service::VotingService;
use snex_levelc::service::LevelCService;
use snex_anchoring::service::AnchoringService;
use snex_retention::service::RetentionService;
use snex_tenant::service::TenantService;
use snex_crypto::key_hierarchy::MasterKey;
use std::sync::Arc;
use sqlx::PgPool;

#[derive(Clone)]
pub struct ApiState {
    pub config: AppConfig,
    pub pool: PgPool,
    pub issuer: Arc<IssuerService>,
    pub verifier: Arc<VerifierService>,
    pub registry: Arc<RegistryService>,
    pub reporting: Arc<ReportingService>,
    pub voting: Arc<VotingService>,
    pub level_c: Arc<LevelCService>,
    pub anchoring: Arc<AnchoringService>,
    pub retention: Arc<RetentionService>,
    pub tenant: Arc<TenantService>,
}

impl ApiState {
    pub async fn new(config: AppConfig, pool: PgPool) -> snex_core::error::Result<Self> {
        let master_key = snex_crypto::key_hierarchy::MasterKey::generate();
        
        let issuer_db = snex_issuer::database::IssuerDatabase::new(pool.clone());
        let issuer = Arc::new(IssuerService::new(config.clone(), issuer_db)?);
        issuer.initialize().await?;
        
        let verifier_db = snex_verifier::database::VerifierDatabase::new(pool.clone());
        let verifier = Arc::new(VerifierService::new(config.clone(), verifier_db));
        verifier.initialize().await?;
        
        let registry_db = snex_registry::database::RegistryDatabase::new(pool.clone());
        let registry = Arc::new(RegistryService::new(registry_db));
        registry.initialize().await?;
        
        let reporting = Arc::new(ReportingService::new(registry.clone(), config.clone()));
        
        let voting = Arc::new(VotingService::new(registry.clone(), verifier.clone(), config.clone()));
        
        let level_c = Arc::new(LevelCService::new(config.level_c.clone()));
        
        let anchoring = Arc::new(AnchoringService::new(config.anchoring.clone())?);
        anchoring.start_anchor_task().await;
        
        let retention = Arc::new(RetentionService::new(master_key, config.retention.clone()));
        retention.start_backup_expiry_task().await;
        
        let tenant = Arc::new(TenantService::new());
        
        Ok(Self {
            config,
            pool,
            issuer,
            verifier,
            registry,
            reporting,
            voting,
            level_c,
            anchoring,
            retention,
            tenant,
        })
    }
}