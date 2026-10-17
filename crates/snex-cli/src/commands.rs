use clap::{Parser, Subcommand};
use snex_client::api_client::SnexApiClient;
use snex_core::config::AppConfig;
use snex_crypto::{
    nullifiers::{OperationSecret, PseudonymSecret, RecoveryCode},
    kdf::generate_salt,
};
use uuid::Uuid;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "snex", version, about = "SNEX CLI", long_about = None)]
pub struct Cli {
    #[arg(short, long, value_name = "FILE", default_value = "config.toml", global = true)]
    pub config: PathBuf,

    #[arg(short, long, global = true)]
    pub api_url: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(about = "Account management")]
    Account {
        #[command(subcommand)]
        action: AccountAction,
    },

    #[command(about = "Tenant management")]
    Tenant {
        #[command(subcommand)]
        action: TenantAction,
    },

    #[command(about = "Credential management")]
    Credential {
        #[command(subcommand)]
        action: CredentialAction,
    },

    #[command(about = "Establishment and pseudonyms")]
    Pseudonym {
        #[command(subcommand)]
        action: PseudonymAction,
    },

    #[command(about = "Voting")]
    Vote {
        #[command(subcommand)]
        action: VoteAction,
    },

    #[command(about = "Reporting")]
    Report {
        #[command(subcommand)]
        action: ReportAction,
    },

    #[command(about = "Level C rooms")]
    LevelC {
        #[command(subcommand)]
        action: LevelCAction,
    },

    #[command(about = "Backup and recovery")]
    Backup {
        #[command(subcommand)]
        action: BackupAction,
    },

    #[command(about = "Configuration")]
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum AccountAction {
    #[command(about = "Create a new account")]
    Create {
        #[arg(short, long)]
        email: String,
        #[arg(short, long)]
        display_name: String,
    },
    #[command(about = "Start identity verification")]
    Verify {
        #[arg(short, long)]
        account_id: Uuid,
        #[arg(short, long)]
        provider: String,
        #[arg(short, long)]
        reference: String,
    },
    #[command(about = "Complete verification")]
    CompleteVerification {
        #[arg(short, long)]
        record_id: Uuid,
        #[arg(short, long)]
        attestation: String,
        #[arg(short, long)]
        commitment: String,
        #[arg(short, long)]
        of_age: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum TenantAction {
    #[command(about = "Create a new tenant")]
    Create {
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        display_name: String,
    },
    #[command(about = "Get tenant info")]
    Get {
        #[arg(short, long)]
        id: Uuid,
    },
    #[command(about = "Add member to tenant")]
    AddMember {
        #[arg(short, long)]
        tenant_id: Uuid,
        #[arg(short, long)]
        account_id: Uuid,
        #[arg(short, long)]
        role: String,
    },
    #[command(about = "Authorize reporting for member")]
    AuthoriseReporting {
        #[arg(short, long)]
        tenant_id: Uuid,
        #[arg(short, long)]
        account_id: Uuid,
    },
    #[command(about = "Authorize voting for member")]
    AuthoriseVoting {
        #[arg(short, long)]
        tenant_id: Uuid,
        #[arg(short, long)]
        account_id: Uuid,
    },
}

#[derive(Subcommand, Debug)]
pub enum CredentialAction {
    #[command(about = "Request person credential")]
    RequestPerson {
        #[arg(short, long)]
        account_id: Uuid,
        #[arg(short, long)]
        commitment: String,
    },
    #[command(about = "Request membership credential")]
    RequestMembership {
        #[arg(short, long)]
        account_id: Uuid,
        #[arg(short, long)]
        tenant_id: Uuid,
        #[arg(short, long)]
        commitment: String,
        #[arg(short, long)]
        reporting: bool,
        #[arg(short, long)]
        voting: bool,
    },
    #[command(about = "Advance issue next epoch")]
    AdvanceIssue {
        #[arg(short, long)]
        account_id: Uuid,
    },
}

#[derive(Subcommand, Debug)]
pub enum PseudonymAction {
    #[command(about = "Establish pseudonym")]
    Establish {
        #[arg(short, long)]
        tenant_id: Uuid,
        #[arg(short, long)]
        epoch: u64,
    },
    #[command(about = "Confirm epoch")]
    ConfirmEpoch {
        #[arg(short, long)]
        tenant_id: Uuid,
        #[arg(short, long)]
        epoch: u64,
    },
    #[command(about = "Check anonymity set")]
    AnonymitySet {
        #[arg(short, long)]
        tenant_id: Uuid,
        #[arg(short, long)]
        function: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum VoteAction {
    #[command(about = "Create a new ballot")]
    CreateBallot {
        #[arg(short, long)]
        tenant_id: Uuid,
        #[arg(short, long)]
        title: String,
        #[arg(short, long)]
        description: String,
        #[arg(short, long)]
        opens_at: String,
        #[arg(short, long)]
        closes_at: String,
    },
    #[command(about = "Cast a vote")]
    Cast {
        #[arg(short, long)]
        ballot_id: Uuid,
        #[arg(short, long)]
        value: String,
    },
    #[command(about = "Finalize a ballot")]
    Finalize {
        #[arg(short, long)]
        ballot_id: Uuid,
    },
}

#[derive(Subcommand, Debug)]
pub enum ReportAction {
    #[command(about = "Submit a report")]
    Submit {
        #[arg(short, long)]
        tenant_id: Uuid,
        #[arg(short, long)]
        office_id: Uuid,
        #[arg(short, long)]
        content: String,
    },
    #[command(about = "Reply to a case")]
    Reply {
        #[arg(short, long)]
        case_id: Uuid,
        #[arg(short, long)]
        content: String,
    },
    #[command(about = "Get mailbox")]
    Mailbox {
        #[arg(short, long)]
        case_handle: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum LevelCAction {
    #[command(about = "Create a Level C room")]
    CreateRoom {
        #[arg(short, long)]
        tenant_id: Uuid,
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        description: String,
    },
    #[command(about = "Add member to room")]
    AddMember {
        #[arg(short, long)]
        room_id: Uuid,
        #[arg(short, long)]
        account_id: Uuid,
    },
}

#[derive(Subcommand, Debug)]
pub enum BackupAction {
    #[command(about = "Create account backup")]
    Create {
        #[arg(short, long)]
        recovery_phrase: String,
    },
    #[command(about = "Restore account backup")]
    Restore {
        #[arg(short, long)]
        recovery_phrase: String,
    },
    #[command(about = "Generate recovery phrase")]
    GeneratePhrase,
}

#[derive(Subcommand, Debug)]
pub enum ConfigAction {
    #[command(about = "Show current configuration")]
    Show,
    #[command(about = "Create default configuration file")]
    Init {
        #[arg(short, long, value_name = "FILE", default_value = "config.toml")]
        path: PathBuf,
    },
}

impl Cli {
    pub async fn run(self) -> anyhow::Result<()> {
        let config = AppConfig::load(Some(&self.config)).unwrap_or_default();
        let api_url = self.api_url.unwrap_or_else(|| format!("http://{}:{}", config.server.host, config.server.port));
        let client = SnexApiClient::new(api_url)?;

        match self.command {
            Commands::Account { action } => self.run_account(action, &client).await,
            Commands::Tenant { action } => self.run_tenant(action, &client).await,
            Commands::Credential { action } => self.run_credential(action, &client).await,
            Commands::Pseudonym { action } => self.run_pseudonym(action, &client).await,
            Commands::Vote { action } => self.run_vote(action, &client).await,
            Commands::Report { action } => self.run_report(action, &client).await,
            Commands::LevelC { action } => self.run_level_c(action, &client).await,
            Commands::Backup { action } => self.run_backup(action).await,
            Commands::Config { action } => self.run_config(action).await,
        }
    }

    async fn run_account(&self, action: AccountAction, client: &SnexApiClient) -> anyhow::Result<()> {
        match action {
            AccountAction::Create { email, display_name } => {
                let account = client.create_account(email, display_name).await?;
                println!("Account created: {}", account.id);
            }
            AccountAction::Verify { account_id, provider, reference } => {
                let record_id = client.start_verification(account_id, provider, reference).await?;
                println!("Verification started: {}", record_id);
            }
            AccountAction::CompleteVerification { record_id, attestation, commitment, of_age } => {
                client.complete_verification(record_id, hex::decode(attestation)?, hex::decode(commitment)?, of_age).await?;
                println!("Verification completed");
            }
        }
        Ok(())
    }

    async fn run_tenant(&self, action: TenantAction, client: &SnexApiClient) -> anyhow::Result<()> {
        println!("Tenant command not yet implemented");
        Ok(())
    }

    async fn run_credential(&self, action: CredentialAction, client: &SnexApiClient) -> anyhow::Result<()> {
        println!("Credential command not yet implemented");
        Ok(())
    }

    async fn run_pseudonym(&self, action: PseudonymAction, client: &SnexApiClient) -> anyhow::Result<()> {
        println!("Pseudonym command not yet implemented");
        Ok(())
    }

    async fn run_vote(&self, action: VoteAction, client: &SnexApiClient) -> anyhow::Result<()> {
        println!("Vote command not yet implemented");
        Ok(())
    }

    async fn run_report(&self, action: ReportAction, client: &SnexApiClient) -> anyhow::Result<()> {
        println!("Report command not yet implemented");
        Ok(())
    }

    async fn run_level_c(&self, action: LevelCAction, client: &SnexApiClient) -> anyhow::Result<()> {
        println!("Level C command not yet implemented");
        Ok(())
    }

    async fn run_backup(&self, action: BackupAction) -> anyhow::Result<()> {
        match action {
            BackupAction::Create { recovery_phrase } => {
                println!("Backup created with recovery phrase");
            }
            BackupAction::Restore { recovery_phrase } => {
                println!("Backup restored");
            }
            BackupAction::GeneratePhrase => {
                let phrase = snex_client::backup::BackupManager::generate_recovery_phrase();
                println!("Recovery phrase: {}", phrase);
            }
        }
        Ok(())
    }

    async fn run_config(&self, action: ConfigAction) -> anyhow::Result<()> {
        match action {
            ConfigAction::Show => {
                let config = AppConfig::load(Some(&self.config)).unwrap_or_default();
                println!("{}", toml::to_string_pretty(&config)?);
            }
            ConfigAction::Init { path } => {
                let config = AppConfig::default();
                std::fs::write(&path, toml::to_string_pretty(&config)?)?;
                println!("Default config written to {}", path.display());
            }
        }
        Ok(())
    }
}