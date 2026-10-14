use clap::Parser;
use config::{Config, File};
use serde::Deserialize;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

mod cli;
mod config as app_config;

use cli::Cli;
use app_config::AppConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let cli = Cli::parse();
    let config = load_config(&cli.config)?;

    info!("Starting SNEX v{}", env!("CARGO_PKG_VERSION"));
    info!("Config loaded from: {:?}", cli.config);

    match cli.command {
        cli::Commands::Run { input } => {
            run_command(&config, input).await?;
        }
        cli::Commands::Config { action } => {
            config_command(&config, action).await?;
        }
    }

    Ok(())
}

fn load_config(config_path: &std::path::Path) -> anyhow::Result<AppConfig> {
    let mut builder = Config::builder()
        .add_source(File::with_name(config_path.to_str().unwrap()).required(false))
        .add_source(config::Environment::with_prefix("SNEX").separator("_"));

    let config = builder.build()?;
    config.try_deserialize().map_err(Into::into)
}

async fn run_command(config: &AppConfig, input: Option<String>) -> anyhow::Result<()> {
    info!("Running with config: {:?}", config);
    
    if let Some(input) = input {
        info!("Processing input: {}", input);
    }

    println!("SNEX running... (implement your logic here)");
    Ok(())
}

async fn config_command(config: &AppConfig, action: cli::ConfigAction) -> anyhow::Result<()> {
    match action {
        cli::ConfigAction::Show => {
            println!("{}", toml::to_string_pretty(config)?);
        }
        cli::ConfigAction::Init { path } => {
            let default = AppConfig::default();
            std::fs::write(&path, toml::to_string_pretty(&default)?)?;
            println!("Default config written to {}", path.display());
        }
    }
    Ok(())
}