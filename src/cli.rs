use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "snex", version, about = "SNEX - A Rust CLI application", long_about = None)]
pub struct Cli {
    #[arg(short, long, value_name = "FILE", default_value = "config.toml", global = true)]
    pub config: PathBuf,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(about = "Run the application")]
    Run {
        #[arg(short, long, help = "Input data")]
        input: Option<String>,
    },

    #[command(about = "Configuration management")]
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
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