use snex_cli::{Cli, commands::Cli as CommandsCli};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    
    let cli = Cli::parse();
    cli.run().await
}