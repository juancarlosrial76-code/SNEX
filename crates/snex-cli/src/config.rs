use snex_core::config::AppConfig;
use std::path::PathBuf;

pub fn load_config(config_path: Option<&PathBuf>) -> AppConfig {
    AppConfig::load(config_path).unwrap_or_default()
}

pub fn save_config(config: &AppConfig, path: &PathBuf) -> anyhow::Result<()> {
    std::fs::write(path, toml::to_string_pretty(config)?)?;
    Ok(())
}