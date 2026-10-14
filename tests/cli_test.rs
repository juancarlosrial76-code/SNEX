use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

#[test]
fn test_help() {
    let mut cmd = Command::cargo_bin("snex").unwrap();
    cmd.arg("--help").assert().success().stdout(predicate::str::contains("SNEX"));
}

#[test]
fn test_version() {
    let mut cmd = Command::cargo_bin("snex").unwrap();
    cmd.arg("--version").assert().success().stdout(predicate::str::contains("snex"));
}

#[test]
fn test_config_init() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("test-config.toml");

    let mut cmd = Command::cargo_bin("snex").unwrap();
    cmd.args(["config", "init", "--config", config_path.to_str().unwrap()])
        .assert()
        .success();

    assert!(config_path.exists());
    let content = std::fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("server"));
    assert!(content.contains("database"));
    assert!(content.contains("logging"));
}

#[test]
fn test_config_show() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("test-config.toml");

    let mut cmd = Command::cargo_bin("snex").unwrap();
    cmd.args(["config", "init", "--config", config_path.to_str().unwrap()])
        .assert()
        .success();

    let mut cmd = Command::cargo_bin("snex").unwrap();
    cmd.args(["--config", config_path.to_str().unwrap(), "config", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("server"));
}