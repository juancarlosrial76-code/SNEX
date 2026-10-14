# SNEX

A Rust CLI application with configuration, logging, and async support.

## Features

- **CLI** - Command-line interface with `clap`
- **Config** - TOML configuration with `config` crate and environment variable overrides
- **Logging** - Structured logging with `tracing`
- **Async** - Tokio runtime for async operations
- **Tests** - Integration tests with `assert_cmd`

## Installation

```bash
cargo install --path .
```

Or build from source:

```bash
cargo build --release
./target/release/snex --help
```

## Usage

```bash
# Show help
snex --help

# Run with default config
snex run

# Run with custom input
snex run --input "data"

# Show current config
snex config show

# Create default config file
snex config init --path ./config.toml

# Use custom config file
snex --config ./my-config.toml run
```

## Configuration

Create a `config.toml` file:

```toml
[server]
host = "127.0.0.1"
port = 8080
workers = 4

[database]
url = "sqlite://snex.db"
max_connections = 10

[logging]
level = "info"
format = "text"
```

Environment variables override config (prefix `SNEX_`):
- `SNEX_SERVER__PORT=9000`
- `SNEX_DATABASE__URL=postgres://...`

## Development

```bash
# Format code
cargo fmt

# Lint
cargo clippy

# Run tests
cargo test

# Run with logging
RUST_LOG=debug snex run
```

## License

MIT OR Apache-2.0