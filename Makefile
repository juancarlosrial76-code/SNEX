.PHONY: help build test fmt clippy check run clean install

help:
	@echo "SNEX - Available targets:"
	@echo "  build     - Build debug"
	@echo "  release   - Build release"
	@echo "  test      - Run tests"
	@echo "  fmt       - Format code"
	@echo "  clippy    - Lint"
	@echo "  check     - Check (fmt + clippy + test)"
	@echo "  run       - Run with default config"
	@echo "  clean     - Clean build artifacts"
	@echo "  install   - Install locally"

build:
	cargo build

release:
	cargo build --release

test:
	cargo test --all-targets

fmt:
	cargo fmt --all

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

check: fmt clippy test

run:
	cargo run -- run

clean:
	cargo clean

install:
	cargo install --path .