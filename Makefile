.PHONY: help build test fmt clippy check run-dev run-prod docker-build docker-up docker-down clean migrate

help:
	@echo "SNEX - Available targets:"
	@echo "  build           - Build all crates in release mode"
	@echo "  test            - Run all tests"
	@echo "  fmt             - Format code with rustfmt"
	@echo "  clippy          - Run clippy lints"
	@echo "  check           - Run fmt, clippy, and test"
	@echo "  run-dev         - Run with docker-compose (dev mode)"
	@echo "  run-prod        - Run with docker-compose (prod mode)"
	@echo "  docker-build    - Build all Docker images"
	@echo "  docker-up       - Start all services"
	@echo "  docker-down     - Stop all services"
	@echo "  docker-logs     - Follow docker-compose logs"
	@echo "  migrate         - Run database migrations"
	@echo "  clean           - Clean build artifacts"

build:
	cargo build --release --workspace

test:
	cargo test --workspace

fmt:
	cargo fmt --all

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

check: fmt clippy test

run-dev:
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

run-prod:
	docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

docker-build:
	docker-compose build

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f

migrate:
	sqlx migrate run --database-url ${DATABASE_URL}

clean:
	cargo clean
	docker-compose down -v