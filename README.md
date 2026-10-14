# SNEX

SNEX is a privacy-focused platform for associations and organizations with members, implementing three product lines with strong cryptographic guarantees:

- **Line 1**: Member administration with evidence (Levels A/B readable by operator)
- **Line 2**: Confidential rooms with end-to-end encryption (Level C via MLS/RFC 9420)
- **Line 3**: Anonymous reports and consultative votes (Variant B - no resolvability)

## Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Issuer    │    │  Verifier   │    │  Registry   │
│  (Accounts) │    │(Pseudonyms) │    │ (Nullifiers)│
└──────┬──────┘    └──────┬──────┘    └──────┬──────┘
       │                  │                  │
       └──────────────────┼──────────────────┘
                          ▼
              ┌───────────────────────┐
              │      API Gateway      │
              └───────────────────────┘
```

### Core Cryptographic Primitives

- **BBS Signatures** with blind issuance for credentials
- **Pedersen Commitments** for binding secrets
- **Nullifiers** for voting, reporting, and rate limiting
- **Key Hierarchy** (Master → KEK → DEK) with crypto-shredding
- **Post-Quantum Hybrid Encryption** (X25519 + ML-KEM-768)
- **MLS (RFC 9420)** for Level C group messaging

## Quick Start

### Prerequisites

- Rust 1.82+
- Docker & Docker Compose
- PostgreSQL 17+
- Redis 7+

### Development

```bash
# Copy environment template
cp .env.example .env

# Start infrastructure
docker-compose up -d postgres redis

# Run migrations
sqlx migrate run

# Build and run
cargo run --release --bin snex-api
```

### Production

```bash
# Build images
docker-compose build

# Start all services
docker-compose up -d
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| snex-api | 8080 | Unified HTTP API Gateway |
| snex-issuer | - | Credential issuance, epochs, governance |
| snex-verifier | - | Pseudonym establishment, snapshots |
| snex-registry | - | Nullifier store, admission journal |
| snex-anchoring | - | Audit chain anchoring |
| snex-retention | - | Crypto-shredding, legal hold |

## API Endpoints

### Issuer
- `POST /api/issuer/accounts` - Create account
- `POST /api/issuer/accounts/{id}/verification` - Start verification
- `POST /api/issuer/verification/{id}` - Complete verification
- `POST /api/issuer/accounts/{id}/credentials/person` - Request person credential
- `POST /api/issuer/accounts/{id}/credentials/membership` - Request membership credential

### Verifier
- `POST /api/verifier/establishment` - Process establishment
- `POST /api/verifier/epoch-confirmation` - Confirm epoch
- `POST /api/verifier/snapshots` - Create snapshot
- `GET /api/verifier/anonymity-set/{tenant_id}/{function}` - Get anonymity set

### Registry
- `POST /api/registry/votes` - Register vote
- `POST /api/registry/reports` - Register report
- `POST /api/registry/replies` - Add reply
- `GET /api/registry/mailboxes/{case_handle}` - Get mailbox

### Voting
- `POST /api/voting/ballots` - Create ballot
- `POST /api/voting/ballots/{id}/vote` - Cast vote
- `POST /api/voting/ballots/{id}/finalize` - Finalize ballot

### Reporting
- `POST /api/reporting/reports` - Submit report
- `POST /api/reporting/cases/{id}/replies` - Submit reply
- `GET /api/reporting/mailboxes/{case_handle}` - Get mailbox

### Level C
- `POST /api/level-c/rooms` - Create room
- `POST /api/level-c/rooms/{id}/members` - Add member

### Anchoring
- `POST /api/anchoring/append` - Append to audit chain
- `POST /api/anchoring/anchor` - Create anchor
- `GET /api/anchoring/verify` - Verify chain

### Retention
- `POST /api/retention/data` - Register data
- `POST /api/retention/data/{id}/delete` - Request deletion
- `POST /api/retention/data/{id}/legal-hold` - Place legal hold

### Tenant
- `POST /api/tenant/tenants` - Create tenant
- `POST /api/tenant/tenants/{id}/members` - Add member
- `POST /api/tenant/tenants/{id}/members/{account_id}/reporting` - Authorize reporting

## Configuration

See `.env.example` for all configuration options. Key parameters:

- `SNEX_VERIFIER__MINIMUM_ANONYMITY_SET` - Minimum active pseudonyms for anonymous functions (default: 30)
- `SNEX_ISSUER__EPOCH_DURATION_DAYS` - Credential rotation interval (default: 180)
- `SNEX_VERIFIER__MIN_BATCH_SIZE` - Minimum establishments per batch (default: 8)

## Security Model

**Protection through inability, not refusal** - The operator cannot hand over certain data because it doesn't possess it:

- No direct mapping of persons to pseudonyms in stored holdings
- Context separation between Issuer (knows person) and Verifier (knows pseudonym)
- End-to-end encryption for Level C (operator has no keys)
- Crypto-shredding for deletion (destroy keys, data becomes unreadable)

## Testing

```bash
# Unit tests
cargo test --workspace

# Integration tests (requires running services)
cargo test --workspace --test integration
```

## License

MIT OR Apache-2.0