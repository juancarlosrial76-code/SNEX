# SNEX Architecture Overview

## System Overview

SNEX is a privacy-focused platform for associations and organizations with three product lines:

1. **Line 1**: Member administration with evidence (Levels A/B)
2. **Line 2**: Confidential rooms with end-to-end encryption (Level C via MLS/RFC 9420)
3. **Line 3**: Anonymous reports and consultative votes (Variant B - no resolvability)

## Core Principle

**Protection through inability, not refusal** - The operator cannot hand over certain data because it doesn't possess it:
- No direct mapping of persons to pseudonyms in stored holdings
- Context separation between Issuer (knows person) and Verifier (knows pseudonym)
- End-to-end encryption for Level C (operator has no keys)
- Crypto-shredding for deletion (destroy keys, data becomes unreadable)

## Service Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        API Gateway (snex-api)                    │
│                    Unified HTTP Interface                        │
└───────────────────────────┬─────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│  snex-issuer  │   │ snex-verifier │   │ snex-registry │
│  (Accounts)   │   │ (Pseudonyms)  │   │ (Nullifiers)  │
└───────┬───────┘   └───────┬───────┘   └───────┬───────┘
        │                   │                   │
        └───────────────────┼───────────────────┘
                            ▼
              ┌───────────────────────┐
              │   snex-anchoring      │
              │  (Audit Chains)       │
              └───────────┬───────────┘
                          ▼
              ┌───────────────────────┐
              │   snex-retention      │
              │ (Crypto-Shredding)    │
              └───────────────────────┘
```

### Service Responsibilities

| Service | Responsibility | Data Owned |
|---------|---------------|------------|
| **snex-issuer** | Account management, identity verification, credential issuance, epoch management, governance keys | Accounts, verification records, credentials |
| **snex-verifier** | Pseudonym establishment, batching buffer, epoch confirmation, snapshots, anonymity sets | Pseudonym registrations, batches, snapshots |
| **snex-registry** | Nullifier store, block/termination lists, admission journal, vote registers, reports/cases | Nullifiers, votes, reports, cases, mailboxes |
| **snex-reporting** | RLN rate limiting, case management, mailboxes, external intake | Reports, cases, replies, mailboxes |
| **snex-voting** | Tier 1 consultative votes, Merkle snapshots, vote registers | Ballots, votes, tallies |
| **snex-levelc** | MLS groups, device management, recovery backups | Level C rooms, MLS state |
| **snex-anchoring** | Hash chains, RFC 3161 anchors, witness protocol | Audit chains, anchored hashes |
| **snex-retention** | Crypto-shredding, key hierarchy, legal hold, backup expiry | Retention records, deletion journal |
| **snex-tenant** | Tenant administration, members, governance keys, audit log | Tenants, members, configs |

## Data Flow

### Account Creation & Verification
```
Client → API Gateway → snex-issuer → Identity Verification Provider
                                    ↓
                              snex-issuer (stores verification)
                                    ↓
                              Blind Credential Issuance
```

### Pseudonym Establishment
```
Client (with credentials) → API Gateway → snex-verifier
                                    ↓
                            Batching Buffer (min 8)
                                    ↓
                            Random Release Threshold
                                    ↓
                            Pseudonym Activated
```

### Voting (Tier 1)
```
Client → Create Ballot → Snapshot (Merkle Tree)
                ↓
         Cast Vote (Nullifier + ZK Proof)
                ↓
         Registry stores vote
                ↓
         Finalize → Publish Register
```

### Reporting
```
Client → Rate Limit Tag (RLN) → Report + Case
                            ↓
                     Case Key → Role Key Envelope
                            ↓
                     Handover → Case Key Rewrap
                            ↓
                     Mailbox for Replies
```

## Cryptographic Primitives

### BBS Signatures (blst)
- Blind issuance for credentials
- Zero-knowledge proofs for selective disclosure
- Unlinkable presentations

### Pedersen Commitments
- Binding secrets without revealing values
- Used for credential binding

### Nullifiers
- Vote nullifiers: `H(op_secret || ballot_id)`
- Report nullifiers: `H(op_secret || window || slot)`
- Rate limit tags: `H(op_secret || window || tenant)`
- Establishment nullifiers: `H(op_secret || epoch || tenant || index)`

### Key Hierarchy
```
Master Key (HSM)
    ├── KEK (per tenant/context)
    │     └── DEK (per object/person)
    ├── Backup Wrapping Key (per generation)
    └── PQ Wrapping Key (per generation)
```

### Post-Quantum Hybrid
- TLS: X25519 + ML-KEM-768
- Client-side PQ wrap: ML-KEM-1024
- Server-side PQ wrap: AES-256-GCM

### MLS (RFC 9420)
- Group messaging for Level C
- Each device = separate leaf
- Tree-based key derivation
- Post-quantum ciphersuites (when available)

## Security Model

### Threat Actors
1. **Platform Operator** (including compelled/bribed/hacked)
2. **Another Tenant**
3. **External Network Attacker**
4. **Passive Recording + Future Quantum Decryption**
5. **Compromised End Device**
6. **Manipulated Software Supply Chain**
7. **Identity Verification Provider**
8. **Database Administrator**
9. **Support/Recovery Attacker**
10. **Tenant Administrator**
11. **Malicious Member(s)**
12. **Compromised Reporting-Office Device**
13. **Infrastructure/HSM/Push Providers**

### Execution Assumptions (X1-X4)
- **X1**: Operator executes protocols as specified, no live instrumentation
- **X2**: At least 2 independent relays hide network addresses
- **X3**: Client is the published client (reproducible builds)
- **X4**: Identity provider verifies honestly, no duplicate identities

### Invariants (30 Total)
Key invariants include:
- **I1**: Usage path takes no account identifier
- **I4**: Each operation accepted at most once per nullifier domain
- **I7**: After key destruction, no declared copy readable
- **I14**: Operator never holds Level C decryption keys
- **I21**: Single quota per person across all valid credentials

## Build Stages

| Stage | Description | Anonymity Commitment |
|-------|-------------|---------------------|
| **Milestone 1-3** | Modulith (Lines 1+2) | None |
| **First Line 3 Code** | Process Separation | None |
| **Milestone 5a** | Physical Split | None |
| **Milestone 5b** | Pilot with Anchor Tenant | ✅ Active |
| **Rollout** | Production | ✅ Active |

## Configuration Parameters

Key parameters (from Annex A):
- `minimum_anonymity_set`: 30 (operational gate)
- `epoch_duration_days`: 180
- `credential_lifetime_epochs`: 3
- `advance_issuance_epochs`: 1
- `min_batch_size`: 8
- `max_batch_size`: 50
- `batch_release_threshold`: 8-12 (random)
- `rln_limit_per_window`: 3 reports/24h
- `grace_period_days`: 14