# SNEX API Reference

## Base URL
```
http://localhost:8080/api
```

## Authentication
Currently uses API key in header:
```
Authorization: Bearer <api_key>
```

## Common Headers
```
Content-Type: application/json
Accept: application/json
```

## Error Responses
```json
{
  "error": "Error message",
  "code": "ERROR_CODE",
  "details": {}
}
```

HTTP Status Codes:
- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `409` - Conflict
- `429` - Rate Limited
- `500` - Internal Server Error

---

## Issuer API (`/api/issuer`)

### Create Account
```http
POST /accounts
Content-Type: application/json

{
  "email": "user@example.com",
  "display_name": "User Name"
}
```

**Response:**
```json
{
  "account": {
    "id": "uuid",
    "email": "user@example.com",
    "display_name": "User Name",
    "status": "pending_verification",
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:00Z",
    "of_age_flag": false
  }
}
```

### Start Verification
```http
POST /accounts/{account_id}/verification
Content-Type: application/json

{
  "provider_id": "provider1",
  "verification_ref": "ref123"
}
```

**Response:**
```json
{
  "record_id": "uuid"
}
```

### Complete Verification
```http
POST /verification/{record_id}
Content-Type: application/json

{
  "attestation": "base64_encoded",
  "blinded_commitment": "base64_encoded",
  "of_age": true
}
```

**Response:**
```json
{
  "record_id": "uuid"
}
```

### Request Person Credential
```http
POST /accounts/{account_id}/credentials/person
Content-Type: application/json

{
  "blinded_commitment": "base64_encoded",
  "attributes": ["base64_attr1", "base64_attr2"]
}
```

**Response:**
```json
{
  "credential": {
    "schema_id": "SNEX_PersonCredential_v1",
    "issuer": { "key": "base64_pubkey" },
    "subject": "base64_commitment",
    "attributes": ["base64_attr1"],
    "signature": { "signature": "base64_sig" },
    "epoch": 1,
    "issued_at": 1234567890,
    "expires_at": 1234567890
  }
}
```

### Request Membership Credential
```http
POST /accounts/{account_id}/credentials/membership
Content-Type: application/json

{
  "tenant_id": "uuid",
  "blinded_commitment": "base64_encoded",
  "attributes": [],
  "reporting_authorised": true,
  "voting_authorised": true
}
```

**Response:**
```json
{
  "credential": { ... }
}
```

### Advance Issue Next Epoch
```http
POST /accounts/{account_id}/credentials/advance
```

**Response:**
```json
{
  "operation_secret": "base64_encoded"
}
```

### Get Epoch State
```http
GET /epoch
```

**Response:**
```json
{
  "epoch": 1,
  "issuance_cohort_open": true,
  "issuance_cohort_size": 5,
  "minimum_cohort_size": 30,
  "grace_active": false
}
```

### Close Cohort
```http
POST /cohort/close
```

### Activate Grace
```http
POST /grace/activate
```

---

## Verifier API (`/api/verifier`)

### Process Establishment
```http
POST /establishment
Content-Type: application/json

{
  "tenant_id": "uuid",
  "person_credential": { ... },
  "membership_credential": { ... },
  "commitment": "base64_encoded",
  "commitment_key": "base64_encoded",
  "establishment_nullifier": "base64_encoded",
  "pair_tag": "base64_encoded",
  "epoch": 1,
  "lifetime_index": 0,
  "zero_knowledge_proof": "base64_encoded"
}
```

**Response:**
```json
{
  "accepted": true,
  "batch_pending": 5
}
```

### Confirm Epoch
```http
POST /epoch-confirmation
Content-Type: application/json

{
  "pseudonym": "base64_encoded",
  "tenant_id": "uuid",
  "epoch": 2,
  "person_credential": { ... },
  "membership_credential": { ... },
  "zero_knowledge_proof": "base64_encoded"
}
```

**Response:**
```json
{
  "confirmed": true
}
```

### Create Snapshot
```http
POST /snapshots
Content-Type: application/json

{
  "tenant_id": "uuid",
  "epoch": 1,
  "ballot_id": "uuid"
}
```

**Response:**
```json
{
  "snapshot_id": "uuid",
  "merkle_root": "hex_encoded",
  "size": 5
}
```

### Get Snapshot
```http
GET /snapshots/{snapshot_id}
```

### Get Anonymity Set
```http
GET /anonymity-set/{tenant_id}/{function}
```

**Response:**
```json
{
  "tenant_id": "uuid",
  "function": "voting",
  "count": 5,
  "build_up_mode": false
}
```

### Check Build-up Mode
```http
GET /build-up-mode/{tenant_id}/{function}
```

### Terminate Pseudonym
```http
POST /pseudonym/{pseudonym_hex}/terminate
```

### Block Pseudonym
```http
POST /pseudonym/{pseudonym_hex}/block
Content-Type: application/json

{
  "reason": "abuse detected"
}
```

---

## Registry API (`/api/registry`)

### Register Vote
```http
POST /votes
Content-Type: application/json

{
  "ballot_id": "uuid",
  "nullifier": "base64_encoded",
  "vote_value": "yes",
  "vote_hash": "base64_encoded",
  "pseudonym": "base64_encoded",
  "proof": "base64_encoded"
}
```

### Get Vote Register
```http
GET /votes/{ballot_id}
```

### Finalize Vote Register
```http
POST /votes/{ballot_id}/finalize
```

### Register Report
```http
POST /reports
Content-Type: application/json

{
  "case_handle": "base64_encoded",
  "tenant_id": "uuid",
  "reporting_office_id": "uuid",
  "rate_limit_tag": "base64_encoded",
  "content": "base64_encoded",
  "case_key_wrapped": "base64_encoded",
  "epoch": 1
}
```

**Response:**
```json
{
  "report_id": "uuid",
  "case_id": "uuid"
}
```

### Add Reply
```http
POST /replies
Content-Type: application/json

{
  "case_id": "uuid",
  "content": "base64_encoded",
  "sent_by": "officer"
}
```

### Handover Case
```http
POST /cases/{case_id}/handover
Content-Type: application/json

{
  "new_officer_key": "base64_encoded"
}
```

### Close Case
```http
POST /cases/{case_id}/close
```

### Get Mailbox
```http
GET /mailboxes/{case_handle_hex}
```

### Check Nullifier
```http
GET /nullifiers/{domain}/{nullifier_hex}
```

**Response:**
```json
{
  "exists": true
}
```

### Get Admission Journal
```http
GET /admission-journal?epoch=1&tenant_id=uuid
```

---

## Voting API (`/api/voting`)

### Create Ballot
```http
POST /ballots
Content-Type: application/json

{
  "tenant_id": "uuid",
  "title": "Ballot Title",
  "description": "Description",
  "opens_at": "2026-01-01T10:00:00Z",
  "closes_at": "2026-01-02T10:00:00Z"
}
```

### Cast Vote
```http
POST /ballots/{ballot_id}/vote
Content-Type: application/json

{
  "operation_secret": "base64_encoded",
  "vote_value": "yes",
  "pseudonym": "hex_encoded",
  "merkle_proof": { ... },
  "snapshot_leaf": { ... }
}
```

### Finalize Ballot
```http
POST /ballots/{ballot_id}/finalize
```

**Response:**
```json
{
  "tally": {
    "total": 10,
    "yes": 6,
    "no": 3,
    "abstain": 1
  }
}
```

### Get Vote Register
```http
GET /ballots/{ballot_id}/register
```

### Get Snapshot
```http
GET /snapshots/{snapshot_id}
```

### Get Anonymity Set
```http
GET /anonymity-set/{tenant_id}
```

---

## Reporting API (`/api/reporting`)

### Submit Report
```http
POST /reports
Content-Type: application/json

{
  "tenant_id": "uuid",
  "reporting_office_id": "uuid",
  "operation_secret": "base64_encoded",
  "report_window": 1234567890,
  "slot": 0,
  "content": "base64_encoded",
  "case_key_wrapped": "base64_encoded"
}
```

### Submit Reply
```http
POST /cases/{case_id}/replies
Content-Type: application/json

{
  "content": "base64_encoded",
  "sent_by": "officer"
}
```

### Handover Case
```http
POST /cases/{case_id}/handover
Content-Type: application/json

{
  "new_officer_key": "base64_encoded"
}
```

### Close Case
```http
POST /cases/{case_id}/close
```

### Get Mailbox
```http
GET /mailboxes/{case_handle_hex}
```

### Submit External Intake
```http
POST /external-intake
Content-Type: application/json

{
  "tenant_id": "uuid",
  "content": "base64_encoded",
  "proof_of_work": "base64_encoded"
}
```

---

## Level C API (`/api/level-c`)

### Create Room
```http
POST /rooms
Content-Type: application/json

{
  "tenant_id": "uuid",
  "name": "Board Room",
  "description": "Confidential discussions",
  "created_by": "uuid",
  "rule_set": {
    "add_permission": {
      "allowed_roles": ["owner", "admin"],
      "requires_approval": true,
      "approval_quorum": 2
    },
    "remove_permission": { ... },
    "external_join_permission": { ... },
    "version": 1
  }
}
```

### Get Room
```http
GET /rooms/{room_id}
```

### Add Member
```http
POST /rooms/{room_id}/members
Content-Type: application/json

{
  "account_id": "uuid",
  "device": {
    "device_id": "uuid",
    "leaf_index": 0,
    "signature_key": "base64_encoded",
    "encryption_key": "base64_encoded"
  },
  "added_by": "uuid"
}
```

### Remove Member
```http
DELETE /rooms/{room_id}/members/{account_id}
```

### Add Device
```http
POST /rooms/{room_id}/members/{account_id}/devices
```

### Remove Device
```http
DELETE /rooms/{room_id}/members/{account_id}/devices/{device_id}
```

### Create Device Backup
```http
POST /backups/device
Content-Type: application/json

{
  "account_id": "uuid",
  "device_id": "uuid",
  "recovery_phrase": "phrase",
  "mls_private_keys": "base64_encoded"
}
```

### Restore Device Backup
```http
POST /backups/device/{device_id}
Content-Type: application/json

{
  "recovery_phrase": "phrase"
}
```

### Create Recovery Backup
```http
POST /backups/recovery
```

### Restore Recovery Backup
```http
POST /backups/recovery/{account_id}
```

### Verify Group Change
```http
GET /rooms/{room_id}/verify-change/{version}
```

### Update Freshness
```http
GET /rooms/{room_id}/freshness/{account_id}/{lag_seconds}
```

---

## Anchoring API (`/api/anchoring`)

### Append to Audit Chain
```http
POST /append
Content-Type: application/json

{
  "component": "component_name",
  "action": "action_name",
  "data": {},
  "tenant_id": "uuid",
  "epoch": 1
}
```

### Create Anchor
```http
POST /anchor
```

### Verify Chain
```http
GET /verify
```

### Get Latest Anchor
```http
GET /latest-anchor
```

### Log Security Event
```http
POST /security-event
Content-Type: application/json

{
  "event_type": "key_generation",
  "data": {}
}
```

---

## Retention API (`/api/retention`)

### Register Data
```http
POST /data
Content-Type: application/json

{
  "data_id": "user123",
  "retention_class": "RA",
  "tenant_id": "uuid",
  "person_key_id": "person_key_1"
}
```

### Get Record
```http
GET /data/{data_id}
```

### Request Deletion
```http
POST /data/{data_id}/delete
Content-Type: application/json

{
  "requested_by": "admin",
  "volume": 100
}
```

### Approve Destruction
```http
POST /destruction/{pending_id}/approve
Content-Type: application/json

{
  "approved_by": "security_officer"
}
```

### Place Legal Hold
```http
POST /data/{data_id}/legal-hold
Content-Type: application/json

{
  "reason": "investigation",
  "placed_by": "legal",
  "review_interval_days": 30,
  "expires_at": "2026-12-31T23:59:59Z"
}
```

### Lift Legal Hold
```http
POST /data/{data_id}/legal-hold/{hold_id}
```

### Check Legal Hold
```http
GET /data/{data_id}/legal-hold
```

### Get Deletion Journal
```http
GET /deletion-journal
```

### Process Backup Expiry
```http
POST /backup-expiry/{generation}
```

---

## Tenant API (`/api/tenant`)

### Create Tenant
```http
POST /tenants
Content-Type: application/json

{
  "name": "tenant-name",
  "display_name": "Tenant Display Name"
}
```

### Get Tenant
```http
GET /tenants/{tenant_id}
```

### Activate Tenant
```http
POST /tenants/{tenant_id}/activate
```

### Suspend Tenant
```http
POST /tenants/{tenant_id}/suspend
```

### Terminate Tenant
```http
POST /tenants/{tenant_id}/terminate
```

### Add Member
```http
POST /tenants/{tenant_id}/members
Content-Type: application/json

{
  "account_id": "uuid",
  "role": "member"
}
```

### Get Members
```http
GET /tenants/{tenant_id}/members
```

### Remove Member
```http
DELETE /tenants/{tenant_id}/members/{account_id}
```

### Change Member Role
```http
PUT /tenants/{tenant_id}/members/{account_id}/role
Content-Type: application/json

{
  "role": "admin"
}
```

### Authorize Reporting
```http
POST /tenants/{tenant_id}/members/{account_id}/reporting
```

### Authorize Voting
```http
POST /tenants/{tenant_id}/members/{account_id}/voting
```

### Get Governance Keys
```http
GET /tenants/{tenant_id}/governance-keys
```

### Get Configuration
```http
GET /tenants/{tenant_id}/config
```

### Update Configuration
```http
PUT /tenants/{tenant_id}/config
Content-Type: application/json

{
  "config": { ... }
}
```

### Get Audit Log
```http
GET /tenants/{tenant_id}/audit?limit=100
```

---

## Health Check
```http
GET /health
```

**Response:**
```
OK
```