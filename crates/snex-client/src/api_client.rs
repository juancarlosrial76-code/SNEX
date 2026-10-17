use snex_core::{
    identity::Account,
    epoch::Epoch,
    tenant::Tenant,
    pseudonym::PseudonymFunction,
    voting::{Ballot, Vote, VoteValue, VoteTally, Snapshot},
    reporting::{Report, Case, Reply},
    error::{CoreError, Result},
};
use snex_crypto::{
    bbs::BbsCredential,
    commitments::Commitment,
    nullifiers::{Nullifier, OperationSecret, Pseudonym, CaseHandle, MailboxAccess},
    encryption::EncryptedData,
};
use uuid::Uuid;
use reqwest::Client;
use serde::{Serialize, Deserialize};
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EstablishmentRequestDto {
    pub tenant_id: Uuid,
    pub person_credential: BbsCredential,
    pub membership_credential: BbsCredential,
    pub commitment: Vec<u8>,
    pub commitment_key: Vec<u8>,
    pub establishment_nullifier: Vec<u8>,
    pub pair_tag: Vec<u8>,
    pub epoch: u64,
    pub lifetime_index: u32,
    pub zero_knowledge_proof: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochConfirmationRequest {
    pub pseudonym: Vec<u8>,
    pub tenant_id: Uuid,
    pub epoch: u64,
    pub person_credential: BbsCredential,
    pub membership_credential: BbsCredential,
    pub zero_knowledge_proof: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Mailbox {
    pub case_handle: CaseHandle,
    pub mailbox_access: MailboxAccess,
    pub messages: Vec<MailboxMessage>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_accessed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MailboxMessage {
    pub id: Uuid,
    pub content: EncryptedData,
    pub direction: MessageDirection,
    pub sent_at: chrono::DateTime<chrono::Utc>,
    pub read_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageDirection {
    Incoming,
    Outgoing,
}

pub struct SnexApiClient {
    base_url: String,
    client: Client,
    auth_token: Option<String>,
}

impl SnexApiClient {
    pub fn new(base_url: String) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| CoreError::Internal(e.to_string()))?;
        
        Ok(Self {
            base_url,
            client,
            auth_token: None,
        })
    }

    pub fn set_auth_token(&mut self, token: String) {
        self.auth_token = Some(token);
    }

    async fn request<T: serde::de::DeserializeOwned>(&self, method: reqwest::Method, path: &str, body: Option<serde_json::Value>) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.client.request(method, &url);
        
        if let Some(token) = &self.auth_token {
            req = req.bearer_auth(token);
        }
        
        if let Some(body) = body {
            req = req.json(&body);
        }
        
        let resp = req.send().await
            .map_err(|e| CoreError::Internal(e.to_string()))?;
        
        if !resp.status().is_success() {
            let err = resp.text().await.unwrap_or_default();
            return Err(CoreError::Internal(err));
        }
        
        let data = resp.json().await
            .map_err(|e| CoreError::Internal(e.to_string()))?;
        
        Ok(data)
    }

    pub async fn create_account(&self, email: String, display_name: String) -> Result<Account> {
        self.request(reqwest::Method::POST, "/api/issuer/accounts", Some(serde_json::json!({
            "email": email,
            "display_name": display_name,
        }))).await
    }

    pub async fn start_verification(&self, account_id: Uuid, provider_id: String, verification_ref: String) -> Result<Uuid> {
        let resp: serde_json::Value = self.request(reqwest::Method::POST, &format!("/api/issuer/accounts/{}/verification", account_id), Some(serde_json::json!({
            "provider_id": provider_id,
            "verification_ref": verification_ref,
        }))).await?;
        
        Ok(serde_json::from_value(resp).unwrap())
    }

    pub async fn complete_verification(&self, record_id: Uuid, attestation: Vec<u8>, blinded_commitment: Vec<u8>, of_age: bool) -> Result<()> {
        self.request::<()>(reqwest::Method::POST, &format!("/api/issuer/verification/{}", record_id), Some(serde_json::json!({
            "attestation": attestation,
            "blinded_commitment": blinded_commitment,
            "of_age": of_age,
        }))).await?;
        Ok(())
    }

    pub async fn request_person_credential(&self, account_id: Uuid, blinded_commitment: Vec<u8>, attributes: Vec<Vec<u8>>) -> Result<BbsCredential> {
        self.request(reqwest::Method::POST, &format!("/api/issuer/accounts/{}/credentials/person", account_id), Some(serde_json::json!({
            "blinded_commitment": blinded_commitment,
            "attributes": attributes,
        }))).await
    }

    pub async fn request_membership_credential(
        &self,
        account_id: Uuid,
        tenant_id: Uuid,
        blinded_commitment: Vec<u8>,
        attributes: Vec<Vec<u8>>,
        reporting_authorised: bool,
        voting_authorised: bool,
    ) -> Result<BbsCredential> {
        self.request(reqwest::Method::POST, &format!("/api/issuer/accounts/{}/credentials/membership", account_id), Some(serde_json::json!({
            "tenant_id": tenant_id,
            "blinded_commitment": blinded_commitment,
            "attributes": attributes,
            "reporting_authorised": reporting_authorised,
            "voting_authorised": voting_authorised,
        }))).await
    }

    pub async fn advance_issue_next_epoch(&self, account_id: Uuid) -> Result<OperationSecret> {
        let resp: serde_json::Value = self.request(reqwest::Method::POST, &format!("/api/issuer/accounts/{}/credentials/advance", account_id), None).await?;
        let secret: Vec<u8> = resp["operation_secret"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap() as u8).collect();
        Ok(OperationSecret::from_bytes(secret.try_into().unwrap()))
    }

    pub async fn process_establishment(&self, request: EstablishmentRequestDto) -> Result<()> {
        self.request::<()>(reqwest::Method::POST, "/api/verifier/establishment", Some(serde_json::to_value(request).unwrap())).await?;
        Ok(())
    }

    pub async fn confirm_epoch(&self, request: EpochConfirmationRequest) -> Result<()> {
        self.request::<()>(reqwest::Method::POST, "/api/verifier/epoch-confirmation", Some(serde_json::to_value(request).unwrap())).await?;
        Ok(())
    }

    pub async fn get_anonymity_set(&self, tenant_id: Uuid, function: PseudonymFunction) -> Result<u32> {
        let resp: serde_json::Value = self.request(reqwest::Method::GET, &format!("/api/verifier/anonymity-set/{}/{}", tenant_id, function), None).await?;
        Ok(resp["count"].as_u64().unwrap() as u32)
    }

    pub async fn create_ballot(&self, tenant_id: Uuid, title: String, description: String, opens_at: String, closes_at: String) -> Result<Ballot> {
        self.request(reqwest::Method::POST, "/api/voting/ballots", Some(serde_json::json!({
            "tenant_id": tenant_id,
            "title": title,
            "description": description,
            "opens_at": opens_at,
            "closes_at": closes_at,
        }))).await
    }

    pub async fn cast_vote(&self, ballot_id: Uuid, operation_secret: &OperationSecret, vote_value: VoteValue, pseudonym: Pseudonym, merkle_proof: snex_core::voting::MerkleProof, snapshot_leaf: snex_core::voting::SnapshotLeaf) -> Result<Vote> {
        let resp: serde_json::Value = self.request(reqwest::Method::POST, &format!("/api/voting/ballots/{}/vote", ballot_id), Some(serde_json::json!({
            "operation_secret": operation_secret.0.to_vec(),
            "vote_value": vote_value,
            "pseudonym": pseudonym.to_hex(),
            "merkle_proof": merkle_proof,
            "snapshot_leaf": snapshot_leaf,
        }))).await?;
        
        Ok(serde_json::from_value(resp).unwrap())
    }

    pub async fn finalize_ballot(&self, ballot_id: Uuid) -> Result<VoteTally> {
        self.request(reqwest::Method::POST, &format!("/api/voting/ballots/{}/finalize", ballot_id), None).await
    }

    pub async fn submit_report(
        &self,
        tenant_id: Uuid,
        reporting_office_id: Uuid,
        operation_secret: &OperationSecret,
        report_window: u64,
        slot: u32,
        content: EncryptedData,
        case_key_wrapped: Vec<u8>,
    ) -> Result<(Report, Case)> {
        let resp: serde_json::Value = self.request(reqwest::Method::POST, "/api/reporting/reports", Some(serde_json::json!({
            "tenant_id": tenant_id,
            "reporting_office_id": reporting_office_id,
            "operation_secret": operation_secret.0.to_vec(),
            "report_window": report_window,
            "slot": slot,
            "content": content.0,
            "case_key_wrapped": case_key_wrapped,
        }))).await?;
        
        Ok((
            serde_json::from_value(resp["report_id"].clone()).unwrap(),
            serde_json::from_value(resp["case_id"].clone()).unwrap(),
        ))
    }

    pub async fn get_mailbox(&self, case_handle: CaseHandle) -> Result<Mailbox> {
        self.request(reqwest::Method::GET, &format!("/api/registry/mailboxes/{}", hex::encode(case_handle.as_bytes())), None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_client() {
        let client = SnexApiClient::new("http://localhost:8080".into()).unwrap();
        assert_eq!(client.base_url, "http://localhost:8080");
    }
}