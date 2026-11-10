use crate::key_provider::KeyProvider;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("request failed: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("backend returned {status}: {body}")]
    Backend { status: u16, body: String },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentCompleteRequest {
    pub enrollment_transaction_id: Uuid,
    pub device_instance_id: Uuid,
    pub platform: String,
    pub os_version: Option<String>,
    pub hostname: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub hardware_uuid_hash: Option<String>,
    pub serial_hash: Option<String>,
    pub ownership: String,
    pub agent_version: String,
    pub public_key: String,
    pub key_algorithm: String,
    pub assurance_level: String,
    pub proof_of_possession: String,
    pub fingerprint_version: i32,
    pub fingerprint_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentCompleteResponse {
    pub device_id: Uuid,
    pub status: String,
    pub approval_type: String,
    pub certificate_status: String,
    pub certificate_pem: Option<String>,
    pub issuing_ca_pem: Option<String>,
    pub policy_version: i32,
    pub message: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HeartbeatRequest {
    pub agent_version: String,
    pub policy_version: i32,
    pub health_status: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeviceAppPolicy {
    pub application_id: Uuid,
    pub pending_access: bool,
    pub offline_access: bool,
    pub offline_grace_seconds: i64,
    pub failure_mode: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DevicePolicyResponse {
    pub policy_id: Uuid,
    pub policy_version: i32,
    pub issued_at: String,
    pub expires_at: String,
    pub device_status: String,
    pub heartbeat_interval_seconds: i32,
    pub posture_interval_seconds: i32,
    pub agent_failure_mode: String,
    pub applications: Vec<DeviceAppPolicy>,
    pub signature: String,
}

/// Talks to iam-tenant-svc's /api/v1/endpoint API (Section 10). enrollment/start is deliberately
/// absent: iam-login-portal calls it server-side with the browser's session, so this agent never
/// holds a session token (see [`crate::enrollment`]). enrollment/complete authenticates via the
/// key-bound transaction + proof-of-possession; everything after that uses [`sign_request`].
pub struct ApiClient {
    http: reqwest::Client,
    base_url: String,
}

impl ApiClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self { http: reqwest::Client::new(), base_url: base_url.into() }
    }

    pub async fn complete_enrollment(&self, request: &EnrollmentCompleteRequest) -> Result<EnrollmentCompleteResponse, ApiError> {
        let response = self
            .http
            .post(format!("{}/api/v1/endpoint/enrollment/complete", self.base_url))
            .json(request)
            .send()
            .await?;
        parse_json(response).await
    }

    pub async fn heartbeat(&self, tenant_id: &str, device_id: Uuid, key: &dyn KeyProvider, request: &HeartbeatRequest) -> Result<(), ApiError> {
        let (timestamp, signature) = sign_request(device_id, key);
        let response = self
            .http
            .post(format!("{}/api/v1/endpoint/devices/{}/heartbeat?tenantId={}", self.base_url, device_id, tenant_id))
            .header("X-Device-Signature", signature)
            .header("X-Device-Timestamp", timestamp)
            .json(request)
            .send()
            .await?;
        ensure_success(response).await
    }

    pub async fn fetch_policy(&self, tenant_id: &str, device_id: Uuid, key: &dyn KeyProvider) -> Result<DevicePolicyResponse, ApiError> {
        let (timestamp, signature) = sign_request(device_id, key);
        let response = self
            .http
            .get(format!("{}/api/v1/endpoint/devices/{}/policy?tenantId={}", self.base_url, device_id, tenant_id))
            .header("X-Device-Signature", signature)
            .header("X-Device-Timestamp", timestamp)
            .send()
            .await?;
        parse_json(response).await
    }
}

/// Signs `"{deviceId}:{timestamp}"` -- must match
/// DeviceTrustService.requireDeviceProof on the backend byte-for-byte.
/// Deliberately truncated to whole seconds (no fractional part): Java's
/// `Instant.toString()` only omits the fractional component when it's
/// exactly zero, so sending whole-second timestamps is what guarantees the
/// string the backend re-serializes for signature verification is
/// identical to the one this function signed -- any fractional precision
/// this side chose would have to exactly survive Java's own trimming rules
/// (groups of 3 digits, zero-padded) to still match, which is fragile to
/// depend on where simply not sending one is free.
pub fn sign_request(device_id: Uuid, key: &dyn KeyProvider) -> (String, String) {
    let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let signed_data = format!("{}:{}", device_id, timestamp);
    let signature = key.sign(signed_data.as_bytes());
    (timestamp, signature)
}

async fn parse_json<T: for<'de> Deserialize<'de>>(response: reqwest::Response) -> Result<T, ApiError> {
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        return Err(ApiError::Backend { status: status.as_u16(), body });
    }
    serde_json::from_str(&body).map_err(|e| ApiError::Backend { status: status.as_u16(), body: format!("malformed response body: {e}; raw: {body}") })
}

async fn ensure_success(response: reqwest::Response) -> Result<(), ApiError> {
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(ApiError::Backend { status: status.as_u16(), body });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_provider::SoftwareEd25519KeyProvider;

    #[test]
    fn sign_request_produces_a_timestamp_with_no_fractional_seconds() {
        let (provider, _) = SoftwareEd25519KeyProvider::generate();
        let (timestamp, _signature) = sign_request(Uuid::new_v4(), &provider);
        assert!(timestamp.ends_with('Z'));
        assert!(!timestamp.contains('.'));
    }
}
