use crate::key_provider::KeyProvider;
use crate::posture::PostureSignals;
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

/// Sent to `/devices/{id}/events` (DeviceEventRequest). `severity` is INFO, WARNING or CRITICAL.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentEvent {
    pub event_type: String,
    pub severity: String,
    pub metadata_json: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeviceAppPolicy {
    pub application_id: Uuid,
    pub pending_access: bool,
    pub offline_access: bool,
    pub offline_grace_seconds: i64,
    pub failure_mode: String,
}

/// Tenant-wide browser controls, signed on their own (see `policy_verifier::BrowserControlsVerdict`). Older platforms do not send
/// the block at all; the agent then leaves the browsers as they are.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BrowserControls {
    pub block_personal_microsoft: bool,
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DevicePolicyResponse {
    pub tenant_id: Uuid,
    pub device_id: Uuid,
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
    /// Raw and UNVERIFIED as received; `verify_policy` checks it, records the verdict and clears this field, so nothing
    /// downstream (the cache on disk, local decisions) ever holds an unchecked claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_controls: Option<BrowserControls>,
}

/// Talks to iam-tenant-svc's /api/v1/endpoint API (Section 10). enrollment/start is deliberately
/// absent: iam-login-portal calls it server-side with the browser's session, so this agent never
/// holds a session token (see [`crate::enrollment`]). enrollment/complete authenticates via the
/// key-bound transaction + proof-of-possession; everything after that uses [`sign_request`].
#[derive(Clone)]
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

    /// GET /devices/{id}/agent-update: the newest release newer than `current_version`, or `None` (HTTP 204).
    pub async fn agent_update_offer(&self, tenant_id: &str, device_id: Uuid, key: &dyn KeyProvider, current_version: &str) -> Result<Option<crate::update::ReleaseOffer>, ApiError> {
        let (timestamp, signature) = sign_request(device_id, key);
        let response = self
            .http
            .get(format!("{}/api/v1/endpoint/devices/{}/agent-update", self.base_url, device_id))
            .query(&[("tenantId", tenant_id), ("currentVersion", current_version)])
            .header("X-Device-Signature", signature)
            .header("X-Device-Timestamp", timestamp)
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::NO_CONTENT {
            return Ok(None);
        }
        parse_json(response).await.map(Some)
    }

    /// GET the installer bytes. Refuses to read more than the update size limit.
    pub async fn agent_update_package(&self, tenant_id: &str, device_id: Uuid, key: &dyn KeyProvider, release_id: Uuid) -> Result<Vec<u8>, ApiError> {
        let (timestamp, signature) = sign_request(device_id, key);
        let response = self
            .http
            .get(format!("{}/api/v1/endpoint/devices/{}/agent-releases/{}/package", self.base_url, device_id, release_id))
            .query(&[("tenantId", tenant_id)])
            .header("X-Device-Signature", signature)
            .header("X-Device-Timestamp", timestamp)
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            return Err(ApiError::Backend { status: status.as_u16(), body: response.text().await.unwrap_or_default() });
        }
        if response.content_length().is_some_and(|n| n > crate::update::MAX_PACKAGE_BYTES) {
            return Err(ApiError::Backend { status: status.as_u16(), body: "package larger than the update size limit".into() });
        }
        let bytes = response.bytes().await?;
        if bytes.len() as u64 > crate::update::MAX_PACKAGE_BYTES {
            return Err(ApiError::Backend { status: status.as_u16(), body: "package larger than the update size limit".into() });
        }
        Ok(bytes.to_vec())
    }

    /// PATCH /devices/{id}/posture. Sends facts only; the server decides what they mean.
    pub async fn report_posture(&self, tenant_id: &str, device_id: Uuid, key: &dyn KeyProvider, signals: &PostureSignals) -> Result<(), ApiError> {
        let (timestamp, signature) = sign_request(device_id, key);
        let response = self
            .http
            .patch(format!("{}/api/v1/endpoint/devices/{}/posture?tenantId={}", self.base_url, device_id, tenant_id))
            .header("X-Device-Signature", signature)
            .header("X-Device-Timestamp", timestamp)
            .json(&serde_json::json!({ "signals": signals }))
            .send()
            .await?;
        ensure_success(response).await
    }

    pub async fn post_event(&self, tenant_id: &str, device_id: Uuid, key: &dyn KeyProvider, event: &AgentEvent) -> Result<(), ApiError> {
        let (timestamp, signature) = sign_request(device_id, key);
        let response = self
            .http
            .post(format!("{}/api/v1/endpoint/devices/{}/events?tenantId={}", self.base_url, device_id, tenant_id))
            .header("X-Device-Signature", signature)
            .header("X-Device-Timestamp", timestamp)
            .json(event)
            .send()
            .await?;
        ensure_success(response).await
    }
}

/// The production [`crate::sync::Backend`]: this device's identity (tenant, device id, signing key) bound
/// to an [`ApiClient`], so the sync engine can call "fetch my policy" without knowing about signing.
pub struct DeviceBackend {
    api: ApiClient,
    tenant_id: String,
    device_id: Uuid,
    key: Box<dyn KeyProvider>,
}

impl DeviceBackend {
    pub fn new(api: ApiClient, tenant_id: impl Into<String>, device_id: Uuid, key: Box<dyn KeyProvider>) -> Self {
        Self { api, tenant_id: tenant_id.into(), device_id, key }
    }
}

impl crate::sync::Backend for DeviceBackend {
    fn fetch_policy(&self) -> impl std::future::Future<Output = Result<DevicePolicyResponse, ApiError>> + Send {
        self.api.fetch_policy(&self.tenant_id, self.device_id, self.key.as_ref())
    }

    fn heartbeat(&self, request: &HeartbeatRequest) -> impl std::future::Future<Output = Result<(), ApiError>> + Send {
        self.api.heartbeat(&self.tenant_id, self.device_id, self.key.as_ref(), request)
    }

    fn post_event(&self, event: &AgentEvent) -> impl std::future::Future<Output = Result<(), ApiError>> + Send {
        self.api.post_event(&self.tenant_id, self.device_id, self.key.as_ref(), event)
    }

    fn report_posture(&self, signals: &PostureSignals) -> impl std::future::Future<Output = Result<(), ApiError>> + Send {
        self.api.report_posture(&self.tenant_id, self.device_id, self.key.as_ref(), signals)
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
