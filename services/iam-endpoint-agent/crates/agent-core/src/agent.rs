use crate::api_client::{ApiClient, EnrollmentCompleteRequest};
use crate::config::AgentConfig;
use crate::device_identity::{fingerprint_hash, hash_value, DeviceIdentity, HardwareAttributes, FINGERPRINT_VERSION};
use crate::enrollment::{obtain_enrollment_authorization_via_browser, BrowserLauncher};
use crate::key_provider::{KeyProvider, SoftwareEd25519KeyProvider};
use crate::policy_verifier::verify_policy;
use crate::secure_storage::{SecureStorage, StorageError, StoredState};
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Auth(#[from] crate::enrollment::EnrollmentAuthError),
    #[error(transparent)]
    Api(#[from] crate::api_client::ApiError),
    #[error("already enrolled (device id {0}) -- re-enrollment is not yet supported by this version")]
    AlreadyEnrolled(Uuid),
    #[error("enrollment has not completed yet -- nothing to run")]
    NotEnrolled,
}

/// Top-level orchestration the `iam-endpoint-agent` binary's platform/windows
/// Service entrypoint drives. Everything here is platform-agnostic; the
/// binary crate owns the Windows Service lifecycle (start/stop/pause) and
/// calls into this.
pub struct Agent {
    config: AgentConfig,
    storage: SecureStorage,
    api: ApiClient,
    agent_version: String,
}

impl Agent {
    pub fn new(config: AgentConfig, storage_path: impl AsRef<std::path::Path>, agent_version: impl Into<String>) -> Self {
        let api = ApiClient::new(config.backend_base_url.clone());
        Self { storage: SecureStorage::new(storage_path), config, api, agent_version: agent_version.into() }
    }

    /// Section 6.1, steps 1-10. Idempotent in the sense that it refuses to
    /// run again once a device id is already stored -- re-enrollment
    /// (Section 6.3 "approval expiry and re-enrolment policy") is
    /// deliberately out of scope for this version; see AgentError::AlreadyEnrolled.
    pub async fn enroll(&self, hardware: HardwareAttributes, ownership: &str, launcher: &dyn BrowserLauncher) -> Result<Uuid, AgentError> {
        if let Some(existing) = self.storage.load()? {
            if let Some(device_id) = existing.device_id {
                return Err(AgentError::AlreadyEnrolled(device_id));
            }
        }

        let identity = DeviceIdentity::new();
        // The key is generated *before* sign-in so its thumbprint can be committed to up front --
        // the backend then only lets this exact key complete the resulting transaction.
        let (key_provider, key_material) = SoftwareEd25519KeyProvider::generate();

        let authorization =
            obtain_enrollment_authorization_via_browser(&self.config.enrollment_login_url, &key_provider.key_thumbprint(), launcher).await?;

        let proof_of_possession = key_provider.sign(authorization.nonce.as_bytes());
        let fingerprint = fingerprint_hash(&self.config.tenant_id, "WINDOWS", &hardware);

        let request = EnrollmentCompleteRequest {
            enrollment_transaction_id: authorization.enrollment_transaction_id,
            device_instance_id: identity.device_instance_id,
            platform: "WINDOWS".to_string(),
            os_version: hardware.os_version.clone(),
            hostname: hostname_or_none(),
            manufacturer: hardware.manufacturer.clone(),
            model: hardware.model.clone(),
            hardware_uuid_hash: hardware.hardware_uuid.as_deref().map(hash_value),
            serial_hash: hardware.serial_number.as_deref().map(hash_value),
            ownership: ownership.to_string(),
            agent_version: self.agent_version.clone(),
            public_key: key_provider.public_key_base64(),
            key_algorithm: key_provider.algorithm().to_string(),
            assurance_level: key_provider.assurance_level().as_str().to_string(),
            proof_of_possession,
            fingerprint_version: FINGERPRINT_VERSION,
            fingerprint_hash: fingerprint,
        };

        let response = self.api.complete_enrollment(&request).await?;

        self.storage.save(&StoredState {
            identity,
            key_algorithm: key_provider.algorithm().to_string(),
            key_assurance_level: key_provider.assurance_level(),
            key_material,
            device_id: Some(response.device_id),
            certificate_pem: response.certificate_pem,
            issuing_ca_pem: response.issuing_ca_pem,
        })?;

        tracing::info!(device_id = %response.device_id, status = %response.status, "enrollment complete");
        Ok(response.device_id)
    }

    /// Fetches, verifies, and returns the current signed policy (Section
    /// 10.3) -- an invalid/unverifiable signature is returned as an error,
    /// never silently accepted (Section 16 "Policy rejected" on signature
    /// failure, not a warning).
    pub async fn fetch_and_verify_policy(&self) -> Result<crate::api_client::DevicePolicyResponse, AgentError> {
        let state = self.storage.load()?.ok_or(AgentError::NotEnrolled)?;
        let device_id = state.device_id.ok_or(AgentError::NotEnrolled)?;
        let key_provider = SoftwareEd25519KeyProvider::from_material(&state.key_material);

        let policy = self.api.fetch_policy(&self.config.tenant_id, device_id, &key_provider).await?;
        if let Err(err) = verify_policy(&policy, &self.config.device_policy_public_key_base64) {
            tracing::error!(error = %err, "rejecting device policy: signature did not verify");
            // Deliberately still returned as an Err from the caller's perspective via a
            // dedicated variant would be cleaner; kept simple here (Api-shaped error) since the
            // caller's only correct response to either case is "do not trust this policy".
            return Err(AgentError::Api(crate::api_client::ApiError::Backend { status: 0, body: err.to_string() }));
        }
        Ok(policy)
    }

    /// Runs the heartbeat loop forever -- the Windows Service entrypoint
    /// spawns this and only returns control to the service manager on
    /// stop/shutdown, not when this function returns (it never does).
    pub async fn run_heartbeat_loop(&self) -> Result<(), AgentError> {
        let state = self.storage.load()?.ok_or(AgentError::NotEnrolled)?;
        let device_id = state.device_id.ok_or(AgentError::NotEnrolled)?;
        let key_provider = SoftwareEd25519KeyProvider::from_material(&state.key_material);

        crate::heartbeat::run_heartbeat_loop(
            &self.api,
            &self.config.tenant_id,
            device_id,
            &key_provider,
            &self.agent_version,
            Duration::from_secs(self.config.heartbeat_interval_seconds),
            Duration::from_secs(3600),
        )
        .await
    }
}

fn hostname_or_none() -> Option<String> {
    std::env::var("COMPUTERNAME").ok().or_else(|| std::env::var("HOSTNAME").ok())
}
