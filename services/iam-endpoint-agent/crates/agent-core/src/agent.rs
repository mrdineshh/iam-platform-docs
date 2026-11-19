use crate::api_client::{ApiClient, DeviceBackend, EnrollmentCompleteRequest};
use crate::config::AgentConfig;
use crate::device_identity::{fingerprint_hash, hash_value, DeviceIdentity, HardwareAttributes, FINGERPRINT_VERSION};
use crate::enrollment::{obtain_enrollment_authorization_via_browser, BrowserLauncher};
use crate::key_provider::{HardwareKeyStore, KeyProvider, SharedKey, SoftwareEd25519KeyProvider, SoftwareKeyMaterial};
use crate::posture::PostureCollector;
use crate::secure_storage::{PolicyStore, SecureStorage, StorageError, StoredState};
use crate::sync::{SyncConfig, SyncEngine};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Auth(#[from] crate::enrollment::EnrollmentAuthError),
    #[error(transparent)]
    Api(#[from] crate::api_client::ApiError),
    #[error("invalid agent configuration: {0}")]
    Config(String),
    #[error("already enrolled (device id {0}) -- re-enrollment is not yet supported by this version")]
    AlreadyEnrolled(Uuid),
    #[error("enrollment has not completed yet -- nothing to run")]
    NotEnrolled,
    #[error("this device's key is stored in the TPM but cannot be opened ({0}); re-register the device with --reset-enrollment")]
    HardwareKeyUnavailable(String),
    #[error("the stored identity has no device key; re-register the device with --reset-enrollment")]
    NoKey,
}

/// Top-level orchestration the `iam-endpoint-agent` binary drives. Everything here is platform-agnostic;
/// the binary crate owns the OS service lifecycle (start/stop) and hands this a shutdown signal.
pub struct Agent {
    config: AgentConfig,
    data_dir: PathBuf,
    storage: SecureStorage,
    api: ApiClient,
    agent_version: String,
    local_log: Option<std::sync::Arc<dyn crate::local_log::LocalEventSink>>,
    hardware_keys: Option<Arc<dyn HardwareKeyStore>>,
    update_installer: Option<Arc<dyn crate::update::UpdateInstaller>>,
    browser_block: Option<Arc<dyn crate::browser_block::BrowserBlockController>>,
}

impl Agent {
    /// `data_dir` holds `state.json` (identity and key) and `policy-cache.json` (last-known-good policy).
    pub fn new(config: AgentConfig, data_dir: impl Into<PathBuf>, agent_version: impl Into<String>) -> Self {
        let data_dir = data_dir.into();
        Self {
            api: ApiClient::new(config.backend_base_url.clone()),
            storage: SecureStorage::new(data_dir.join("state.json")),
            data_dir,
            config,
            agent_version: agent_version.into(),
            local_log: None,
            hardware_keys: None,
            update_installer: None,
            browser_block: None,
        }
    }

    /// Offers the platform's way of blocking personal Microsoft sign-in in the browsers. Without one the setting is ignored.
    pub fn with_browser_block(mut self, controller: Arc<dyn crate::browser_block::BrowserBlockController>) -> Self {
        self.browser_block = Some(controller);
        self
    }

    /// Offers the platform's installer launcher. Without one (or without a release key in the config) updates are off.
    pub fn with_update_installer(mut self, installer: Arc<dyn crate::update::UpdateInstaller>) -> Self {
        self.update_installer = Some(installer);
        self
    }

    /// Offers a TPM-backed key store (Windows CNG). Without one, or when it declines, the software key is used.
    pub fn with_hardware_keys(mut self, store: Arc<dyn HardwareKeyStore>) -> Self {
        self.hardware_keys = Some(store);
        self
    }

    /// Mirrors agent events to the device's own log (see [`crate::local_log`]).
    pub fn with_local_log(mut self, sink: std::sync::Arc<dyn crate::local_log::LocalEventSink>) -> Self {
        self.local_log = Some(sink);
        self
    }

    /// Section 6.1, steps 1-10. Refuses to run again once a device id is already stored -- re-enrolment
    /// (Section 6.3 "approval expiry and re-enrolment policy") is out of scope for this version.
    pub async fn enroll(&self, hardware: HardwareAttributes, ownership: &str, launcher: &dyn BrowserLauncher) -> Result<Uuid, AgentError> {
        if let Some(existing) = self.storage.load()? {
            if let Some(device_id) = existing.device_id {
                return Err(AgentError::AlreadyEnrolled(device_id));
            }
        }

        let identity = DeviceIdentity::new();
        // The key is generated *before* sign-in so its thumbprint can be committed to up front --
        // the backend then only lets this exact key complete the resulting transaction.
        let chosen = self.choose_key(&identity);
        let outcome = self.enroll_with_key(identity, hardware, ownership, launcher, &chosen).await;
        if outcome.is_err() {
            // Enrollment did not finish: do not leave a key behind in the TPM that nothing will ever use.
            if let (Some(name), Some(store)) = (&chosen.hardware_key_name, &self.hardware_keys) {
                store.delete(name);
            }
        }
        outcome
    }

    async fn enroll_with_key(
        &self,
        identity: DeviceIdentity,
        hardware: HardwareAttributes,
        ownership: &str,
        launcher: &dyn BrowserLauncher,
        chosen: &ChosenKey,
    ) -> Result<Uuid, AgentError> {
        let key_provider = chosen.provider.clone();

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
            key_material: chosen.software_material.clone(),
            hardware_key_name: chosen.hardware_key_name.clone(),
            device_id: Some(response.device_id),
            certificate_pem: response.certificate_pem,
            issuing_ca_pem: response.issuing_ca_pem,
        })?;

        tracing::info!(device_id = %response.device_id, status = %response.status, assurance = key_provider.assurance_level().as_str(), "enrollment complete");
        Ok(response.device_id)
    }

    /// Runs the steady-state sync loop (signed policy fetch + verification + heartbeat) until `shutdown`
    /// fires. Returns promptly when it does, so the OS service can report "stopped".
    pub async fn run(&self, collector: impl PostureCollector, shutdown: watch::Receiver<bool>) -> Result<(), AgentError> {
        let state = self.storage.load()?.ok_or(AgentError::NotEnrolled)?;
        let device_id = state.device_id.ok_or(AgentError::NotEnrolled)?;
        let tenant_id = self.config.tenant_uuid().map_err(AgentError::Config)?;
        let key = self.load_key(&state)?;

        let backend = DeviceBackend::new(
            ApiClient::new(self.config.backend_base_url.clone()),
            tenant_id.to_string(),
            device_id,
            Box::new(SharedKey(key.clone())),
        );
        let engine = SyncEngine::new(
            backend,
            collector,
            PolicyStore::new(self.data_dir.join("policy-cache.json")),
            SyncConfig {
                tenant_id,
                device_id,
                transit_public_key_base64: self.config.device_policy_public_key_base64.clone(),
                agent_version: self.agent_version.clone(),
                default_interval: Duration::from_secs(self.config.heartbeat_interval_seconds),
                max_backoff: Duration::from_secs(3600),
            },
        )?
        .with_integrity(crate::integrity::IntegrityMonitor::baseline(self.watched_files()));
        let engine = match &self.local_log {
            Some(sink) => engine.with_local_log(sink.clone()),
            None => engine,
        };
        let engine = match &self.browser_block {
            Some(controller) => engine.with_browser_block(controller.clone()),
            None => engine,
        };

        tracing::info!(%device_id, "agent running");

        // Device-bound sign-in endpoint. Optional and isolated: if it cannot start (no free port, bad URL) the agent
        // carries on reporting exactly as before.
        let local_api = if self.config.local_api_enabled {
            match crate::local_api::origin_of(&self.config.enrollment_login_url) {
                Some(allowed_origin) => Some(tokio::spawn(crate::local_api::run(
                    crate::local_api::LocalApiContext {
                        tenant_id,
                        device_id,
                        allowed_origin,
                        agent_version: self.agent_version.clone(),
                        signer: key.clone(),
                    },
                    shutdown.clone(),
                ))),
                None => {
                    tracing::warn!("enrollment_login_url has no usable origin; device sign-in endpoint not started");
                    None
                }
            }
        } else {
            None
        };

        let update_task = self.start_update_loop(tenant_id, device_id, key.clone(), shutdown.clone());

        engine.run(shutdown).await;
        if let Some(task) = local_api {
            task.abort();
        }
        if let Some(task) = update_task {
            task.abort();
        }
        Ok(())
    }
}

impl Agent {
    /// Starts the automatic-update check when (and only when) an administrator configured a release key AND the platform
    /// adapter supplied an installer. Isolated from the sync loop: it cannot slow or stop reporting.
    fn start_update_loop(&self, tenant_id: Uuid, device_id: Uuid, key: Arc<dyn KeyProvider>, shutdown: watch::Receiver<bool>) -> Option<tokio::task::JoinHandle<()>> {
        let release_key = self.config.release_public_key_base64.as_deref().map(str::trim).filter(|k| !k.is_empty())?.to_string();
        let installer = self.update_installer.clone()?;
        struct SharedInstaller(Arc<dyn crate::update::UpdateInstaller>);
        impl crate::update::UpdateInstaller for SharedInstaller {
            fn install(&self, package: &std::path::Path) -> Result<(), String> {
                self.0.install(package)
            }
        }
        struct Reporter {
            api: ApiClient,
            tenant_id: String,
            device_id: Uuid,
            key: Arc<dyn KeyProvider>,
            local_log: Option<Arc<dyn crate::local_log::LocalEventSink>>,
        }
        impl crate::update::UpdateReporter for Reporter {
            fn report(&self, event_type: &str, severity: &str, detail: &str) {
                if let Some(sink) = &self.local_log {
                    sink.write(severity, event_type, detail);
                }
                let event = crate::api_client::AgentEvent {
                    event_type: event_type.to_string(),
                    severity: severity.to_string(),
                    metadata_json: Some(serde_json::json!({ "reason": detail }).to_string()),
                };
                let (api, tenant, key) = (self.api.clone(), self.tenant_id.clone(), self.key.clone());
                let device_id = self.device_id;
                tokio::spawn(async move {
                    if let Err(err) = api.post_event(&tenant, device_id, key.as_ref(), &event).await {
                        tracing::warn!(error = %err, "could not deliver update event");
                    }
                });
            }
        }
        let api = ApiClient::new(self.config.backend_base_url.clone());
        let source = crate::update::PlatformUpdateSource { api: api.clone(), tenant_id: tenant_id.to_string(), device_id, key: key.clone() };
        let reporter = Arc::new(Reporter { api, tenant_id: tenant_id.to_string(), device_id, key, local_log: self.local_log.clone() });
        tracing::info!("automatic updates are on (release key configured)");
        Some(tokio::spawn(crate::update::run_update_loop(
            source,
            SharedInstaller(installer),
            release_key,
            self.agent_version.clone(),
            self.data_dir.join("updates"),
            reporter,
            shutdown,
        )))
    }

    /// A new device key for this machine: TPM-backed when allowed and available, otherwise the software key. Never fails:
    /// whatever goes wrong with the hardware just means "use the software key", with the reason logged.
    fn choose_key(&self, identity: &DeviceIdentity) -> ChosenKey {
        if self.config.prefer_hardware_key {
            if let Some(store) = &self.hardware_keys {
                let name = format!("IamEndpointAgent-{}", identity.device_instance_id);
                match store.create(&name) {
                    Some(provider) => {
                        tracing::info!(assurance = provider.assurance_level().as_str(), "using a hardware-backed device key");
                        return ChosenKey { provider, software_material: None, hardware_key_name: Some(name) };
                    }
                    None => tracing::warn!("no usable TPM key store on this machine; using a software device key (lower assurance)"),
                }
            }
        }
        let (provider, material) = SoftwareEd25519KeyProvider::generate();
        ChosenKey { provider: Arc::new(provider), software_material: Some(material), hardware_key_name: None }
    }

    /// The key an existing identity signs with. A software key comes from the stored material; a TPM key is opened by name.
    /// A TPM key that cannot be opened is an error, never silently replaced by a different key (that would be a new
    /// identity the platform has not registered).
    fn load_key(&self, state: &StoredState) -> Result<Arc<dyn KeyProvider>, AgentError> {
        if let Some(name) = &state.hardware_key_name {
            let store = self.hardware_keys.as_ref().ok_or_else(|| AgentError::HardwareKeyUnavailable("no hardware key store on this platform".into()))?;
            return store.open(name).ok_or_else(|| AgentError::HardwareKeyUnavailable(format!("key {name} not found or TPM not ready")));
        }
        match &state.key_material {
            Some(material) => Ok(Arc::new(SoftwareEd25519KeyProvider::from_material(material))),
            None => Err(AgentError::NoKey),
        }
    }

    /// The device id if this machine has already completed enrollment.
    pub fn enrolled_device(&self) -> Result<Option<Uuid>, AgentError> {
        Ok(self.storage.load()?.and_then(|s| s.device_id))
    }

    /// Re-enrolment (spec Section 6.3): forgets this machine's device identity, key and cached policy so it can
    /// enroll again as a NEW device. The old device record stays on the platform until an administrator revokes it --
    /// the agent cannot and must not delete platform records. Returns the old device id, if there was one.
    /// The caller must make sure the service is stopped first, or it would keep using the old identity in memory.
    pub fn reset_enrollment(&self) -> Result<Option<Uuid>, AgentError> {
        let state = self.storage.load()?;
        let previous = state.as_ref().and_then(|s| s.device_id);
        // A TPM key belongs to the identity being forgotten; leave none behind.
        if let (Some(name), Some(store)) = (state.as_ref().and_then(|s| s.hardware_key_name.clone()), &self.hardware_keys) {
            store.delete(&name);
        }
        for name in ["state.json", "policy-cache.json"] {
            match std::fs::remove_file(self.data_dir.join(name)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(StorageError::Io(e).into()),
            }
        }
        Ok(previous)
    }

    /// Read-only summary for `--status` (no network, no secrets). Reads the same files the service writes.
    pub fn status_report(&self) -> Result<String, AgentError> {
        let state = self.storage.load()?;
        let cache = PolicyStore::new(self.data_dir.join("policy-cache.json")).load()?;
        Ok(crate::status::render_status(state.as_ref(), cache.as_ref(), &self.config, crate::sync::unix_now()))
    }

    /// Files whose silent modification means someone is tampering with the agent: its own program and its
    /// configuration. (The device key file is deliberately not here: the agent itself rewrites state.)
    fn watched_files(&self) -> Vec<(String, PathBuf)> {
        let mut files = vec![("config.json".to_string(), self.data_dir.join("config.json"))];
        if let Ok(exe) = std::env::current_exe() {
            files.push(("agent program".to_string(), exe));
        }
        files
    }
}

/// The key picked for a new enrollment and how to remember it.
struct ChosenKey {
    provider: Arc<dyn KeyProvider>,
    software_material: Option<SoftwareKeyMaterial>,
    hardware_key_name: Option<String>,
}

fn hostname_or_none() -> Option<String> {
    std::env::var("COMPUTERNAME").ok().or_else(|| std::env::var("HOSTNAME").ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent_in(dir: &std::path::Path) -> Agent {
        let config: AgentConfig = serde_json::from_value(serde_json::json!({
            "backend_base_url": "https://iam.example.com",
            "enrollment_login_url": "https://login.example.com/device-enroll",
            "tenant_id": "11111111-1111-4111-8111-111111111111",
            "device_policy_public_key_base64": "AAAA"
        }))
        .unwrap();
        Agent::new(config, dir, "test")
    }

    use crate::key_provider::KeyAssuranceLevel;
    use std::sync::Mutex;

    /// A stand-in TPM: a software key that claims hardware assurance, and records what was created and deleted.
    struct FakeTpm {
        available: bool,
        created: Mutex<Vec<String>>,
        deleted: Mutex<Vec<String>>,
        keys: Mutex<Vec<(String, Arc<dyn KeyProvider>)>>,
    }

    struct FakeHardwareKey(SoftwareEd25519KeyProvider);
    impl KeyProvider for FakeHardwareKey {
        fn algorithm(&self) -> &'static str {
            "ECDSA_P256"
        }
        fn assurance_level(&self) -> KeyAssuranceLevel {
            KeyAssuranceLevel::HardwareTpm
        }
        fn public_key_base64(&self) -> String {
            self.0.public_key_base64()
        }
        fn sign(&self, data: &[u8]) -> String {
            self.0.sign(data)
        }
    }

    impl FakeTpm {
        fn new(available: bool) -> Arc<Self> {
            Arc::new(Self { available, created: Mutex::default(), deleted: Mutex::default(), keys: Mutex::default() })
        }
    }

    impl HardwareKeyStore for FakeTpm {
        fn create(&self, name: &str) -> Option<Arc<dyn KeyProvider>> {
            if !self.available {
                return None;
            }
            let key: Arc<dyn KeyProvider> = Arc::new(FakeHardwareKey(SoftwareEd25519KeyProvider::generate().0));
            self.created.lock().unwrap().push(name.to_string());
            self.keys.lock().unwrap().push((name.to_string(), key.clone()));
            Some(key)
        }
        fn open(&self, name: &str) -> Option<Arc<dyn KeyProvider>> {
            self.keys.lock().unwrap().iter().find(|(n, _)| n == name).map(|(_, k)| k.clone())
        }
        fn delete(&self, name: &str) {
            self.deleted.lock().unwrap().push(name.to_string());
        }
    }

    fn state_with(key_material: Option<SoftwareKeyMaterial>, hardware_key_name: Option<String>) -> StoredState {
        let mut state = crate::secure_storage::test_state(Uuid::new_v4());
        state.key_material = key_material;
        state.hardware_key_name = hardware_key_name;
        state
    }

    #[test]
    fn a_new_enrollment_uses_the_tpm_key_when_one_is_available_and_stores_only_its_name() {
        let dir = std::env::temp_dir().join(format!("iam-key-{}", Uuid::new_v4()));
        let tpm = FakeTpm::new(true);
        let agent = agent_in(&dir).with_hardware_keys(tpm.clone());
        let chosen = agent.choose_key(&DeviceIdentity::new());
        assert_eq!(chosen.provider.assurance_level(), KeyAssuranceLevel::HardwareTpm);
        assert!(chosen.software_material.is_none(), "no private key bytes may be stored for a TPM key");
        let name = chosen.hardware_key_name.expect("the key name is remembered");
        assert!(name.starts_with("IamEndpointAgent-"));
        assert_eq!(tpm.created.lock().unwrap().as_slice(), [name]);
    }

    #[test]
    fn without_a_usable_tpm_a_software_key_is_used() {
        let dir = std::env::temp_dir().join(format!("iam-key-{}", Uuid::new_v4()));
        for agent in [agent_in(&dir), agent_in(&dir).with_hardware_keys(FakeTpm::new(false))] {
            let chosen = agent.choose_key(&DeviceIdentity::new());
            assert_eq!(chosen.provider.assurance_level(), KeyAssuranceLevel::Software);
            assert!(chosen.software_material.is_some());
            assert!(chosen.hardware_key_name.is_none());
        }
    }

    #[test]
    fn the_config_switch_forces_a_software_key_even_when_a_tpm_exists() {
        let dir = std::env::temp_dir().join(format!("iam-key-{}", Uuid::new_v4()));
        let tpm = FakeTpm::new(true);
        let mut agent = agent_in(&dir).with_hardware_keys(tpm.clone());
        agent.config.prefer_hardware_key = false;
        let chosen = agent.choose_key(&DeviceIdentity::new());
        assert_eq!(chosen.provider.assurance_level(), KeyAssuranceLevel::Software);
        assert!(tpm.created.lock().unwrap().is_empty(), "the TPM must not be touched at all");
    }

    #[test]
    fn an_existing_software_identity_keeps_its_key_even_if_a_tpm_is_now_available() {
        let dir = std::env::temp_dir().join(format!("iam-key-{}", Uuid::new_v4()));
        let agent = agent_in(&dir).with_hardware_keys(FakeTpm::new(true));
        let (provider, material) = SoftwareEd25519KeyProvider::generate();
        let key = agent.load_key(&state_with(Some(material), None)).unwrap();
        assert_eq!(key.public_key_base64(), provider.public_key_base64());
        assert_eq!(key.assurance_level(), KeyAssuranceLevel::Software);
    }

    #[test]
    fn a_tpm_identity_reopens_its_tpm_key_by_name() {
        let dir = std::env::temp_dir().join(format!("iam-key-{}", Uuid::new_v4()));
        let tpm = FakeTpm::new(true);
        let agent = agent_in(&dir).with_hardware_keys(tpm.clone());
        let chosen = agent.choose_key(&DeviceIdentity::new());
        let key = agent.load_key(&state_with(None, chosen.hardware_key_name.clone())).unwrap();
        assert_eq!(key.public_key_base64(), chosen.provider.public_key_base64());
    }

    #[test]
    fn a_tpm_key_that_cannot_be_opened_is_an_error_and_never_replaced_by_another_key() {
        let dir = std::env::temp_dir().join(format!("iam-key-{}", Uuid::new_v4()));
        let with_store = agent_in(&dir).with_hardware_keys(FakeTpm::new(true));
        assert!(matches!(with_store.load_key(&state_with(None, Some("missing".into()))), Err(AgentError::HardwareKeyUnavailable(_))));
        let without_store = agent_in(&dir);
        assert!(matches!(without_store.load_key(&state_with(None, Some("any".into()))), Err(AgentError::HardwareKeyUnavailable(_))));
        assert!(matches!(without_store.load_key(&state_with(None, None)), Err(AgentError::NoKey)));
    }

    #[test]
    fn reset_forgets_identity_and_policy_cache_and_reports_the_old_device() {
        let dir = std::env::temp_dir().join(format!("iam-reset-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let old = Uuid::new_v4();
        SecureStorage::new(dir.join("state.json")).save(&crate::secure_storage::test_state(old)).unwrap();
        std::fs::write(dir.join("policy-cache.json"), "{}").unwrap();
        std::fs::write(dir.join("config.json"), "{}").unwrap();

        let agent = agent_in(&dir);
        assert_eq!(agent.reset_enrollment().unwrap(), Some(old));
        assert!(!dir.join("state.json").exists());
        assert!(!dir.join("policy-cache.json").exists());
        assert!(dir.join("config.json").exists(), "configuration must survive a reset");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn reset_on_a_machine_that_never_enrolled_is_harmless() {
        let dir = std::env::temp_dir().join(format!("iam-reset-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(agent_in(&dir).reset_enrollment().unwrap(), None);
        std::fs::remove_dir_all(dir).ok();
    }
}
