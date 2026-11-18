use crate::device_identity::DeviceIdentity;
use crate::key_provider::{KeyAssuranceLevel, SoftwareKeyMaterial};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Everything the agent needs to remember between runs about *who it is*. Persisted as JSON today --
/// protection-at-rest (Windows DPAPI, so another local user or a copied file can't read it) is a
/// platform-layer concern that is **not yet implemented**; this crate only defines *what* is persisted.
/// That gap matters most for `key_material` while [`KeyAssuranceLevel::Software`] is in use: a
/// hardware-backed provider (TPM/CNG) never has private key bytes to persist at all, which is exactly why
/// it is the preferred assurance level (spec Section 5.3; tracked as OQ-17).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredState {
    pub identity: DeviceIdentity,
    pub key_algorithm: String,
    pub key_assurance_level: KeyAssuranceLevel,
    /// Present for a software key. Identities written before hardware keys existed always have it.
    #[serde(default)]
    pub key_material: Option<SoftwareKeyMaterial>,
    /// Present instead of `key_material` when the key lives in the TPM (CNG key name; the private key never leaves it).
    #[serde(default)]
    pub hardware_key_name: Option<String>,
    /// Set once enrollment completes; absent before that.
    pub device_id: Option<Uuid>,
    pub certificate_pem: Option<String>,
    pub issuing_ca_pem: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("failed to read or write state file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse state file: {0}")]
    Parse(#[from] serde_json::Error),
}

/// A single JSON document on disk. Writes are atomic: the new contents go to a temporary sibling file and
/// are then renamed over the target, so a crash or power loss mid-write leaves either the complete old
/// file or the complete new one -- never a truncated file that would fail to parse on the next start.
pub struct JsonFileStore<T> {
    path: PathBuf,
    _marker: PhantomData<fn() -> T>,
}

impl<T: Serialize + DeserializeOwned> JsonFileStore<T> {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self { path: path.as_ref().to_path_buf(), _marker: PhantomData }
    }

    pub fn load(&self) -> Result<Option<T>, StorageError> {
        if !self.path.exists() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_str(&std::fs::read_to_string(&self.path)?)?))
    }

    pub fn save(&self, value: &T) -> Result<(), StorageError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(value)?)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

pub type SecureStorage = JsonFileStore<StoredState>;
pub type PolicyStore = JsonFileStore<crate::policy_state::PolicyCache>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_provider::SoftwareEd25519KeyProvider;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("iam-agent-test-{}", Uuid::new_v4())).join(name)
    }

    #[test]
    fn an_identity_file_written_before_hardware_keys_existed_still_loads_with_its_software_key() {
        let path = temp_path("state.json");
        let storage = SecureStorage::new(&path);
        let (_, material) = SoftwareEd25519KeyProvider::generate();
        let mut state = crate::secure_storage::test_state(Uuid::new_v4());
        state.key_material = Some(material);
        storage.save(&state).unwrap();

        // Remove the field that did not exist in older versions, exactly as an old file would be.
        let mut json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        json.as_object_mut().unwrap().remove("hardware_key_name");
        std::fs::write(&path, serde_json::to_string(&json).unwrap()).unwrap();

        let loaded = storage.load().unwrap().unwrap();
        assert!(loaded.key_material.is_some());
        assert!(loaded.hardware_key_name.is_none());
    }

    #[test]
    fn a_tpm_identity_is_saved_without_any_private_key_bytes() {
        let path = temp_path("state.json");
        let storage = SecureStorage::new(&path);
        let mut state = crate::secure_storage::test_state(Uuid::new_v4());
        state.key_material = None;
        state.hardware_key_name = Some("IamEndpointAgent-x".into());
        storage.save(&state).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("signing_key_bytes"));
        assert!(text.contains("IamEndpointAgent-x"));
    }

    #[test]
    fn a_saved_state_round_trips_through_load() {
        let path = temp_path("state.json");
        let storage = SecureStorage::new(&path);
        let (_, material) = SoftwareEd25519KeyProvider::generate();
        let state = StoredState {
            identity: DeviceIdentity::new(),
            key_algorithm: "ED25519".into(),
            key_assurance_level: KeyAssuranceLevel::Software,
            key_material: Some(material),
            hardware_key_name: None,
            device_id: Some(Uuid::new_v4()),
            certificate_pem: Some("-----BEGIN CERTIFICATE-----...".into()),
            issuing_ca_pem: None,
        };

        storage.save(&state).unwrap();
        let loaded = storage.load().unwrap().unwrap();

        assert_eq!(loaded.identity.device_instance_id, state.identity.device_instance_id);
        assert_eq!(loaded.device_id, state.device_id);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn loading_a_nonexistent_file_returns_none_not_an_error() {
        assert!(SecureStorage::new(temp_path("missing.json")).load().unwrap().is_none());
    }

    #[test]
    fn a_corrupt_file_is_an_error_not_silently_treated_as_empty() {
        // Treating garbage as "no state" would let a corrupted file make a device forget it is enrolled.
        let path = temp_path("state.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "{ not json").unwrap();
        assert!(matches!(SecureStorage::new(&path).load(), Err(StorageError::Parse(_))));
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn saving_replaces_the_previous_contents_and_leaves_no_temporary_file() {
        let path = temp_path("cache.json");
        let store = PolicyStore::new(&path);
        let mut cache = crate::policy_state::PolicyCache::default();
        store.save(&cache).unwrap();
        cache.clock_high_water = 42;
        store.save(&cache).unwrap();

        assert_eq!(store.load().unwrap().unwrap().clock_high_water, 42);
        assert!(!path.with_extension("json.tmp").exists());
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }
}

/// A throwaway enrolled state for tests in other modules.
#[cfg(test)]
pub fn test_state(device_id: Uuid) -> StoredState {
    use crate::key_provider::{KeyProvider, SoftwareEd25519KeyProvider};
    let (provider, key_material) = SoftwareEd25519KeyProvider::generate();
    StoredState {
        identity: DeviceIdentity::new(),
        key_algorithm: provider.algorithm().to_string(),
        key_assurance_level: provider.assurance_level(),
        key_material: Some(key_material),
        hardware_key_name: None,
        device_id: Some(device_id),
        certificate_pem: None,
        issuing_ca_pem: None,
    }
}
