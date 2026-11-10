use crate::device_identity::DeviceIdentity;
use crate::key_provider::{KeyAssuranceLevel, SoftwareKeyMaterial};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Everything the agent needs to remember between runs. Persisted as a
/// single JSON file today -- real protection-at-rest (Windows DPAPI,
/// scoped to the machine/user account so another local user or a copied
/// file can't read it) is a platform-layer concern not yet implemented
/// here; this crate only defines *what* gets persisted, not how it's
/// protected on disk. That gap matters most for `key_material` when
/// [`KeyAssuranceLevel::Software`] is in use -- a hardware-backed provider
/// (TPM/CNG) never has private key bytes to persist at all, which is
/// exactly why that's the preferred assurance level (Section 5.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredState {
    pub identity: DeviceIdentity,
    pub key_algorithm: String,
    pub key_assurance_level: KeyAssuranceLevel,
    pub key_material: SoftwareKeyMaterial,
    /// Set once enrollment completes; absent before that.
    pub device_id: Option<Uuid>,
    pub certificate_pem: Option<String>,
    pub issuing_ca_pem: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("failed to read state file: {0}")]
    Read(#[from] std::io::Error),
    #[error("failed to parse state file: {0}")]
    Parse(#[from] serde_json::Error),
}

pub struct SecureStorage {
    path: PathBuf,
}

impl SecureStorage {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self { path: path.as_ref().to_path_buf() }
    }

    pub fn load(&self) -> Result<Option<StoredState>, StorageError> {
        if !self.path.exists() {
            return Ok(None);
        }
        let contents = std::fs::read_to_string(&self.path)?;
        Ok(Some(serde_json::from_str(&contents)?))
    }

    pub fn save(&self, state: &StoredState) -> Result<(), StorageError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let contents = serde_json::to_string_pretty(state)?;
        std::fs::write(&self.path, contents)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_provider::SoftwareEd25519KeyProvider;

    #[test]
    fn a_saved_state_round_trips_through_load() {
        let dir = std::env::temp_dir().join(format!("iam-agent-test-{}", Uuid::new_v4()));
        let storage = SecureStorage::new(dir.join("state.json"));
        let (_, material) = SoftwareEd25519KeyProvider::generate();
        let state = StoredState {
            identity: DeviceIdentity::new(),
            key_algorithm: "ED25519".into(),
            key_assurance_level: KeyAssuranceLevel::Software,
            key_material: material,
            device_id: Some(Uuid::new_v4()),
            certificate_pem: Some("-----BEGIN CERTIFICATE-----...".into()),
            issuing_ca_pem: None,
        };

        storage.save(&state).unwrap();
        let loaded = storage.load().unwrap().unwrap();

        assert_eq!(loaded.identity.device_instance_id, state.identity.device_instance_id);
        assert_eq!(loaded.device_id, state.device_id);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn loading_a_nonexistent_file_returns_none_not_an_error() {
        let storage = SecureStorage::new(std::env::temp_dir().join(format!("iam-agent-missing-{}.json", Uuid::new_v4())));
        assert!(storage.load().unwrap().is_none());
    }
}
