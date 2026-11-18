//! TPM-backed device keys (spec section 5.3: "private key never exported; hardware-backed where possible").
//!
//! Uses Windows CNG with the "Microsoft Platform Crypto Provider", which keeps the private key inside the TPM: the agent
//! can ask the chip to sign, but nothing (not the agent, not an administrator, not malware) can read the key out or copy
//! it to another machine. Keys are created as MACHINE keys so the agent's service (LocalSystem) can open the key that an
//! elevated administrator created during enrollment.
//!
//! Every failure here degrades to "no hardware key" (the agent then uses its software key and says so in the platform
//! as a lower assurance level). Nothing in this file is allowed to panic or to stop the agent.
//!
//! The raw `NCrypt*` calls are the only unsafe code. Each is a plain two-step (ask the size, then fill the buffer) call on
//! buffers owned by this file.

use agent_core::key_provider::{p256_spki_from_ecc_blob, HardwareKeyStore, KeyAssuranceLevel, KeyProvider};
use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use windows_sys::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptDeleteKey, NCryptExportKey, NCryptFinalizeKey, NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider,
    NCryptSignHash,
};

const PROVIDER: &str = "Microsoft Platform Crypto Provider";
const ALG_ECDSA_P256: &str = "ECDSA_P256";
const BLOB_ECC_PUBLIC: &str = "ECCPUBLICBLOB";
const MACHINE_KEY_FLAG: u32 = 0x20; // NCRYPT_MACHINE_KEY_FLAG
const SILENT_FLAG: u32 = 0x40; // NCRYPT_SILENT_FLAG

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// An NCrypt provider or key handle, released when dropped.
struct Handle(usize);

impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: the handle came from an NCrypt call and is released exactly once.
            unsafe { NCryptFreeObject(self.0) };
        }
    }
}

fn open_provider() -> Option<Handle> {
    let name = wide(PROVIDER);
    let mut handle: usize = 0;
    // SAFETY: `name` is a live NUL-terminated buffer and `handle` a valid out pointer.
    let rc = unsafe { NCryptOpenStorageProvider(&mut handle, name.as_ptr(), 0) };
    if rc != 0 {
        tracing::debug!(status = format!("{rc:#010x}"), "TPM crypto provider not available");
        return None;
    }
    Some(Handle(handle))
}

/// Deletes the key the handle refers to. The handle is consumed: on success NCrypt has already released it.
fn delete_key(mut key: Handle) {
    // SAFETY: valid key handle.
    let rc = unsafe { NCryptDeleteKey(key.0, 0) };
    if rc == 0 {
        key.0 = 0; // already invalid; do not free it again
    } else {
        tracing::warn!(status = format!("{rc:#010x}"), "could not delete a TPM key");
    }
}

fn export_public_spki(key: &Handle) -> Option<Vec<u8>> {
    let blob_type = wide(BLOB_ECC_PUBLIC);
    let mut len: u32 = 0;
    // SAFETY: size query (null output buffer) on a valid key handle.
    let rc = unsafe { NCryptExportKey(key.0, 0, blob_type.as_ptr(), std::ptr::null(), std::ptr::null_mut(), 0, &mut len, 0) };
    if rc != 0 || len == 0 || len > 4096 {
        return None;
    }
    let mut buf = vec![0u8; len as usize];
    // SAFETY: `buf` is `len` bytes long.
    let rc = unsafe { NCryptExportKey(key.0, 0, blob_type.as_ptr(), std::ptr::null(), buf.as_mut_ptr(), len, &mut len, 0) };
    if rc != 0 {
        return None;
    }
    buf.truncate(len as usize);
    match p256_spki_from_ecc_blob(&buf) {
        Ok(der) => Some(der),
        Err(err) => {
            tracing::warn!(%err, "TPM public key was not a P-256 key");
            None
        }
    }
}

/// A key that lives in the TPM. Holds the handles; the private key itself is never in this process.
pub struct TpmKey {
    key: Handle,
    // The key handle depends on its provider staying loaded.
    _provider: Handle,
    spki_base64: String,
}

impl KeyProvider for TpmKey {
    fn algorithm(&self) -> &'static str {
        "ECDSA_P256"
    }

    fn assurance_level(&self) -> KeyAssuranceLevel {
        KeyAssuranceLevel::HardwareTpm
    }

    fn public_key_base64(&self) -> String {
        self.spki_base64.clone()
    }

    /// ECDSA P-256 over SHA-256, returned as the raw 64-byte r||s pair (what CNG produces; the platform accepts this form).
    /// On any failure returns an empty signature, which the platform rejects: a failed signature can never look valid.
    fn sign(&self, data: &[u8]) -> String {
        let digest = Sha256::digest(data);
        let mut len: u32 = 0;
        // SAFETY: size query on a valid key handle with a 32-byte digest.
        let rc = unsafe { NCryptSignHash(self.key.0, std::ptr::null(), digest.as_ptr(), 32, std::ptr::null_mut(), 0, &mut len, 0) };
        if rc != 0 || len == 0 || len > 1024 {
            tracing::error!(status = format!("{rc:#010x}"), "TPM signing failed (size query)");
            return String::new();
        }
        let mut signature = vec![0u8; len as usize];
        // SAFETY: `signature` is `len` bytes long.
        let rc = unsafe { NCryptSignHash(self.key.0, std::ptr::null(), digest.as_ptr(), 32, signature.as_mut_ptr(), len, &mut len, 0) };
        if rc != 0 {
            tracing::error!(status = format!("{rc:#010x}"), "TPM signing failed");
            return String::new();
        }
        signature.truncate(len as usize);
        STANDARD.encode(signature)
    }
}

pub struct TpmKeyStore {
    /// Machine keys are readable by the LocalSystem service; user keys only by the user that made them (self-test only).
    machine: bool,
}

impl TpmKeyStore {
    fn flags(&self) -> u32 {
        if self.machine {
            MACHINE_KEY_FLAG
        } else {
            0
        }
    }
}

impl HardwareKeyStore for TpmKeyStore {
    fn create(&self, name: &str) -> Option<Arc<dyn KeyProvider>> {
        let provider = open_provider()?;
        let (alg, key_name) = (wide(ALG_ECDSA_P256), wide(name));
        let mut raw: usize = 0;
        // SAFETY: all pointers are live NUL-terminated buffers / valid out pointers.
        let rc = unsafe { NCryptCreatePersistedKey(provider.0, &mut raw, alg.as_ptr(), key_name.as_ptr(), 0, self.flags()) };
        if rc != 0 {
            tracing::warn!(status = format!("{rc:#010x}"), "could not create a TPM key");
            return None;
        }
        let key = Handle(raw);
        // SAFETY: valid, not yet finalized key handle.
        let rc = unsafe { NCryptFinalizeKey(key.0, SILENT_FLAG) };
        if rc != 0 {
            tracing::warn!(status = format!("{rc:#010x}"), "could not finalize a TPM key");
            delete_key(key);
            return None;
        }
        let Some(spki) = export_public_spki(&key) else {
            delete_key(key);
            return None;
        };
        Some(Arc::new(TpmKey { key, _provider: provider, spki_base64: STANDARD.encode(spki) }))
    }

    fn open(&self, name: &str) -> Option<Arc<dyn KeyProvider>> {
        let provider = open_provider()?;
        let key_name = wide(name);
        let mut raw: usize = 0;
        // SAFETY: as above.
        let rc = unsafe { NCryptOpenKey(provider.0, &mut raw, key_name.as_ptr(), 0, self.flags()) };
        if rc != 0 {
            tracing::warn!(status = format!("{rc:#010x}"), "could not open the TPM key");
            return None;
        }
        let key = Handle(raw);
        let spki = export_public_spki(&key)?;
        Some(Arc::new(TpmKey { key, _provider: provider, spki_base64: STANDARD.encode(spki) }))
    }

    fn delete(&self, name: &str) {
        let Some(provider) = open_provider() else { return };
        let key_name = wide(name);
        let mut raw: usize = 0;
        // SAFETY: as above.
        let rc = unsafe { NCryptOpenKey(provider.0, &mut raw, key_name.as_ptr(), 0, self.flags()) };
        if rc == 0 {
            delete_key(Handle(raw));
        }
    }
}

/// The store the agent offers to `agent-core`. Whether a TPM actually exists is only learned when a key is created.
pub fn hardware_key_store() -> Option<Arc<dyn HardwareKeyStore>> {
    Some(Arc::new(TpmKeyStore { machine: true }))
}

/// `--tpm-selftest [--user]`: creates a throwaway TPM key, signs a fixed message, prints the public key and signature as
/// JSON (so an independent tool can verify them), and deletes the key. `--user` makes a per-user key, which works without
/// administrator rights; the default is a machine key, which is what the service uses and needs an elevated shell.
pub fn tpm_selftest(user_scope: bool) -> anyhow::Result<()> {
    let store = TpmKeyStore { machine: !user_scope };
    let name = format!("IamAgentSelfTest-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos()));
    let Some(key) = store.create(&name) else {
        anyhow::bail!(
            "could not create a TPM key ({} key). No TPM, TPM not ready, or not enough rights{}",
            if user_scope { "user" } else { "machine" },
            if user_scope { "" } else { " (machine keys need an administrator shell; try --user)" }
        );
    };
    let message = "iam-tpm-selftest";
    let signature = key.sign(message.as_bytes());
    let reopened = store.open(&name).map(|k| k.public_key_base64() == key.public_key_base64()).unwrap_or(false);
    store.delete(&name);
    let gone = store.open(&name).is_none();
    anyhow::ensure!(!signature.is_empty(), "the TPM key was created but signing failed");
    println!(
        "{}",
        serde_json::json!({
            "scope": if user_scope { "user" } else { "machine" },
            "assurance": key.assurance_level().as_str(),
            "algorithm": key.algorithm(),
            "publicKey": key.public_key_base64(),
            "message": message,
            "signature": signature,
            "reopenedSameKey": reopened,
            "deletedCleanly": gone,
        })
    );
    Ok(())
}
