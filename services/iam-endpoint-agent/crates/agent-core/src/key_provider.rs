use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// base64url (no padding) SHA-256 over a public key's X.509 SubjectPublicKeyInfo DER -- PKCE's
/// "S256" construction (RFC 7636 Section 4.2). Committed to before the user signs in, so the
/// backend only lets *this* key complete the resulting enrollment transaction. Must match
/// iam-tenant-svc's DeviceKeyThumbprint.of exactly -- both sides pin the same test vector.
pub fn key_thumbprint(public_key_der: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(public_key_der))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyAssuranceLevel {
    /// TPM-backed, non-exportable (Section 5.3's preferred option). Not yet
    /// implemented in this crate -- real TPM2 key generation/signing is
    /// platform-specific FFI (Windows CNG / TPM2 APIs) that belongs in the
    /// `iam-endpoint-agent` binary crate's platform/windows module, behind
    /// the same [`KeyProvider`] trait this software fallback implements.
    HardwareTpm,
    HardwareCng,
    /// What this crate actually provides today: a software Ed25519 key,
    /// generated once and persisted to disk (see secure_storage), with its
    /// assurance level reported honestly to the backend at enrollment
    /// time -- Section 5.3: "clearly report assurance level", not silently
    /// claimed as hardware-backed.
    Software,
}

impl KeyAssuranceLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyAssuranceLevel::HardwareTpm => "HARDWARE_TPM",
            KeyAssuranceLevel::HardwareCng => "HARDWARE_CNG",
            KeyAssuranceLevel::Software => "SOFTWARE",
        }
    }
}

/// Serializable key material for a software-backed key. A hardware-backed
/// provider would instead hold an opaque handle (TPM key handle / CNG key
/// container name) here -- nothing in this crate assumes a raw private key
/// is always available, [`KeyProvider`] only ever exposes signing and the
/// public key, never the private key itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareKeyMaterial {
    signing_key_bytes: [u8; 32],
}

pub trait KeyProvider: Send + Sync {
    fn algorithm(&self) -> &'static str;
    fn assurance_level(&self) -> KeyAssuranceLevel;
    /// X.509 SubjectPublicKeyInfo DER, base64-encoded -- the exact format
    /// iam-tenant-svc's DeviceSignatureVerifier.decodePublicKey expects on
    /// the backend (`KeyFactory.generatePublic(X509EncodedKeySpec(bytes))`),
    /// not a bespoke wire format either side would have to special-case.
    fn public_key_base64(&self) -> String;
    /// Base64-encoded signature over `data`.
    fn sign(&self, data: &[u8]) -> String;

    fn key_thumbprint(&self) -> String {
        let der = STANDARD.decode(self.public_key_base64()).expect("public_key_base64 always produces valid base64");
        key_thumbprint(&der)
    }
}

pub struct SoftwareEd25519KeyProvider {
    signing_key: SigningKey,
}

impl SoftwareEd25519KeyProvider {
    pub fn generate() -> (Self, SoftwareKeyMaterial) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let material = SoftwareKeyMaterial { signing_key_bytes: signing_key.to_bytes() };
        (Self { signing_key }, material)
    }

    pub fn from_material(material: &SoftwareKeyMaterial) -> Self {
        Self { signing_key: SigningKey::from_bytes(&material.signing_key_bytes) }
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

// RFC 8410 Ed25519 X.509 SubjectPublicKeyInfo DER prefix -- a fixed 12-byte
// ASN.1 header (SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING }) that
// precedes the raw 32-byte public key in every Ed25519 SPKI encoding. Java's
// `KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(...))`
// expects exactly this on the backend side.
const ED25519_SPKI_DER_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

impl KeyProvider for SoftwareEd25519KeyProvider {
    fn algorithm(&self) -> &'static str {
        "ED25519"
    }

    fn assurance_level(&self) -> KeyAssuranceLevel {
        KeyAssuranceLevel::Software
    }

    fn public_key_base64(&self) -> String {
        let mut der = Vec::with_capacity(44);
        der.extend_from_slice(&ED25519_SPKI_DER_PREFIX);
        der.extend_from_slice(self.verifying_key().as_bytes());
        STANDARD.encode(der)
    }

    fn sign(&self, data: &[u8]) -> String {
        let signature = self.signing_key.sign(data);
        STANDARD.encode(signature.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_der_is_44_bytes_with_the_expected_prefix() {
        let (provider, _) = SoftwareEd25519KeyProvider::generate();
        let der = STANDARD.decode(provider.public_key_base64()).unwrap();
        assert_eq!(der.len(), 44);
        assert_eq!(&der[0..12], &ED25519_SPKI_DER_PREFIX);
    }

    #[test]
    fn a_signature_verifies_against_its_own_public_key() {
        let (provider, _) = SoftwareEd25519KeyProvider::generate();
        let data = b"challenge-nonce";
        let signature_b64 = provider.sign(data);
        let signature_bytes: [u8; 64] = STANDARD.decode(signature_b64).unwrap().try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
        assert!(provider.verifying_key().verify_strict(data, &signature).is_ok());
    }

    #[test]
    fn key_thumbprint_matches_the_pinned_cross_language_test_vector() {
        // SHA-256("abc"), base64url without padding -- iam-tenant-svc's DeviceTrustServiceTest pins
        // the identical value, so the Rust and Kotlin implementations can't silently drift apart.
        assert_eq!(key_thumbprint(b"abc"), "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0");
    }

    #[test]
    fn a_providers_thumbprint_is_43_url_safe_characters() {
        let (provider, _) = SoftwareEd25519KeyProvider::generate();
        let thumbprint = provider.key_thumbprint();
        assert_eq!(thumbprint.len(), 43);
        assert!(thumbprint.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn restoring_from_material_reproduces_the_same_public_key() {
        let (provider, material) = SoftwareEd25519KeyProvider::generate();
        let restored = SoftwareEd25519KeyProvider::from_material(&material);
        assert_eq!(provider.public_key_base64(), restored.public_key_base64());
    }
}
