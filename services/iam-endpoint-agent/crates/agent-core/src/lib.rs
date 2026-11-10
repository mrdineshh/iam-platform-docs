//! Platform-agnostic core of the IAM Endpoint Device Trust agent (Windows-only
//! Phase 1 -- see `/IAM Endpoint Device Trust Technical Specification - v1.pdf`).
//! OS-specific concerns (Windows Service registration, CNG/TPM key storage,
//! opening the system browser) are intentionally NOT here -- see each
//! module's own doc comment -- so this crate can be built and unit-tested
//! on any platform, with the `iam-endpoint-agent` binary crate supplying
//! the Windows-specific adapters behind the traits this crate defines
//! ([`enrollment::BrowserLauncher`], [`key_provider::KeyProvider`]).

pub mod agent;
pub mod api_client;
pub mod config;
pub mod device_identity;
pub mod enrollment;
pub mod heartbeat;
pub mod key_provider;
pub mod policy_verifier;
pub mod secure_storage;

pub use agent::{Agent, AgentError};
pub use config::AgentConfig;
