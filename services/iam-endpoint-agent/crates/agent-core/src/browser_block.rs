//! The hook through which the sync loop switches the personal Microsoft sign-in block on and off.
//!
//! The decision comes from the signed device policy (`policy_verifier::BrowserControlsVerdict`); how it is carried out (the
//! browsers' URL block lists in the Windows registry) is the platform adapter's job, behind this trait, so the sync logic is
//! tested here without touching a registry.

/// Makes the browsers' block of personal Microsoft sign-in match `blocked`.
pub trait BrowserBlockController: Send + Sync {
    /// `Err` carries text for the event log. Success means every browser now matches `blocked`.
    fn set_personal_microsoft_block(&self, blocked: bool) -> Result<(), String>;
}
